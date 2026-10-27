# Architecture

Structural reference for xSypher-Stream: component responsibilities, the kernel object, the maps that
carry policy state, and the reasoning behind the current shape of the system.

Companion documents: [THREAT-MODEL.md](THREAT-MODEL.md) for what is defended and against whom,
[WIRE-PROTOCOL.md](WIRE-PROTOCOL.md) for byte layouts and the connection state machine,
[ENFORCEMENT.md](ENFORCEMENT.md) for hook semantics and races, [DETECTIONS.md](DETECTIONS.md) for rule
rationale, [PERFORMANCE.md](PERFORMANCE.md) for measurement, and [OPERATIONS.md](OPERATIONS.md) for
running it.

- [Components](#components)
- [Event path](#event-path)
- [Enforcement path](#enforcement-path)
- [Wire protocol](#wire-protocol)
- [Design decisions](#design-decisions)
- [Known limitations](#known-limitations)
- [Compatibility](#compatibility)

---

## Components

| Component | Language | Source | Responsibility |
|---|---|---|---|
| Kernel programs | restricted C, eBPF CO-RE | `src/bpf/xsypher.bpf.c` | collect events, enforce LSM policy, maintain counters |
| Collector | C++20, libbpf | `src/collector/` | drain the ring buffer, enrich with container identity, transport |
| Engine | Python 3.12, asyncio | `src/engine/` | decode, lineage, rule evaluation, mitigation, observability |

![Component and data flow](architecture.svg)

### Kernel programs

Five tracepoint programs and three LSM programs share one object and one set of maps.

| Program | Section | Purpose |
|---|---|---|
| `xsypher_execve` | `tp/syscalls/sys_enter_execve` | records `filename` and up to four `argv` entries |
| `xsypher_connect` | `tp/syscalls/sys_enter_connect` | records destination address and port for `AF_INET` / `AF_INET6` |
| `xsypher_openat` | `tp/syscalls/sys_enter_openat` | records opens of credential paths and `.env` files, plus write-like opens under `/tmp`, `/dev/shm`, `/usr/bin`, `/usr/local/bin`; filtered in kernel to control volume |
| `xsypher_memfd_create` | `tp/syscalls/sys_enter_memfd_create` | records memory-backed file creation |
| `xsypher_process_exit` | `tp/sched/sched_process_exit` | records exit and removes the tgid from the quarantine map |
| `xsypher_lsm_bprm_check` | `lsm/bprm_check_security` | denies exec inside a quarantined domain |
| `xsypher_lsm_socket_connect` | `lsm/socket_connect` | denies blocked IPv4 destinations and IMDS access from quarantined cgroups |
| `xsypher_lsm_file_open` | `lsm/file_open` | denies credential reads and any write inside a quarantined domain |

Maps:

| Map | Type | Key | Value | Bound |
|---|---|---|---|---|
| `events_ringbuf` | `RINGBUF` | n/a | `struct kernel_event_t` | 16 MiB |
| `quarantined_pids_map` | `HASH` | `u32` tgid | `u8` action | 16,384 |
| `quarantined_cgroups_map` | `HASH` | `u64` cgroup id | `u8` action | 4,096 |
| `blocked_ipv4_map` | `HASH` | `u32` network-order IPv4 | `u8` reason | 8,192 |
| `config_map` | `ARRAY` | `0` | `u32` enforcement mode | 1 |
| `metrics_map` | `PERCPU_ARRAY` | metric id | `u64` count | 16 |

All task metadata is read with `BPF_CORE_READ`, so the object is portable across kernel versions
without recompilation. `nsproxy` is nullable and checked before use.

![Deployment topology](fig-deployment.svg)

*One collector per kernel. The only listening socket is the metrics port.*

### Collector

Single-threaded epoll reactor. The ring buffer, client sockets and a `signalfd` share one epoll
instance, so there is no locking on the hot path.

- `bpf_loader` owns the libbpf skeleton, decides whether LSM programs can be attached, and exposes
  thread-safe wrappers over `bpf_map_update_elem` / `bpf_map_delete_elem`.
- `cgroup_resolver` parses `/proc/<pid>/cgroup` behind a bounded LRU cache with a five-second TTL, and
  extracts 64-hex Docker, containerd or CRI-O identifiers. Unknown layouts resolve to `host`.
- `uds_server` owns the `AF_UNIX`/`SOCK_SEQPACKET` socket: broadcast of telemetry frames, intake of
  policy commands, non-blocking writes with per-client drop accounting.

If the kernel rejects the LSM programs (no `CONFIG_BPF_LSM`, or `lsm=bpf` absent from the command
line), the loader retries the load with those three programs disabled via
`bpf_program__set_autoload(prog, false)` and continues with telemetry. The condition is reported in
the status line as `lsm=unavailable`.

### Engine

`asyncio` process with one consumer task. Frames are decoded, applied to the lineage graph, evaluated
against the rule set, and on a match turned into policy commands plus an audit record.

- `abi.py` mirrors the C header with `ctypes` and asserts sizes and offsets at import.
- `lineage.py` keeps `pid -> ProcessNode` with children sets, an ancestry walk, a five-second grace
  window after exit (for out-of-order events) and LRU eviction at `--max-tracked`.
- `rule_engine.py` compiles YAML rules into pre-normalised sets and tuple prefixes, indexes them by
  event type, and resolves ancestry once per event rather than once per rule.
- `mitigator.py` deduplicates policy commands, sends them to the collector, optionally sends
  user-space `SIGKILL`, and appends the SHA-256 chained audit record.
- `metrics.py` is an HTTP/1.1 server over `asyncio` streams; no third-party dependency.
- `tui.py` renders telemetry and alert blocks, with colour disabled on non-TTY or `NO_COLOR`.

---

## Event path

1. A tracepoint fires. The program reserves a 640-byte record on the ring buffer, fills identity,
   cgroup, namespace and lineage fields, and submits it. If the buffer is full the event is dropped
   and `METRIC_RINGBUF_DROPS` is incremented.
2. `ring_buffer__poll()` returns the record to the collector. `cgroup_id` and `pid` are resolved to a
   container identifier (cache hit: one hash lookup).
3. The collector wraps the record in a 720-byte `wire_event_msg_t` with a monotonic `seq_no` and
   broadcasts it on the socket.
4. The engine decodes the frame, inserts or refreshes the process node, and evaluates the rules that
   can fire for that event type.
5. On a match the engine builds `wire_policy_cmd_t` frames (32 bytes) and sends them back. The
   collector applies each one with `bpf_map_update_elem`.

Measured cost of steps 1 to 3 is a few microseconds per event; step 4 is 5 to 20 microseconds; step 5
is a 2 to 4 millisecond round trip because it crosses two processes and a socket.

---

## Enforcement path

`config_map[0]` selects behaviour. Full hook-by-hook semantics, return codes, race analysis and known
gaps are in [ENFORCEMENT.md](ENFORCEMENT.md).

| Mode | Value | Effect |
|---|---|---|
| `ENFORCEMENT_AUDIT_ONLY` | 0 | LSM programs return 0; the engine still alerts and logs |
| `ENFORCEMENT_INLINE_BLOCK` | 1 | LSM programs evaluate quarantine state and may return `-EPERM` |

A domain is quarantined when its cgroup id, or the calling tgid, is present in
`quarantined_cgroups_map` / `quarantined_pids_map` with action `QUARANTINE_BLOCK`.

- `bprm_check_security` returns `-EPERM`: no new program can start in that cgroup.
- `socket_connect` returns `-EPERM` for addresses in `blocked_ipv4_map`, and for the metadata service
  when the caller is quarantined.
- `file_open` returns `-EACCES` for credential paths and for any write inside a quarantined domain.

Denials emit an `EVENT_LSM_BLOCK` record so the engine and metrics observe the enforcement, not just
the attempt.

On graceful shutdown the engine sends `UNQUARANTINE_*` for every entry it installed, so a restart
never leaves a node locked down.

---

## Wire protocol

`include/xsypher_abi.h` is normative. `src/engine/abi.py` mirrors it with `ctypes` and asserts every size
and offset at import; a test compiles the header with the host C compiler and compares both.

| Structure | Size | Direction |
|---|---|---|
| `struct kernel_event_t` | 640 B | kernel to collector, one ring buffer record |
| `struct wire_event_msg_t` | 720 B | collector to engine, one `SOCK_SEQPACKET` datagram |
| `struct wire_policy_cmd_t` | 32 B | engine to collector, one datagram per command |

| Constant | Value |
|---|---|
| `XSYPHER_WIRE_MAGIC` | `0x58535950` |
| `XSYPHER_ABI_VERSION` | 2 |
| `MAX_COMM_LEN` / `MAX_PATH_LEN` / `MAX_ARGS_LEN` / `MAX_CONTAINER_ID_LEN` | 16 / 256 / 256 / 64 |

Event types 1 to 6: `EXECVE`, `CONNECT`, `OPENAT`, `MEMFD_CREATE`, `PROCESS_EXIT`, `LSM_BLOCK`.
Command types 10 to 16: quarantine and unquarantine of a pid and of a cgroup, block and unblock of an
IPv4 address, and set enforcement mode.

Field-by-field tables with offsets, hexdumps of a real frame and command, the connection state machine,
validation rules and the versioning policy are in [WIRE-PROTOCOL.md](WIRE-PROTOCOL.md).

## Design decisions

**Ring buffer instead of perf buffer.** `BPF_MAP_TYPE_RINGBUF` is a single shared mapping with
reserve/submit semantics, so ordering is per-CPU-consistent and a slow consumer cannot stall a
syscall. Overflow is explicit and counted.

**`SOCK_SEQPACKET` instead of a stream or TCP.** Message boundaries are preserved, the connection is
stateful so collector restarts are visible, and the transport cannot accidentally be exposed beyond
the host.

**Cgroup-level quarantine.** PIDs are recycled in seconds and a forked child can outrun user space.
Quarantining the cgroup covers every current and future task in the domain. The PID map is still
maintained for precision, and is cleaned on `sched_process_exit` to avoid reuse false positives.

**Policy in BPF maps, decisions in Python.** The kernel does one hash lookup per hook; interpretation
lives where it can be iterated quickly. This keeps the verifier surface small and the detection
content reviewable as data.

**Strict rule validation.** An invalid rule file aborts startup. Silently running with fewer
detections is worse than not starting.

---

## Known limitations

- `args` captures the first four `argv` pointers, 64 bytes each. Adequate for a command line, not for
  arbitrary binary payloads.
- Container identity depends on Docker/containerd/CRI-O cgroup layouts; other runtimes report `host`.
- `--active-kill` is a user-space `SIGKILL` and races against a fast fork loop. The kernel quarantine
  is the authoritative control.
- IMDS denial covers IPv4 `169.254.169.254` in the LSM hook. The IPv6 equivalent is handled by rule
  evaluation only.
- `file_open` resolves the dentry basename, not a full path, so its credential-path branch cannot match
  absolute prefixes. The effective in-kernel file protection is write denial inside a quarantined domain.
  Details and the intended fix: [ENFORCEMENT.md](ENFORCEMENT.md#7-known-enforcement-gaps).
- The `openat` kernel filter emits a record for credential prefixes, `.env` suffixes and write-like opens
  into staging directories only, so rule conditions on other suffixes and names are narrower than they
  read. See [DETECTIONS.md](DETECTIONS.md#6-sensitive_credential_harvest).
- `openat` filtering is deliberately narrow. Hosts with heavy temporary-file traffic may need the
  staging-path list widened or narrowed; see `is_writable_staging_path()`.
- The reduced `vmlinux.h` produced by `scripts/gen_vmlinux.sh` when BTF is unavailable is for type
  checking only. Never deploy an object built against it.

---

## Compatibility

| Axis | Support |
|---|---|
| Kernel | 5.10 to 6.x; one CO-RE object, no per-kernel builds |
| Architectures | x86_64, aarch64 |
| Distributions | Any with BTF: Ubuntu 20.04+, Debian 11+, RHEL 9+, Amazon Linux 2023, Bottlerocket, Talos |
| Container runtimes | Docker, containerd, CRI-O |
| Python | 3.10, 3.11, 3.12 (reference), 3.13 |
| libbpf | 1.0 or later; 1.1 or later for the epoll-driven ring buffer, older 1.x uses timed polling |
| Inline enforcement | Requires `CONFIG_BPF_LSM=y` and `lsm=bpf` |
