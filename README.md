# xSypher-Stream

**Version 2.0.0 · wire ABI v2 · Apache-2.0 (user space) / GPL-2.0 (eBPF object)**

Kernel-resident security telemetry and inline policy enforcement for Linux hosts that run AI agents and
Model Context Protocol servers. Process execution, outbound connections, credential-file access and
memory-backed file creation are captured at the syscall boundary with eBPF, enriched with container and
namespace identity, resolved against a live process-lineage graph, evaluated against a declarative rule
set, and enforced inside the kernel through BPF LSM hooks.

Enforcement does not require workload cooperation, container restart, or a privileged sidecar in the
workload's namespace. The privileged surface is a single collector per node that parses fixed-size
records and applies 32-byte policy commands; all policy logic lives in an unprivileged Python process.

| Property | Value |
|---|---|
| Kernel baseline | Linux 5.10+, BTF required, x86_64 and aarch64 |
| Inline enforcement | `CONFIG_BPF_LSM=y` and `lsm=bpf`; telemetry works without them |
| Wire ABI | v2, magic `0x58535950`, three fixed structures (640 / 720 / 32 bytes) |
| Collector | C++20, libbpf 1.0+, single-threaded epoll reactor |
| Engine | Python 3.10+ (3.12 reference), asyncio, PyYAML only |
| Test suite | 59 tests, 31 subtests, plus a 10,016-event end-to-end attack simulation |

### Documentation map

| Document | Scope |
|---|---|
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | assets, attacker model, trust boundaries, security invariants, non-goals |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | components, kernel programs, map catalogue, event and enforcement paths |
| [docs/WIRE-PROTOCOL.md](docs/WIRE-PROTOCOL.md) | byte layouts, hexdumps, state machine, validation, versioning |
| [docs/DETECTIONS.md](docs/DETECTIONS.md) | per-rule rationale, false-positive profile, evasion analysis, coverage gaps |
| [docs/ENFORCEMENT.md](docs/ENFORCEMENT.md) | quarantine state machine, hook semantics, race conditions and mitigations |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | every flag, environment variable, rule key, action and exit code |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | health, metrics, alerting, audit forensics, capacity, upgrade, troubleshooting |
| [docs/PERFORMANCE.md](docs/PERFORMANCE.md) | measurement method, stage breakdown, cost model, scaling limits |

---

## 1. Why this exists

An MCP server publishes tools to a language model. The model calls them with arguments it chose. Every
security control around that loop assumes the model is choosing benign arguments: the container is
allowed to run `sh` because the image contains `/bin/sh`; the pod may reach the metadata endpoint
because the network policy allows egress to the link-local range; the process may read `/proc/self/environ`
because it is the same UID. A successful prompt injection produces activity that is, at every individual
layer, ordinary and authorised.

The resulting kill chain is short and completes in single-digit milliseconds. The timeline below is
illustrative, not a measurement; what is measured is the detection-to-enforcement budget in §12.

| t (ms) | Kernel-visible action | Who is looking |
|---|---|---|
| 0.0 | model emits a tool call with a shell argument | prompt-level filtering, if any |
| 0.4 | MCP server calls `fork()` and `execve("/bin/sh", ["-c", ...])` | nothing; `sh` is in the image |
| 0.9 | `connect(AF_INET, 169.254.169.254:80)` | nothing; egress is permitted |
| 4.1 | `openat("/var/run/secrets/kubernetes.io/serviceaccount/token")` | nothing; same UID, same mount |
| 6.8 | `connect(AF_INET, 203.0.113.9:443)` with the token in a request body | nothing; TLS to a normal address |

Image scanning, admission control, static network policy and host agents that poll `/proc` at one-second
intervals all miss this window. Only the syscall path sees it in time, and only an LSM hook can stop it
after the fact without killing the workload first.

xSypher-Stream occupies those two points: the tracepoint for observation, the LSM hook for control.

---

## 2. Threat model

Full model, including assets and non-goals: [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). Summary:

| Attacker capability | In scope | Consequence if undetected |
|---|---|---|
| Controls prompt input to an LLM that has MCP tool access | yes | arbitrary tool invocation inside an authorised container |
| Can execute commands inside an existing container as the workload UID | yes | shell, recon, credential theft, C2 |
| Can reach the instance metadata service over IPv4 | yes | cloud IAM credential theft |
| Can read files mounted into the workload | yes | service-account tokens, SSH keys, `.env` secrets |
| Can write and execute from memory or shared memory | yes | fileless payload staging, disk-forensic evasion |
| Has root on the host and can unload BPF programs | **no** | sensor removal; out of scope by design |
| Has kernel code execution or an eBPF verifier exploit | **no** | full compromise; report upstream |

Security invariants the implementation is built to hold:

- **P1, no blocking on user space.** A stalled or absent consumer never blocks a syscall. Events are
  dropped and counted; the traced path continues.
- **P2, no policy loss on engine restart.** Policy already installed in BPF maps survives engine exit.
- **P3, no silent degradation.** A kernel without BPF LSM is reported as `lsm=unavailable` in the status
  line and `NOTICE: inline enforcement is inactive`, never as active.
- **P4, no partial rule sets.** An invalid rule document aborts startup rather than running with reduced
  detection coverage.
- **P5, tamper-evident audit.** Every alert commits to the previous record's SHA-256, verifiable offline
  with no external service.
- **P6, reversible enforcement.** Graceful shutdown emits the inverse command for every quarantine and
  block the engine installed.

---

## 3. Design decisions

| Decision | Alternative rejected | Rationale |
|---|---|---|
| One CO-RE object, one ring buffer | per-kernel builds, perf buffer | no recompilation across 5.10 to 6.x; reserve/submit semantics cannot stall a syscall |
| 640-byte fixed record, no variable payload | netlink with variable messages | constant allocation and memcpy cost, no length parsing on the hot path, and a bounded record means the ring buffer can be sized in records |
| Filtering in the kernel, not the engine | send everything, filter in Python | `openat` is the dominant syscall; unfiltered it is orders of magnitude more volume than the other four hooks combined |
| Decisions in Python, state in BPF maps | classify inside the kernel | rule iteration and analysis are cheap to change in Python; the verifier surface stays small and policy content stays reviewable as data |
| Cgroup-scoped quarantine | PID-scoped only | PIDs are recycled in seconds and a fork loop outruns user-space enumeration; a cgroup covers current and future tasks |
| `AF_UNIX`/`SOCK_SEQPACKET` transport | TCP, or a stream socket | message boundaries preserved, connection state visible to both sides, cannot be exposed off-host by accident |
| SHA-256 hash-chained JSONL audit | database, or syslog only | no dependency, append-only, verifiable with `sha256sum` and a script, ships with existing log agents |
| Rule documents validated at load | best-effort loading | running with fewer detections than the operator believes is a worse failure than refusing to start |

---

## 4. System architecture

![Data flow: five tracepoints and three LSM hooks write 640-byte records to a 16 MiB ring buffer; the C++20 collector forwards 720-byte frames over AF_UNIX SOCK_SEQPACKET to the Python engine, which returns 32-byte policy commands applied to the BPF maps](docs/architecture.svg)

| Component | Source | Language | Privilege | If it stops |
|---|---|---|---|---|
| Kernel programs | `src/bpf/xsypher.bpf.c` | restricted C, BPF | kernel | no telemetry, no enforcement; existing map state remains |
| Collector | `src/collector/` | C++20 + libbpf | root or `CAP_BPF` + `CAP_PERFMON` | engine reconnects every second; kernel policy stays applied |
| Engine | `src/engine/` | Python 3.12, asyncio | none | detection stops; collector drops frames and counts them |

| Execution context | Model |
|---|---|
| Kernel programs | tracepoint and LSM context, one instance per CPU, no sleep, bounded work |
| Collector | one thread, one `epoll` set covering the ring buffer fd, the listening socket, client sockets and a `signalfd` |
| Engine transport | one asyncio loop, non-blocking socket, reader and writer callbacks on the loop |
| Engine pipeline | one consumer task draining a queue in batches of up to 4096 frames, then pruning the graph |
| Metrics | separate asyncio HTTP server task on the same loop |

End-to-end path with measured costs from the 2 vCPU reference host:

| Step | Where | Cost |
|---|---|---|
| 1. Reserve, zero and fill a 640-byte record | kernel | sub-microsecond, ring buffer allocation |
| 2. Poll, resolve container identity, wrap in a 720-byte frame | collector | cache hit is one hash lookup; miss reads `/proc/<pid>/cgroup` |
| 3. Broadcast on the socket | collector | one `send()` per attached client, `MSG_DONTWAIT` |
| 4. Decode, update lineage, evaluate rules | engine | 5 to 20 µs per event (see §12) |
| 5. Build command, send, apply to map | engine and collector | 2.1 to 3.8 ms round trip, dominated by process and socket hops |

---

## 5. Kernel layer

Five tracepoint programs and three LSM programs share one object and one set of maps.

| Program | Hook | Emits | Kernel-side filtering |
|---|---|---|---|
| `xsypher_execve` | `tp/syscalls/sys_enter_execve` | `EVENT_EXECVE` | none, `filename` plus up to four `argv` entries of 64 bytes |
| `xsypher_connect` | `tp/syscalls/sys_enter_connect` | `EVENT_CONNECT` | `AF_INET` and `AF_INET6` only |
| `xsypher_openat` | `tp/syscalls/sys_enter_openat` | `EVENT_OPENAT` | credential prefixes, `.env` suffix, or write-like open under `/tmp`, `/dev/shm`, `/usr/bin`, `/usr/local/bin` |
| `xsypher_memfd_create` | `tp/syscalls/sys_enter_memfd_create` | `EVENT_MEMFD_CREATE` | none, this syscall is rare and always interesting |
| `xsypher_process_exit` | `tp/sched/sched_process_exit` | `EVENT_PROCESS_EXIT` | also deletes the tgid from `quarantined_pids_map` |
| `xsypher_lsm_bprm_check` | `lsm/bprm_check_security` | `EVENT_LSM_BLOCK` | only when the domain is quarantined |
| `xsypher_lsm_socket_connect` | `lsm/socket_connect` | `EVENT_LSM_BLOCK` | only IPv4, only blocked destinations or quarantined IMDS |
| `xsypher_lsm_file_open` | `lsm/file_open` | `EVENT_LSM_BLOCK` | only when the domain is quarantined |

### Map catalogue

| Map | Type | Key | Value | Max entries | Mutated by |
|---|---|---|---|---|---|
| `events_ringbuf` | `RINGBUF` | n/a | `kernel_event_t` | 16 MiB (16,777,216 B) | kernel |
| `quarantined_pids_map` | `HASH` | `u32` tgid | `u8` action | 16,384 | engine via collector |
| `quarantined_cgroups_map` | `HASH` | `u64` cgroup id | `u8` action | 4,096 | engine via collector |
| `blocked_ipv4_map` | `HASH` | `u32` raw network-order IPv4 | `u8` reason | 8,192 | engine via collector, and `--block-imds` at startup |
| `config_map` | `ARRAY` | `u32` 0 | `u32` enforcement mode | 1 | `--enforce` at startup, `CMD_SET_ENFORCEMENT_MODE` |
| `metrics_map` | `PERCPU_ARRAY` | `u32` metric id | `u64` counter | 16 | kernel |

Metrics ids: 0 events total, 1 ring buffer drops, 2 LSM blocks, 3 execve, 4 connect, 5 openat, 6 memfd,
7 exit, 8 IMDS blocks, 9 IP blocks, 10 quarantine denies. The array holds 16 slots so the id space can
grow without changing the ABI.

### Record layout

`struct kernel_event_t` is 640 bytes, `packed, aligned(8)`, with explicit padding. Field groups:

| Offset range | Contents |
|---|---|
| 0 to 63 | identity and lineage: `timestamp_ns`, `cgroup_id`, `pid`, `tgid`, `ppid`, `uid`, `gid`, three namespace ids, `event_type`, `retval`, LSM flag, address family, two ports |
| 64 to 91 | per-event fields: two IPv4 addresses, 16-byte IPv6 address, `open_flags` |
| 92 to 123 | `comm` and `parent_comm`, 16 bytes each |
| 124 to 379 | `filename`, 256 bytes |
| 380 to 635 | `args`, 256 bytes, up to four `argv` entries joined by spaces |
| 636 to 639 | explicit tail padding to the 8-byte alignment boundary |

The exact offsets are normative in `include/xsypher_abi.h` and mirrored in `src/engine/abi.py` with
`ctypes` size and offset assertions that run at import. A test compiles the C header and compares the two.

### Verifier constraints that shape the code

Every constraint below is visible in `xsypher.bpf.c` and exists because the verifier rejects the
alternative:

- Loops have constant bounds only. `collect_argv` runs a `#pragma unroll` loop over four pointers with a
  nested unrolled copy of 63 bytes, and stops early on explicit length checks.
- No unbounded pointer arithmetic. Strings are copied into stack scratch buffers (`XSYPHER_SCAN_LEN` 96
  bytes for path comparisons, `XSYPHER_ARG_CHUNK` 64 bytes per argument) before any byte comparison.
- All task reads go through `BPF_CORE_READ`, including `real_parent->tgid` and `nsproxy->mnt_ns->ns.inum`.
  `nsproxy` is nullable during exit and is checked before dereference.
- User memory is never dereferenced directly: `bpf_probe_read_user` for `sockaddr` and `argv`, and
  `bpf_probe_read_user_str` for paths.
- The `socket_connect` hook reads the kernel-side copy that `move_addr_to_kernel()` produced before
  `security_socket_connect()` runs, hence `bpf_probe_read_kernel`. Using the user read here fails.
- Ring buffer reservation is atomic with respect to the record: fields are written before
  `bpf_ringbuf_submit`, and a failed reservation increments `METRIC_RINGBUF_DROPS` and returns.

### Loading and LSM fallback

`BpfLoader::load()` opens the object, applies runtime defaults and attaches. If the load fails with an
LSM-related error and `--no-lsm-fallback` was not given, the loader destroys the skeleton, reopens it,
calls `bpf_program__set_autoload(prog, false)` for the three `lsm/*` programs, and loads again with only
the tracepoints. `lsm_available_` becomes false, the status line reports `lsm=unavailable`, and the
collector prints a warning naming the kernel error. This is the difference between a sensor that runs on
a stock cloud kernel and one that refuses to start.

---

## 6. Collector internals

Single-threaded by design: the ring buffer callback, socket accepts, socket reads and signal handling all
happen in one `epoll` loop, so the hot path takes no locks. Two mutexes exist only for the client map and
the resolver cache, which are also touched by non-hot paths.

| Concern | Implementation |
|---|---|
| Ring buffer notification | `ring_buffer__epoll_fd()` registered in the epoll set on libbpf 1.1+, falling back to timed polling on 1.0 |
| Signals | `SIGINT`, `SIGTERM`, `SIGHUP`, `SIGQUIT` blocked and consumed through `signalfd`; no syscall is interrupted |
| Container identity | two-level cache: `pid -> container_id` LRU of 4,096 entries with a 5 second TTL, and `cgroup_id -> container_id` of 8,192 entries |
| Resolver parsing | scans `/proc/<pid>/cgroup` for a maximal 64-hex run (Docker, containerd, CRI-O, systemd scopes, kubelet pod paths), falls back to a 12-hex short id, otherwise returns `host` |
| Resolver miss cost | one file read of up to 8,192 bytes; a process that has already exited is not cached |
| Clients | up to 64 concurrent engine connections, accepted non-blocking |
| Broadcast | one `send(MSG_DONTWAIT | MSG_NOSIGNAL)` per client per frame; `EAGAIN`, `EWOULDBLOCK` and `ENOBUFS` drop that frame for that client and increment `dropped_frames_` rather than stalling the ring buffer callback |
| Command intake | up to 16 non-blocking reads per wakeup, each datagram validated for length, magic and version before it reaches the map |
| Status line | every 10 seconds unless `--no-status`, with ring buffer, sent, malformed, client, command, resolver and kernel metric counters |

The status line is the primary liveness signal on the node, and its fields map one-to-one to the
degradation modes in §11:

```
[xsypher] status bpf: loaded=yes programs=8 lsm=active | ringbuf=118422 sent=118420 bad=0 | clients=1 | cmd=2 dropped=0 | resolver hits=117891 misses=531 | events=118422 drops=0 lsm_blocks=7 imds=1 ip=1 denials=2
```

---

## 7. Wire protocol

Three fixed structures, all `packed, aligned(8)`, all little-endian:

| Structure | Size | Purpose |
|---|---|---|
| `struct kernel_event_t` | 640 B | kernel to collector, one ring buffer record |
| `struct wire_event_msg_t` | 720 B | collector to engine, one `SOCK_SEQPACKET` datagram |
| `struct wire_policy_cmd_t` | 32 B | engine to collector, one datagram per command |

A telemetry frame in hex, `container_id` of 64 hex characters, `seq_no` 118423:

```
0000  50 59 53 58 02 00 01 00 97 ce 01 00 00 00 00 00  |PYSX............|
0010  32 36 31 30 31 64 36 65 30 34 30 65 35 38 32 35  |26101d6e040e5825|
0020  61 36 66 30 63 33 61 31 62 37 64 32 65 34 66 36  |a6f0c3a1b7d2e4f6|
0030  61 38 62 39 63 30 64 31 65 32 66 33 61 34 62 35  |a8b9c0d1e2f3a4b5|
0040  63 36 64 37 65 38 66 39 61 30 62 31 63 32 64 33  |c6d7e8f9a0b1c2d3|
0050  24 cf 3e b3 0e 16 72 18 01 a0 00 00 00 00 00 00  |$.>...r.........|
```

`50 59 53 58` is `PYSX` little-endian, that is magic `0x58535950`. `02 00` is version 2. `01 00` is
`MSG_TELEMETRY_EVENT`. The 8-byte `seq_no` follows, then the 64-byte container id, then the 640-byte
event at offset 80.

A policy command quarantining cgroup `0xA001`, which is cgroup id 40961:

```
0000  50 59 53 58 02 00 0c 00 01 a0 00 00 00 00 00 00  |PYSX............|
0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
```

Command type 12 is `CMD_QUARANTINE_CGROUP`; the target occupies offset 8. Every remaining byte is zero,
which is what a strict decoder should expect.

Conventions that matter in practice:

- Network byte order is preserved end to end. `169.254.169.254` is `0xFEA9FEA9` in memory on
  little-endian hosts; use `XSYPHER_IMDS_IPV4_RAW` rather than computing it.
- `container_id` may fill all 64 bytes with no NUL terminator. Shorter values such as `host` are NUL
  padded. Both must decode.
- One datagram is one frame. A short read on `SOCK_SEQPACKET` is a protocol error, never a partial frame.
- The engine rejects a frame whose magic or version differs and increments a malformed counter; it does
  not attempt a best-effort parse.

Offsets, the connection state machine, rejection paths and the versioning policy are in
[docs/WIRE-PROTOCOL.md](docs/WIRE-PROTOCOL.md).

---

## 8. Engine internals

| Stage | Code | Work | Failure behaviour |
|---|---|---|---|
| Transport | `main.py` `UdsTransport` | non-blocking connect, reader and writer callbacks, reconnect every 1 s | logs reconnects, increments `xsypher_socket_reconnects_total` |
| Decode | `abi.py` `decode_wire_frame` | strict 720-byte decode, magic and version check | malformed frame counted and discarded |
| Lineage | `lineage.py` | upsert node, TTL bookkeeping, LRU eviction | a missing node degrades ancestry to an empty chain |
| Rules | `rule_engine.py` | candidate rules by event type, ancestry resolved once per event | a failed mitigation is logged and the loop continues; a malformed frame never reaches this stage |
| Mitigation | `mitigator.py` | dedup, dispatch commands, optional `SIGKILL`, append audit record | a failed send is recorded as `delivered: false` |
| Observability | `metrics.py`, `tui.py` | Prometheus text, terminal rendering | exporter failure disables metrics, engine continues |

### Lineage graph

`pid -> ProcessNode` where `pid` is the thread group id. Each node carries `ppid`, `comm`, `exe`, `args`,
`uid`, `gid`, `cgroup_id`, `container_id`, three namespace ids, `start_time`, `last_seen`, `exit_seen`,
`exec_count` and a child set.

Behaviour that matters:

- **Exit is deferred.** `PROCESS_EXIT` marks the node and schedules eviction `--lineage-ttl` seconds
  later (5 s default). This absorbs out-of-order events from a multi-CPU ring buffer, where a child's
  `execve` can be delivered after its parent's exit record.
- **Bounded memory.** `--max-tracked` (200,000 default) evicts least-recently-used nodes. Pruning runs
  once per queue drain, not per event.
- **Ancestry resolution is per event, not per rule.** `ancestry_names(pid, depth)` walks at most
  `--max-ancestry-depth` (default 8) links, returning basenames nearest first. With six rules this cuts
  the walk count by 6×.
- **Non-exec events use the recorded image.** For `connect`, `openat` and `memfd_create`, `filename` is a
  resource, not a process. The engine resolves the subject executable from the lineage node, falling back
  to `comm`.
- **PID reuse.** Kernel telemetry carries `start_time`; a new `execve` for a recycled pid reinitialises
  the node rather than inheriting the old ancestry. `sched_process_exit` also deletes the tgid from the
  quarantine map, so a recycled pid cannot inherit a stale block.

### Rule evaluation

Rules are compiled once into immutable `RuleSpec` objects holding pre-lowered sets and tuple prefixes,
then indexed by event type. Evaluation for one event is:

1. Look up candidate rules for the event type (hash lookup, no scan of the full rule set).
2. Resolve subject executable: basename of `filename` for `execve`, lineage image otherwise.
3. Resolve ancestry only if some candidate rule needs it.
4. For each candidate, evaluate the base condition group, then `any_of` groups in order; the first match
   produces a reason string naming the executable, peer or path, container prefix and variant index.
5. Apply per-`(rule, pid)` cooldown (`settings.cooldown_seconds`, default 5 s) to suppress duplicate
   alerts from a fork loop. Suppressed matches still increment a counter.

Conditions in one group are ANDed; list values are ORed; `any_of` groups are ORed with each other and
with the base group, which is how one rule covers two structurally different shapes.

### Mitigation and the audit chain

Deduplication happens before dispatch: a cgroup already quarantined, a pid already quarantined or an
address already blocked produces no second command, so a fork storm cannot flood the control channel.
Each declared action maps to one command; `kill` is user space only and refuses `pid <= 2`.

The audit record is appended after the actions complete, so `delivered` reflects reality:

```
hash_n = SHA256( hex(hash_{n-1}) || canonical_json(record_n without "hash", "prev_hash", "alert_id") )
hash_0 = "0" * 64
```

Canonical JSON is `sort_keys=True`, `separators=(",", ":")`, UTF-8. On startup the engine resumes at the
last record's hash and sequence number, then verifies the whole chain; an invalid chain is reported as
`audit hash chain is INVALID: line N: ...` and the engine continues, because refusing to alert is worse
than alerting into a suspect log.

---

## 9. Detection coverage

Six rules ship in [`config/rules.yaml`](config/rules.yaml). Full analysis, including false-positive
profiles and evasion notes, is in [docs/DETECTIONS.md](docs/DETECTIONS.md).

| Rule | Severity | Keyed on | Actions |
|---|---|---|---|
| `MCP_SHELL_BREAKOUT` | critical | shell or multiplexer execution with an AI-runtime ancestor | quarantine cgroup, kill |
| `MCP_RECON_OR_EXFIL_TOOL` | high | network or encoding tooling with an AI-runtime ancestor | quarantine pid, kill |
| `CLOUD_IMDS_CREDENTIAL_THEFT` | critical | container connection to `169.254.169.254` or `fd00:ec2::254` | quarantine cgroup, block IPv4, kill |
| `SENSITIVE_CREDENTIAL_HARVEST` | critical | credential-file open by a non-authorised process | quarantine pid, kill |
| `FILELESS_MEMFD_EXECUTION` | critical | `memfd_create`, or execution from `/memfd:`, `/proc/self/fd/`, `/dev/shm/` | quarantine cgroup, kill |
| `SUSPICIOUS_OUTBOUND_C2_PORT` | high | container or web worker connecting to a known reverse-shell port | quarantine pid, block IPv4, kill |

The rules are data. Adding, disabling or retuning one requires no rebuild and no kernel change; a rule
document that fails validation aborts startup with the offending rule named.

### Pipeline coverage, stated precisely

A rule can only fire on what the kernel chose to emit. The capture filter and the rule conditions are
deliberately not identical, and the differences are worth knowing before tuning:

| Case | Captured by kernel | Matched by rule | Note |
|---|---|---|---|
| `/etc/shadow`, `/etc/sudoers`, `/etc/passwd`, `/root/.ssh/*`, `/var/run/secrets/*`, `/proc/kcore` | yes | yes, except `/etc/passwd` | `passwd` is captured but intentionally not alerted, since PAM reads it constantly |
| `/proc/sys/kernel/core_pattern` | yes | no | captured to support a future container-escape rule; no rule consumes it today |
| `*.env` anywhere | yes, suffix filter | yes | |
| `id_rsa`, `*.pem`, `*.key`, `credentials.json` outside the captured prefixes | only if written to a staging directory | partially | the kernel filter runs before the rule; extend `is_sensitive_read_path()` to close this |
| Writes into `/tmp`, `/dev/shm`, `/usr/bin`, `/usr/local/bin` | yes | via `FILELESS_MEMFD_EXECUTION` execution paths | write events alone do not alert |
| `openat2` credential reads | no, only `sys_enter_openat` is hooked | no | a separate tracepoint; adding it is a kernel-side change |
| Raw sockets and `AF_UNIX` connections | no | n/a | `AF_INET` and `AF_INET6` only, by design |

The in-kernel filter is intentionally conservative: every path it adds is verified on real traffic before
it ships, because an `openat` filter that is too permissive costs more than a missed low-value event.

---

## 10. Enforcement semantics

Detailed hook semantics, ordering and race analysis: [docs/ENFORCEMENT.md](docs/ENFORCEMENT.md).

`config_map[0]` selects the mode. `0` (`ENFORCEMENT_AUDIT_ONLY`) makes every hook return 0.
`1` (`ENFORCEMENT_INLINE_BLOCK`) makes the hooks evaluate state.

| Hook | Denies | Return | Scope |
|---|---|---|---|
| `bprm_check_security` | any program execution | `-EPERM` | quarantined pid or cgroup |
| `socket_connect` | blocked IPv4 destination | `-EPERM` | **all** processes, blocked list is global |
| `socket_connect` | metadata service | `-EPERM` | quarantined pid or cgroup only |
| `file_open` | write-like opens | `-EACCES` | quarantined pid or cgroup |

Two consequences follow directly and are not incidental:

- Blocking an address is a node-wide decision. That is why `block_ipv4` is only ever emitted for
  addresses the rules consider infrastructure-hostile, and why the engine deduplicates them.
- A quarantined domain keeps its existing file descriptors. Quarantine stops new execution, new blocked
  connections and new writes; it does not revoke sockets already open. The paired `kill` action exists
  because of this, and `--active-kill` exists because some kernels cannot enforce at all.

Race conditions and their handling:

| Race | Window | Handling |
|---|---|---|
| Fork storm | child forks between rule match and map update | cgroup quarantine covers children created after the update, and covers existing children |
| PID reuse | pid exits and is recycled before the command lands | `sched_process_exit` deletes the entry; `SIGKILL` is refused for `pid <= 2`, and the destructive rules prefer cgroup scope |
| Exec in progress | process already inside `execve` when quarantined | `bprm_check_security` fires before the image is replaced, so the exec is denied |
| Engine death between alert and command | commands built but not sent | the audit record records `delivered: false`; the alert is never silently promoted to enforced |
| Two engines, one node | duplicate commands | dedup is per process, so the second engine's commands are idempotent map writes |

---

## 11. Failure modes

| Mode | Observable signal | Blast radius | Response |
|---|---|---|---|
| Kernel without BPF LSM | `lsm=unavailable`, `NOTICE: inline enforcement is inactive` | no enforcement, telemetry intact | enable `CONFIG_BPF_LSM` and `lsm=bpf`, or rely on `--active-kill` |
| Collector not running | engine retries every 1 s, `xsypher_socket_reconnects_total` climbs | no telemetry, no new policy | restart the unit; the engine reconnects itself |
| Engine not running | collector `clients=0`, `drops` climbs | no detection, policy already applied persists | restart; the collector does not buffer indefinitely |
| Ring buffer full | `drops` in the status line, `xsypher_ringbuf_frames_dropped` | events lost, nothing blocked retroactively | narrow kernel-side filtering or add CPU |
| Slow engine client | `dropped` in the collector status line | frames lost for that client only | reduce rule cost or event volume |
| Invalid rule document | startup aborts, offending rule named | no service, loud failure | fix the document; this is P4 by design |
| Audit log unwritable | startup aborts unless the path was overridden | no service | fix permissions; the fallback to `/tmp` applies only when the default was in use |
| Audit chain broken | `audit hash chain is INVALID: line N` | tamper or truncation, detection continues | restore from backup, investigate the writer |
| Metrics port in use | `metrics exporter disabled: ...` | no scraping, detection continues | change `--metrics-port` |

---

## 12. Performance

Method, harnesses and the full cost model: [docs/PERFORMANCE.md](docs/PERFORMANCE.md). Reference host is
2 vCPU, Debian 12, g++ 12, CPython 3.11, 10,016 events, repeated runs.

| Metric | Observed |
|---|---|
| Rule evaluation p50 | 6.2 µs |
| Rule evaluation p95 | 8.3 to 11.7 µs |
| Rule evaluation p99 | 14.8 to 17.3 µs |
| Rule evaluation worst case | 1.15 ms (first-pass cold caches) |
| Engine throughput, in-process replay | 136,000 to 151,000 events/s |
| Engine throughput, end to end | 34,000 to 38,000 events/s |
| Detection to kernel map update | 2.1 to 3.8 ms |
| Ring buffer capacity | 16 MiB, about 26,000 queued 640-byte records plus headers |
| Collector resident memory | about 10 MB plus libbpf accounting |
| Engine resident memory | about 60 MB at 200,000 tracked processes |

Percentiles vary by a few microseconds between runs; treat them as an order of magnitude, not a contract.
The budget is 500 µs per event, which leaves roughly 30× headroom at p99 and allows the rule set to
grow substantially before the evaluation stage becomes the constraint.

The first bottleneck at sustained load is the ring buffer, not rule evaluation. At 34,000 events/s end to
end a single node saturates one engine core; the correct response is kernel-side filtering, then rule
narrowing, then more CPU, in that order.

---

## 13. Deployment topologies

| Topology | Shape | Constraint |
|---|---|---|
| Single node | one collector, one engine, systemd units | simplest; engine holds the only copy of live lineage |
| Kubernetes DaemonSet | collector and engine as two containers in one pod, host PID and mount visibility for the collector | rolling update with `maxUnavailable: 10%` and a pod disruption budget, so sensor coverage is continuous |
| Fleet | one engine per node, scraped centrally | no cross-node correlation; ship the audit log and correlate in the SIEM |
| Air-gapped | images and wheels mirrored, rules from a local ConfigMap | no external dependency at runtime, including for the audit chain |

Each collector is per-kernel. It cannot be shared across hosts, and it cannot observe a workload it
cannot see the syscalls of, which in practice means the collector must run in the host PID namespace.

---

## 14. Operations

| Check | Command |
|---|---|
| Collector socket present | `test -S /run/xsypher/stream.sock && echo ok` |
| Engine liveness | `curl -fsS localhost:9109/healthz` |
| Enforcement actually firing | `curl -s localhost:9109/metrics \| grep xsypher_lsm_blocks_seen` |
| Telemetry flowing | `curl -s localhost:9109/metrics \| grep '^xsypher_events_total'` |
| Policy channel healthy | `curl -s localhost:9109/metrics \| grep commands_failed_total` |
| Audit chain intact | `PYTHONPATH=src python3 -c "from engine.mitigator import AlertLog; print(AlertLog.verify('/var/log/xsypher-alerts.jsonl'))"` |

Suggested service objectives for a production deployment:

| Objective | Target | Measured by |
|---|---|---|
| Detection latency, event to alert | p99 under 25 ms | `xsypher_rule_eval_seconds` plus collector status timing |
| Enforcement latency, alert to map | p99 under 10 ms | 2.1 to 3.8 ms observed |
| Sensor availability | 99.9% per node per month | collector process uptime, `drops` flat |
| Audit completeness | 100% of alerts, chain verified on startup | `AlertLog.verify` |
| Telemetry loss | under 0.1% of kernel events | `drops` over `events` in the status line |

Two alerts matter more than the rest: a silent sensor (`rate(xsypher_events_total[10m]) == 0`) and a
broken policy channel (`increase(xsypher_commands_failed_total[5m]) > 0`). They distinguish "nothing is
happening" from "we are not watching". Metric reference, alert rules, capacity planning, upgrade,
rollback, uninstall and the troubleshooting table are in [docs/OPERATIONS.md](docs/OPERATIONS.md).

---

## 15. Security of the sensor

The collector is the only privileged component and the only code in the data path that runs as root. It
parses fixed-size kernel records and does not interpret policy: it validates magic, version and command
type on a 32-byte datagram, then performs one map update. There is no policy language, no string
evaluation and no configuration parsing in the privileged process.

| Control | Where |
|---|---|
| Least privilege | `CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_IPC_LOCK`, ambient set limited to the first two |
| No new privileges | `NoNewPrivileges=true` on both units |
| Syscall filter | `SystemCallFilter=@system-service bpf perf_event_open` on the collector |
| Filesystem | `ProtectSystem=strict`, `ProtectHome=true`, `ReadWritePaths=/run/xsypher` on the collector; read-only root filesystem and `drop: ["ALL"]` for the engine container |
| Memory | `MemoryDenyWriteExecute=true` on the engine |
| Transport | `AF_UNIX` only, never a TCP port; socket directory created `0750` by `RuntimeDirectoryMode` |
| Engine capabilities | none; its only influence on the kernel is the validated command channel |

Report vulnerabilities privately per [SECURITY.md](SECURITY.md). The in-scope invariants are listed in
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

---

## 16. Build and test

```bash
make check-deps          # clang, g++, bpftool
make -j"$(nproc)"        # build/xsypher.bpf.o, build/xsypher.skel.h, build/xsypher-collector
make test                # unit tests
make verify              # ABI parity + tests + end-to-end simulation
```

`include/vmlinux.h` is generated from the running kernel's BTF by `scripts/gen_vmlinux.sh` and is not
committed. Where BTF and `bpftool` are both absent the script emits a reduced header suitable for type
checking only and says so; an object built against it must not be deployed.

| Suite | Count | Covers |
|---|---|---|
| `tests/test_wire_protocol.py` | 23 | sizes and offsets, C-to-Python parity by compiling the header, codec round trips, malformed frames, a real `SOCK_SEQPACKET` round trip |
| `tests/test_lineage_and_rules.py` | 36 | ancestry and TTL, eviction, all six rules firing and staying quiet on benign traffic, cooldowns, validation, audit chain write/verify/tamper/resume, metrics rendering and HTTP fetch |
| `tests/simulate_mcp_attack.py` | end to end | 10,000 benign events plus five attack chains over a real socket, byte comparison of every expected command, audit verification, benchmarks |

```console
$ python3 -m pytest tests -q
59 passed, 31 subtests passed in 0.55s

$ PYTHONPATH=src python3 tests/simulate_mcp_attack.py
  [1/3] streamed 10000 benign events in 0.28s (36,331 events/s)
  [2/3] injecting attack chains
        ok  chain A: MCP prompt injection -> interactive shell (2.1 ms)
        ok  chain B: MCP recon tool + reverse shell port (2.2 ms)
        ok  chain C: Cloud IMDS credential theft (2.2 ms)
        ok  chain D: Host credential harvest (2.2 ms)
        ok  chain E: Fileless payload staging via memfd (2.2 ms)
        enforcement pkts : 8 (expected 8)
        audit chain      : verified (8 record(s))
RESULT: PASSED
```

CI runs the engine, ABI parity and simulation on `ubuntu-24.04`; a full clang, bpftool and CMake build
with warnings as errors; and a rule-parity check that `config/rules.yaml` and the Kubernetes ConfigMap
copy have not drifted. Where the toolchain is unavailable the verification script reports those steps as
`SKIP` and type-checks the BPF program with the host C compiler instead.

---

## 17. Repository map

```
include/xsypher_abi.h     normative binary ABI, static assertions
src/bpf/xsypher.bpf.c     five tracepoints, three LSM hooks, six maps
src/collector/            bpf_loader, cgroup_resolver, uds_server, main reactor
src/engine/               abi, lineage, rule_engine, mitigator, metrics, tui, main
config/rules.yaml         detection content
deploy/                   Dockerfile, compose, Kubernetes DaemonSet, systemd units
scripts/                  gen_vmlinux.sh, verify_and_benchmark.sh
tests/                    unit tests and the end-to-end attack simulation
docs/                     threat model, architecture, protocol, detections, enforcement, ops, perf
```

---

## 18. Limitations and non-goals

Known limitations, in the order they are likely to affect a deployment:

- `args` captures four `argv` pointers of 64 bytes each. Enough for a command line, not for payloads.
- Container identity depends on cgroup layouts. Unknown runtimes resolve to `host`, which disables any
  rule conditioned on `container_only`.
- The in-kernel `file_open` hook sees the dentry basename, not a full path, so its credential-path branch
  cannot match `/etc/shadow` style absolute prefixes. The effective in-kernel file protection is
  write denial inside a quarantined domain; credential reads are detected, and enforced, through the
  rule path and the quarantine that follows. See [ENFORCEMENT.md](docs/ENFORCEMENT.md) for the exact
  behaviour and the intended fix.
- IMDS denial covers IPv4 in the LSM hook. The IPv6 equivalent `fd00:ec2::254` is handled by rule
  evaluation, which is after the fact rather than in the hook.
- `--active-kill` is a user-space `SIGKILL`. It is a mitigation for kernels without BPF LSM, not an
  authoritative control.
- A quarantined process keeps its open file descriptors and existing sockets.
- Single-node correlation only. There is no cross-host lineage.
- The sensor is removable by root. It is not an immutable boot chain, and it does not attempt to be.
- No DNS-level, TLS-level or HTTP-level inspection. Decisions use addresses, ports and paths.

---

## 19. Compatibility

| Axis | Support |
|---|---|
| Kernel | 5.10 to 6.x, one CO-RE object, no per-kernel builds |
| Architectures | x86_64, aarch64 |
| Distributions | any with BTF: Ubuntu 20.04+, Debian 11+, RHEL 9+, Amazon Linux 2023, Bottlerocket, Talos |
| Container runtimes | Docker, containerd, CRI-O; anything else reports `host` |
| Python | 3.10, 3.11, 3.12 (reference), 3.13 |
| libbpf | 1.0 or later; 1.1 or later for the epoll-driven ring buffer |
| Inline enforcement | `CONFIG_BPF_LSM=y` plus `lsm=bpf` on the kernel command line |

---

## 20. License

Apache-2.0 for user space; see [LICENSE](LICENSE). The eBPF program declares `SEC("license") = "GPL"`
because BPF-LSM program types and the GPL-only helpers it uses require a GPL-compatible licence; GPL-2.0
terms apply to that compilation unit and the object built from it.
