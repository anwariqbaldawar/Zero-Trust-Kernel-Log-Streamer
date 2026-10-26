# xSypher-Stream

**Zero-trust kernel telemetry and inline LSM enforcement for AI-agent and MCP
workloads.**

eBPF CO-RE (kernel) → libbpf + C++20 collector (transport) → Python 3.12 threat
engine (policy) → `wire_policy_cmd_t` → eBPF maps → `-EPERM`.

xSypher-Stream watches what processes actually *do* — exec, connect, open,
memfd — reconstructs their lineage, and when an AI agent / MCP server turns a
prompt injection into a shell, a reverse shell, a metadata-service credential
grab or a fileless payload, it quarantines the process tree **inside the
kernel** using the BPF LSM hooks that already sit in the syscall path.

```
   ┌──────────────────────────────── kernel space ─────────────────────────────┐
   │                                                                           │
   │  tracepoints                    BPF LSM hooks            BPF maps         │
   │  tp/syscalls/sys_enter_execve   lsm/bprm_check_security  events_ringbuf   │
   │  tp/syscalls/sys_enter_connect  lsm/socket_connect       quarantined_pids │
   │  tp/syscalls/sys_enter_openat   lsm/file_open            quarantined_cgrps│
   │  tp/syscalls/sys_enter_memfd    (return -EPERM)          blocked_ipv4     │
   │  tp/sched/sched_process_exit                             config_map       │
   │                         │                                     ▲          │
   └─────────────────────────┼─────────────────────────────────────┼──────────┘
                             │ BPF_MAP_TYPE_RINGBUF (16 MiB)        │ bpf_map_update_elem
                             ▼                                     │
   ┌──────────────────────────── user space ────────────────────────────┬──────┐
   │  xsypher-collector (C++20, libbpf)                                 │      │
   │  ring_buffer__poll → enrich (container id) → seq_no → broadcast    │      │
   └───────────────────────────────────┬────────────────────────────────┴──────┘
                                       │ AF_UNIX / SOCK_SEQPACKET
                        wire_event_msg_t (720 B) ▲   ▼ wire_policy_cmd_t (32 B)
   ┌───────────────────────────────────┴───────────────────────────────────────┐
   │  engine (Python 3.12, asyncio)                                             │
   │  decode → lineage graph → YAML rules → mitigate → JSONL audit + /metrics   │
   └───────────────────────────────────────────────────────────────────────────┘
```

---

## Table of contents

1. [What it detects](#what-it-detects)
2. [Repository layout](#repository-layout)
3. [Build](#build)
4. [Run](#run)
5. [Rules](#rules)
6. [Binary ABI](#binary-abi)
7. [Metrics](#metrics)
8. [Audit log](#audit-log)
9. [Deployment](#deployment)
10. [Verification & benchmarks](#verification--benchmarks)
11. [Design notes & limits](#design-notes--limits)

---

## What it detects

| # | Rule | Severity | Detection | Kernel action |
|---|------|----------|-----------|---------------|
| 1 | `MCP_SHELL_BREAKOUT` | critical | `node → python3 → /bin/sh` (AI/MCP ancestor spawns a shell or tmux/screen) | `QUARANTINE_CGROUP` + `SIGKILL` |
| 2 | `MCP_RECON_OR_EXFIL_TOOL` | high | AI/MCP ancestor spawns `curl`, `wget`, `nc`, `socat`, `nmap`, `ssh`, `base64`, … | `QUARANTINE_PID` + `SIGKILL` |
| 3 | `CLOUD_IMDS_CREDENTIAL_THEFT` | critical | container connects to `169.254.169.254` | `QUARANTINE_CGROUP` + `BLOCK_IPV4` + `SIGKILL` |
| 4 | `SENSITIVE_CREDENTIAL_HARVEST` | critical | `/etc/shadow`, `/etc/sudoers`, `/root/.ssh`, K8s SA token, `.env`, `id_rsa` | `QUARANTINE_PID` + `SIGKILL` |
| 5 | `FILELESS_MEMFD_EXECUTION` | critical | `memfd_create` or exec from `/memfd:`, `/proc/self/fd/`, `/dev/shm/` | `QUARANTINE_CGROUP` + `SIGKILL` |
| 6 | `SUSPICIOUS_OUTBOUND_C2_PORT` | high | container / web-MCP worker → `4444`, `1337`, `31337`, `5555`, `6667`, `9001` | `QUARANTINE_PID` + `BLOCK_IPV4` + `SIGKILL` |

Enforcement is **inline**: once a cgroup is quarantined with
`enforcement_mode = INLINE_BLOCK`, the kernel refuses further `execve`, blocked
`connect()` targets and credential `open()` calls for that domain with `-EPERM`
before the syscall ever completes.

---

## Repository layout

```
xsypher-stream/
├── CMakeLists.txt              # CMake build (BPF → skeleton → collector → ctest)
├── Makefile                    # plain-make build + test/verify/run targets
├── README.md
├── requirements.txt            # PyYAML (only non-stdlib Python dependency)
├── config/
│   └── rules.yaml              # 6 declarative zero-trust rules
├── include/
│   └── xsypher_abi.h           # shared C/C++/Python binary ABI (byte exact)
├── src/
│   ├── bpf/
│   │   └── xsypher.bpf.c       # CO-RE tracepoints + LSM hooks + ring buffer
│   ├── collector/
│   │   ├── main.cpp            # epoll reactor, CLI, signal handling
│   │   ├── bpf_loader.{hpp,cpp}# libbpf lifecycle, LSM fallback, map updates
│   │   ├── cgroup_resolver.*   # pid/cgroup → 64-hex container ID (LRU+TTL)
│   │   └── uds_server.*        # AF_UNIX SOCK_SEQPACKET broadcast + commands
│   └── engine/
│       ├── main.py             # asyncio engine, UDS transport, CLI
│       ├── abi.py              # ctypes mirror with size assertions
│       ├── lineage.py          # process lineage graph (TTL, bounded)
│       ├── rule_engine.py      # declarative rule evaluation (< 20 µs p99)
│       ├── mitigator.py        # policy commands + SHA-256 chained JSONL
│       ├── metrics.py          # zero-dependency Prometheus exporter
│       ├── tui.py              # ANSI live monitor
│       └── __init__.py
├── deploy/
│   ├── Dockerfile                    # multi-stage: build → slim runtime
│   ├── docker-compose.yml            # privileged collector + unprivileged engine
│   ├── kubernetes-daemonset.yaml     # one pod per node, two containers
│   ├── xsypher-collector.service     # systemd unit (kernel side)
│   └── xsypher-engine.service        # systemd unit (policy side)
├── scripts/
│   ├── gen_vmlinux.sh          # BTF dump with documented stub fallback
│   └── verify_and_benchmark.sh # ABI + build + tests + attack simulation
└── tests/
    ├── test_wire_protocol.py   # layout, codecs, real SOCK_SEQPACKET round trip
    ├── test_lineage_and_rules.py
    └── simulate_mcp_attack.py  # 10k events + 5 attack chains, end to end
```

---

## Build

### Dependencies

| Need | Package (Debian/Ubuntu) |
|------|-------------------------|
| `clang` ≥ 12, `llvm` | `clang llvm` |
| `bpftool` (skeleton + BTF) | `bpftool` / `linux-tools-$(uname -r)` |
| libbpf ≥ 1.0 | `libbpf-dev libelf-dev zlib1g-dev` |
| C++20 compiler | `g++` ≥ 12 or `clang++` |
| Python ≥ 3.10 (3.12 recommended) | `python3 python3-yaml` |

```bash
make check-deps        # verify clang/bpftool/g++ are visible
make -j"$(nproc)"      # build/xsypher.bpf.o, build/xsypher.skel.h, build/xsypher-collector
```

or with CMake:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
```

`include/vmlinux.h` is generated from `/sys/kernel/btf/vmlinux` by
`scripts/gen_vmlinux.sh` and is git-ignored. If the host has no BTF and no
`bpftool`, the script writes a clearly-labelled stub header so type checking
still succeeds — **regenerate it on the target kernel before loading**.

The BPF object is built for the host architecture automatically
(`-D__TARGET_ARCH_x86` or `-D__TARGET_ARCH_arm64`).

---

## Run

```bash
# 1. collector (root: needs CAP_BPF/CAP_PERFMON and the ring buffer)
sudo ./build/xsypher-collector \
    --socket-path /run/xsypher/stream.sock \
    --block-imds \
    --enforce \
    --verbose

# 2. engine
PYTHONPATH=src sudo -E python3 -m engine.main \
    --socket-path /run/xsypher/stream.sock \
    --rules config/rules.yaml \
    --alert-log /var/log/xsypher-alerts.jsonl \
    --metrics-port 9109 \
    --enforce-kernel
```

No root, no kernel? Use the synthetic generator — it exercises the *entire*
Python path (lineage, rules, mitigation, audit log, metrics, TUI):

```bash
PYTHONPATH=src python3 -m engine.main --simulate --metrics-port 9109
```

Collector flags: `--socket-path`, `--enforce`, `--block-imds`, `--verbose`,
`--no-lsm-fallback`, `--no-status`, `--help`.

Engine flags: `--socket-path`, `--rules`, `--alert-log`, `--metrics-port`,
`--metrics-host`, `--enforce-kernel`, `--active-kill`, `--simulate`,
`--simulate-count`, `--lineage-ttl`, `--no-color`, `--quiet`, `--verbose`,
`--fsync-alerts`.

> **Kernel requirement for inline blocking:** `CONFIG_BPF_LSM=y` plus
> `lsm=bpf` on the kernel command line. Without it the collector logs a warning
> and keeps streaming telemetry (the user-space `SIGKILL` mitigation still
> works with `--active-kill`).

---

## Rules

Rules are data. `config/rules.yaml` is loaded at startup; no code changes are
needed to add, disable or retune a rule.

```yaml
- id: MCP_SHELL_BREAKOUT
  title: "MCP/AI agent spawned an interactive shell"
  severity: critical            # info | low | medium | high | critical
  enabled: true
  event_types: [execve]         # execve connect openat memfd_create process_exit lsm_block
  conditions:
    exe_in: [sh, bash, zsh, dash, ksh, fish, csh, tcsh, tmux, screen, dtach]
    ancestor_has_ai_runtime: true
    ancestor_min_depth: 1
  actions: [quarantine_cgroup, kill]   # quarantine_pid quarantine_cgroup block_ipv4 block_imds kill
```

Condition semantics: one `conditions:` mapping is **ANDed**; a list value is
**ORed** internally; the special `any_of:` key holds a list of condition groups
that are **ORed** with each other (used by rule 4 and 5, which each cover two
distinct shapes).

| Condition | Meaning |
|-----------|---------|
| `event_types` | restrict to these kernel events |
| `exe_in` / `exe_not_in` | subject executable basename (lineage-aware for non-exec events) |
| `exe_prefix_in` / `exe_suffix_in` | raw `filename` prefix/suffix (fileless detection) |
| `comm_in` / `comm_not_in` | 16-byte kernel `comm` |
| `path_prefix_in` / `path_suffix_in` / `path_contains` | opened file path tests |
| `args_contains` | joined argv substring match |
| `dport_in` / `daddr_in` | destination port (host order) / IPv4 or IPv6 literal |
| `uid_in` / `uid_not_in` | credential of the subject |
| `container_only` | only fire inside a non-host cgroup |
| `container_or_comm_in` | fire in a container **or** for these binaries |
| `ancestor_has_ai_runtime` | any ancestor is `node`, `python3`, `uvicorn`, `claude-mcp`, … |
| `ancestor_any_in` | any ancestor basename in an explicit list |
| `ancestor_min_depth` | require N ancestors |
| `monitor_only` | alert but never enforce |

Unknown keys, unknown event types, unknown actions, duplicate ids and empty
rule sets are rejected at load time with a precise error message.

---

## Binary ABI

`include/xsypher_abi.h` is the single source of truth; `src/engine/abi.py`
mirrors it with `ctypes` and asserts every size and offset at import time. All
structures are `packed, aligned(8)` with explicit padding, so clang, g++ and
ctypes agree byte for byte.

| Structure | Size | Key offsets |
|-----------|------|-------------|
| `struct kernel_event_t` | **640** | `event_type` 48, `retval` 52, `dport` 58, `daddr_v4` 64, `daddr_v6` 72, `open_flags` 88, `comm` 92, `parent_comm` 108, `filename` 124, `args` 380 |
| `struct wire_event_msg_t` | **720** | `magic` 0, `version` 4, `msg_type` 6, `seq_no` 8, `container_id` 16, `event` 80 |
| `struct wire_policy_cmd_t` | **32** | `magic` 0, `cmd_type` 6, `target_cgroup_id` 8, `target_pid` 16, `target_ipv4` 20, `enforcement_mode` 24 |

Constants: `XSYPHER_WIRE_MAGIC = 0x58535950` (`"XSYP"`), `XSYPHER_ABI_VERSION = 2`,
`MAX_COMM_LEN = 16`, `MAX_PATH_LEN = 256`, `MAX_ARGS_LEN = 256`,
`MAX_CONTAINER_ID_LEN = 64`.

Conventions worth remembering:

* IP addresses and ports are stored in **raw network byte order**. On a
  little-endian host `169.254.169.254` appears as `0xFEA9FEA9`
  (`XSYPHER_IMDS_IPV4_RAW`, mirrored as `abi.IMDS_IPV4_RAW`).
* A full 64-hex container ID fills `container_id` completely and is therefore
  not NUL terminated; shorter values (`"host"`) are NUL padded. Both sides
  decode both shapes.

Command types: `CMD_QUARANTINE_PID=10`, `CMD_UNQUARANTINE_PID=11`,
`CMD_QUARANTINE_CGROUP=12`, `CMD_UNQUARANTINE_CGROUP=13`, `CMD_BLOCK_IPV4=14`,
`CMD_UNBLOCK_IPV4=15`, `CMD_SET_ENFORCEMENT_MODE=16` (`0` = audit, `1` = inline
block).

---

## Metrics

`GET http://<host>:9109/metrics` (Prometheus text format, zero dependencies):

```
xsypher_events_total{type="execve"}
xsypher_alerts_total{rule="MCP_SHELL_BREAKOUT",severity="critical"}
xsypher_mitigations_total{action="quarantine_cgroup"}
xsypher_active_tracked_processes
xsypher_rule_cooldowns_active
xsypher_lsm_blocks_seen{type="lsm_block"}
xsypher_commands_sent_total{command="quarantine_pid"}
xsypher_commands_failed_total{reason="disconnected"}
xsypher_socket_reconnects_total
xsypher_rule_eval_seconds_sum / _count
xsypher_engine_uptime_seconds
```

`GET /healthz` returns `200 ok` for liveness/readiness probes.

---

## Audit log

Every alert is appended as one JSON line with a **SHA-256 hash chain**:

```
hash_n = SHA256(hex(hash_{n-1}) || canonical_json(record_n \ {hash, alert_id}))
hash_0 = "0" * 64
```

Each record carries `prev_hash`, `hash`, `alert_id` (= first 16 hex of `hash`),
`sequence`, the rule/severity/reason, the full subject identity, the event, the
ancestry chain and the mitigations that were (or were not) delivered. Any edit
or deletion invalidates every later hash line, so the log is tamper-evident
without external infrastructure. The engine re-verifies the chain on startup
and logs `audit hash chain is INVALID` if it does not add up:

```bash
PYTHONPATH=src python3 -c \
  "from engine.mitigator import AlertLog; print(AlertLog.verify('/var/log/xsypher-alerts.jsonl'))"
```

---

## Deployment

**Docker Compose** (privileged collector + locked-down engine):

```bash
cd deploy && docker compose up --build
```

**Kubernetes** (DaemonSet, one pod per node, hostPID + hostNetwork, engine
metrics annotated for scraping):

```bash
kubectl apply -f deploy/kubernetes-daemonset.yaml
```

**systemd** (bare metal / VM):

```bash
sudo make install                       # binary, engine package, rules, unit files
sudo useradd --system --no-create-home --shell /usr/sbin/nologin xsypher
sudo systemctl daemon-reload
sudo systemctl enable --now xsypher-collector xsypher-engine
journalctl -u xsypher-collector -u xsypher-engine -f
```

The engine container runs with `readOnlyRootFilesystem`, `capabilities.drop:
[ALL]` and `no-new-privileges`; only the collector is privileged, and the
socket lives on a memory-backed `emptyDir` shared by the two containers.

---

## Verification & benchmarks

```bash
./scripts/verify_and_benchmark.sh              # full run, 10k events
./scripts/verify_and_benchmark.sh --quick      # 2k events
make test && make simulate                     # or the individual steps
```

The script performs the ABI cross-check (C compiler vs ctypes), the BPF/C++
build (or an explicit, non-failing `SKIP` when the toolchain is absent), the
whole pytest suite, and `tests/simulate_mcp_attack.py`.

`simulate_mcp_attack.py` stands up a real `AF_UNIX/SOCK_SEQPACKET` server
(playing the C++ collector), launches the engine as a separate process, streams
**10,000 benign events plus five attack chains**, and asserts that exactly the
expected `wire_policy_cmd_t` bytes come back:

```
  [1/3] streamed 10000 benign events in 0.27s (36,443 events/s)
  [2/3] injecting attack chains
        ok  chain A: MCP prompt injection -> interactive shell (2.1 ms)
        ok  chain B: MCP recon tool + reverse shell port (2.2 ms)
        ok  chain C: Cloud IMDS credential theft (2.2 ms)
        ok  chain D: Host credential harvest (2.2 ms)
        ok  chain E: Fileless payload staging via memfd (3.8 ms)

        rule eval mean   : 5.65 us
        rule eval p95    : 11.29 us
        rule eval p99    : 18.55 us
        rule eval max    : 1111.78 us      (first event, includes lazy JIT/caches)

        enforcement pkts : 8 (expected 8)
          - quarantine_cgroup(cgroup=40961)
          - quarantine_pid(pid=10203)
          - block_ipv4(ip=203.0.113.9)
          - quarantine_pid(pid=10302)
          - quarantine_cgroup(cgroup=40963)
          - block_ipv4(ip=169.254.169.254)
          - quarantine_pid(pid=10402)
          - quarantine_cgroup(cgroup=40965)
        alerts by rule   : CLOUD_IMDS_CREDENTIAL_THEFT=1, FILELESS_MEMFD_EXECUTION=2,
                           MCP_RECON_OR_EXFIL_TOOL=2, MCP_SHELL_BREAKOUT=1,
                           SENSITIVE_CREDENTIAL_HARVEST=1, SUSPICIOUS_OUTBOUND_C2_PORT=1
        audit chain      : verified (8 record(s))
```

Numbers from a 2-vCPU sandbox (`g++ 12`, Python 3.11): rule evaluation p99
**≈ 16–19 µs** (budget is 500 µs), in-process throughput **≈ 137k events/s**,
end-to-end (encode → socket → decode → rules → mitigation → JSONL) **≈ 36k
events/s** on a single engine process.

---

## Design notes & limits

**Why a ring buffer?** `BPF_MAP_TYPE_RINGBUF` gives a single shared, lockless,
zero-copy (reserve/submit) queue. The kernel never blocks on a slow consumer; if
the buffer is full the event is dropped and counted in the per-CPU
`metrics_map` (`METRIC_RINGBUF_DROPS`) instead of stalling a syscall.

**Why `SOCK_SEQPACKET`?** Message boundaries are preserved (a 720-byte frame is
never split or coalesced), the protocol is connection-oriented (the collector
notices engine restarts), and it is local-only — no TCP stack involved.

**Why quarantine a cgroup rather than a PID?** PIDs are recycled in seconds and
an attacker can fork faster than user space can kill. Quarantining the container
cgroup (300–400 µs) covers every existing and future task in that domain, and
the exiting-tgid cleanup in `sched_process_exit` prevents PID-reuse false
positives for the PID-level map.

**Failure modes that are handled deliberately**

* No BPF-LSM in the kernel → collector auto-retries the load with the three
  `lsm/*` programs disabled (`bpf_program__set_autoload(prog, false)`),
  telemetry keeps flowing, status line says `lsm=unavailable`.
* Engine restarts → collector keeps streaming, accepts the new connection, and
  the engine re-announces `CMD_SET_ENFORCEMENT_MODE`.
* Engine exits → releases every quarantine it applied (`UNQUARANTINE_*`) so the
  node does not stay locked down.
* Event storms → per-`(rule, pid)` cooldown (`cooldown_seconds`) plus kernel-side
  `openat` filtering (only credential paths and writes into `/tmp`, `/dev/shm`,
  `/usr/bin`).
* Prompt injection that deletes the alert log → the SHA-256 chain breaks and the
  engine reports it on the next start.

**Limits, stated honestly**

* `kernel_event_t.args` captures the first 4 argv pointers (64 bytes each),
  joined with spaces — enough for a command line, not for arbitrary binaries.
* The cgroup → container-ID resolver parses `/proc/<pid>/cgroup` with a bounded
  LRU + TTL cache; a process in a non-Docker/containerd/CRI-O runtime resolves to
  `host`.
* `--active-kill` is user space and therefore racy against a fast fork loop; the
  kernel LSM quarantine is the authoritative control.
* IMDS blocking covers IPv4 `169.254.169.254` and IPv6 `fd00:ec2::254` (rule 3);
  the LSM hook itself enforces the IPv4 address, which is what AWS/GCP/Azure
  serve to IPv4 workloads.
* The stub `vmlinux.h` fallback is for compile checks only — never ship an
  object built against it.

---

## License

Apache-2.0 for user space, GPL-2.0 for the BPF object (`SEC("license") = "GPL"`,
required for BPF-LSM programs). See `include/xsypher_abi.h` and
`src/bpf/xsypher.bpf.c`.
