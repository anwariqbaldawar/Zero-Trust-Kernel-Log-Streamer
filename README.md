# xSypher-Stream

**Zero-trust telemetry and inline enforcement for AI agent hosts.**
eBPF CO-RE at the syscall boundary, policy decisions in an unprivileged Python engine, denials
enforced by BPF LSM hooks in the kernel.

[![ci](https://github.com/anwariqbaldawar/Zero-Trust-Kernel-Log-Streamer/actions/workflows/ci.yml/badge.svg)](https://github.com/anwariqbaldawar/Zero-Trust-Kernel-Log-Streamer/actions/workflows/ci.yml)
![abi](https://img.shields.io/badge/wire%20abi-v2-0369a1?style=flat-square)
![kernel](https://img.shields.io/badge/kernel-5.10%2B-334155?style=flat-square)
![tests](https://img.shields.io/badge/tests-59%20passing-15803d?style=flat-square)
![license](https://img.shields.io/badge/license-Apache--2.0%20%2F%20GPL--2.0-475569?style=flat-square)

| | |
|---|---|
| **Version** | 2.0.0, wire ABI v2 |
| **Platforms** | Linux 5.10+, BTF required, x86_64 and aarch64 |
| **Enforcement** | `CONFIG_BPF_LSM=y` and `lsm=bpf`; telemetry runs without either |
| **Collector** | C++20, libbpf 1.0+, single-threaded epoll reactor |
| **Engine** | Python 3.12, asyncio, PyYAML, no other dependencies |
| **Footprint** | ~10 MB collector RSS, ~60 MB engine at 200k tracked processes |

### Contents

| Section | Read it if you are |
|---|---|
| [1. The problem](#1-the-problem) · [2. How it works](#2-how-it-works) | deciding whether this fits |
| [3. Threat model](#3-threat-model) | a security reviewer |
| [4. Kernel layer](#4-kernel-layer) · [5. Components](#5-components) | an SRE or a kernel engineer |
| [6. Wire protocol](#6-wire-protocol) · [7. Detection](#7-detection) | integrating or tuning |
| [8. Enforcement](#8-enforcement) · [9. Live output](#9-live-output) | responding to an alert |
| [10. Metrics and audit](#10-metrics-and-audit) · [11. Install](#11-install) | operating it |
| [12. Performance](#12-performance) · [13. Failure modes](#13-failure-modes) | capacity planning |
| [14. Operations](#14-operations) · [15. Sensor security](#15-sensor-security) | running it in production |
| [16. Development](#16-development) · [17. Limits](#17-limits-and-non-goals) | changing it |

### Deep reference

[Threat model](docs/THREAT-MODEL.md) ·
[Architecture](docs/ARCHITECTURE.md) ·
[Wire protocol](docs/WIRE-PROTOCOL.md) ·
[Detections](docs/DETECTIONS.md) ·
[Enforcement](docs/ENFORCEMENT.md) ·
[Configuration](docs/CONFIGURATION.md) ·
[Operations](docs/OPERATIONS.md) ·
[Performance](docs/PERFORMANCE.md) ·
[Contributing](CONTRIBUTING.md) ·
[Security policy](SECURITY.md)

---

## 1. The problem

An MCP server publishes tools to a language model. The model calls them with arguments it chose. Every
control around that loop assumes those arguments are benign: the container may run `sh` because the
image ships `/bin/sh`, the pod may reach link-local because egress is open, the process may read its own
mounted secrets because it is the same UID.

A successful prompt injection produces a chain where **every step is authorised**. It completes in
single-digit milliseconds.

![Attack chain timeline and detection coverage: five kernel-visible steps from a prompt-injected tool call to credential exfiltration, and three lanes comparing image scanning, host agent polling and xSypher enforcement windows](docs/fig-killchain.svg)

*Figure 1. The same five syscalls, seen by three kinds of control. Image scanning finishes before the process exists; a one-second `/proc` poll lands long after the chain ends; the tracepoint sees step 2 and the LSM hook denies step 3.*

Only the syscall path is fast enough to observe this, and only an LSM hook can stop it without first
killing the workload. xSypher-Stream occupies exactly those two points.

---

## 2. How it works

![Component and data flow: kernel tracepoints and LSM hooks, a 16 MiB ring buffer, the C++20 collector, the AF_UNIX socket, the Python engine, and 32-byte policy commands returning to the BPF maps](docs/architecture.svg)

*Figure 2. Telemetry flows left to right, policy right to left. The kernel never blocks on either user-space component.*

An event crosses five stages:

| Stage | Where | Cost on the reference host |
|---|---|---|
| 1. Reserve and fill a 640-byte record | kernel, ring buffer | sub-microsecond |
| 2. Poll, resolve container identity, wrap in a 720-byte frame | collector | one hash lookup on a cache hit |
| 3. Broadcast on `AF_UNIX`/`SOCK_SEQPACKET` | collector | one `send()` per attached client |
| 4. Decode, update lineage, evaluate rules | engine | 5 to 20 µs |
| 5. Build command, send, apply to a map | engine and collector | 2.1 to 3.8 ms round trip |

Four properties hold by design:

- **The kernel never blocks on user space.** A full ring buffer drops events and increments a counter.
- **Policy outlives the engine.** Quarantine state lives in BPF maps; a crashed engine leaves it in force.
- **Degradation is never silent.** No BPF LSM means `lsm=unavailable` and a `NOTICE`, never a false claim.
- **Rule sets are whole or absent.** An invalid document aborts startup instead of running with fewer detections.

---

## 3. Threat model

Full assets, boundaries and non-goals: [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

| Attacker capability | In scope | Control that answers it |
|---|---|---|
| Controls prompt input to a tool-using agent | yes | ancestry-aware execution rules |
| Executes commands in the container as the workload UID | yes | cgroup quarantine, `bprm_check_security` |
| Reaches the metadata service over IPv4 | yes | `socket_connect` address block |
| Reads mounted secrets | yes | `openat` detection, then quarantine |
| Stages and runs a payload from memory | yes | `memfd_create` detection, exec denied |
| Has root on the host | **no** | sensor is removable by design |
| Has kernel code execution | **no** | report upstream |

Invariants, each with a failure signature in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md):

| Id | Property |
|---|---|
| P1 | A traced syscall never blocks on user space |
| P2 | Policy survives an engine restart |
| P3 | Degradation is reported, never implied |
| P4 | A rule document is accepted whole or rejected |
| P5 | Every alert commits to the previous record's SHA-256 |
| P6 | Enforcement is reversible on graceful shutdown |
| P7 | Privileged parsing is bounded to 32-byte commands |

---

## 4. Kernel layer

One CO-RE object, eight programs, six maps, no per-kernel builds.

| Program | Hook | Emits | Filtering |
|---|---|---|---|
| `xsypher_execve` | `tp/syscalls/sys_enter_execve` | `EVENT_EXECVE` | none, four `argv` entries of 64 B |
| `xsypher_connect` | `tp/syscalls/sys_enter_connect` | `EVENT_CONNECT` | `AF_INET` and `AF_INET6` |
| `xsypher_openat` | `tp/syscalls/sys_enter_openat` | `EVENT_OPENAT` | credential prefixes, `.env`, writes into staging directories |
| `xsypher_memfd_create` | `tp/syscalls/sys_enter_memfd_create` | `EVENT_MEMFD_CREATE` | none |
| `xsypher_process_exit` | `tp/sched/sched_process_exit` | `EVENT_PROCESS_EXIT` | deletes the tgid from the quarantine map |
| `xsypher_lsm_bprm_check` | `lsm/bprm_check_security` | `EVENT_LSM_BLOCK` | quarantined domains only |
| `xsypher_lsm_socket_connect` | `lsm/socket_connect` | `EVENT_LSM_BLOCK` | IPv4 blocked destinations, quarantined IMDS |
| `xsypher_lsm_file_open` | `lsm/file_open` | `EVENT_LSM_BLOCK` | quarantined domains only |

| Map | Type | Key | Value | Max |
|---|---|---|---|---|
| `events_ringbuf` | `RINGBUF` | n/a | `kernel_event_t` | 16 MiB |
| `quarantined_pids_map` | `HASH` | `u32` tgid | `u8` action | 16,384 |
| `quarantined_cgroups_map` | `HASH` | `u64` cgroup id | `u8` action | 4,096 |
| `blocked_ipv4_map` | `HASH` | raw IPv4 | `u8` reason | 8,192 |
| `config_map` | `ARRAY` | `0` | `u32` mode | 1 |
| `metrics_map` | `PERCPU_ARRAY` | metric id | `u64` | 16 |

The verifier shapes the code, and that is visible in the source: constant loop bounds only, string
comparison against stack scratch buffers, `BPF_CORE_READ` for every task field, no direct user pointer,
and `nsproxy` null-checked because it is cleared while a task exits.

---

## 5. Components

![Deployment topology: workloads and kernel programs on a node, the privileged collector, the unprivileged engine, and outbound paths to Prometheus, a log shipper and the SIEM](docs/fig-deployment.svg)

*Figure 3. One collector per kernel. The only listening socket in the whole system is the metrics port.*

| Component | Language | Privilege | If it stops |
|---|---|---|---|
| Kernel programs | restricted C, BPF CO-RE | kernel | no telemetry, no enforcement; map state persists |
| Collector | C++20, libbpf | root or `CAP_BPF` + `CAP_PERFMON` | engine reconnects every second; kernel policy stays applied |
| Engine | Python 3.12, asyncio | none | detection stops; collector drops frames and counts them |

Collector internals worth knowing: a single `epoll` set covers the ring buffer fd, the listening socket,
clients and a `signalfd`, so the hot path takes no locks. Container identity comes from a two-level
cache, `pid` to container with a five-second TTL and `cgroup_id` to container, both bounded LRU. A
slow client is dropped frame by frame rather than stalling the ring buffer callback.

---

## 6. Wire protocol

![Byte layout of the telemetry frame, its header zoomed to field level, and the 32-byte policy command](docs/fig-frame.svg)

*Figure 4. Three fixed structures. `include/xsypher_abi.h` is normative; `src/engine/abi.py` mirrors it with `ctypes` and asserts every size and offset at import.*

```
50 59 53 58 02 00 01 00 97 ce 01 00 00 00 00 00  |PYSX............|   magic, v2, type, seq_no
32 36 31 30 31 64 36 65 ...                      |26101d6e040e... |   64 B container id, no NUL
24 cf 3e b3 0e 16 72 18                          |$.>...r......... |   kernel timestamp, ns
```

| Structure | Size | Direction |
|---|---|---|
| `struct kernel_event_t` | 640 B | kernel to collector, one ring buffer record |
| `struct wire_event_msg_t` | 720 B | collector to engine, one datagram |
| `struct wire_policy_cmd_t` | 32 B | engine to collector, one datagram |

Three conventions that break naive decoders, all deliberate:

- **Network byte order is preserved.** `169.254.169.254` is `0xFEA9FEA9` in memory; use `XSYPHER_IMDS_IPV4_RAW`.
- **`container_id` may not be NUL terminated.** A full 64-hex id fills the field exactly.
- **One datagram is one frame.** A short read is a protocol error, never a partial frame to reassemble.

Offsets, hexdumps and the connection state machine: [docs/WIRE-PROTOCOL.md](docs/WIRE-PROTOCOL.md).

---

## 7. Detection

Six rules ship in [`config/rules.yaml`](config/rules.yaml). They are data: no rebuild, no kernel change.

| Rule | Severity | Keyed on | Actions |
|---|---|---|---|
| `MCP_SHELL_BREAKOUT` | critical | shell or multiplexer with an AI-runtime ancestor | quarantine cgroup, kill |
| `MCP_RECON_OR_EXFIL_TOOL` | high | network or encoding tooling with an AI-runtime ancestor | quarantine pid, kill |
| `CLOUD_IMDS_CREDENTIAL_THEFT` | critical | container connection to `169.254.169.254` | quarantine cgroup, block IPv4, kill |
| `SENSITIVE_CREDENTIAL_HARVEST` | critical | credential-file open by a non-authorised process | quarantine pid, kill |
| `FILELESS_MEMFD_EXECUTION` | critical | `memfd_create`, or execution from `/memfd:`, `/proc/self/fd/`, `/dev/shm/` | quarantine cgroup, kill |
| `SUSPICIOUS_OUTBOUND_C2_PORT` | high | container or web worker to a known reverse-shell port | quarantine pid, block IPv4, kill |

![Detection coverage matrix of ten attacker techniques against the six shipped rules, with four documented gaps](docs/fig-coverage.svg)

*Figure 5. Coverage is stated per technique rather than per rule, because a rule that never fires on real traffic is worse than no rule: it inflates confidence.*

Gaps are documented with the source change that closes each one, in
[docs/DETECTIONS.md](docs/DETECTIONS.md). Two are worth repeating here: `openat2` is a separate
tracepoint and is not hooked, and the `file_open` hook sees a dentry basename, so its credential-path
prefix check cannot match an absolute path.

---

## 8. Enforcement

![Quarantine state machine with the audit-only path and the three LSM hooks that deny while a domain is quarantined](docs/fig-quarantine.svg)

*Figure 6. Policy state lives in BPF maps. `AUDIT_ONLY` skips the denial, not the detection.*

| Hook | Denies | Return | Scope |
|---|---|---|---|
| `bprm_check_security` | any program execution | `-EPERM` | quarantined pid or cgroup |
| `socket_connect` | blocked IPv4 | `-EPERM` | **all processes**, block list is node-wide |
| `socket_connect` | metadata service | `-EPERM` | quarantined pid or cgroup |
| `file_open` | write-like opens | `-EACCES` | quarantined pid or cgroup |

Two consequences follow directly, and neither is incidental:

- Blocking an address is a **node-wide decision**. That is why only rules identifying infrastructure-hostile
  destinations emit `block_ipv4`.
- A quarantined process **keeps its open descriptors**. Quarantine stops new execution, new blocked
  connections and new writes. The paired `kill` action exists precisely because of that gap.

| Race | Handling |
|---|---|
| Fork storm | cgroup quarantine covers tasks created after the update |
| PID reuse | `sched_process_exit` deletes the entry; `SIGKILL` refuses `pid <= 2` |
| Exec in flight | `bprm_check_security` runs before the image is replaced |
| Engine crash mid-dispatch | the audit record carries `delivered: false`, never an assumed success |
| Collector restart | maps return empty; the engine re-sends the enforcement mode on reconnect |

Detailed semantics and residual risk: [docs/ENFORCEMENT.md](docs/ENFORCEMENT.md).

---

## 9. Live output

![Terminal window showing the engine banner, a critical shell breakout alert with its lineage, the delivered quarantine command, and two LSM denial records](docs/fig-terminal.svg)

*Figure 7. Captured from `python3 -m engine.main --simulate --enforce-kernel`. Line-oriented on purpose: the same bytes go to a TTY or to a log shipper.*

The alert block is the operational unit. It carries the resolved lineage, so an analyst can answer "why
did this fire" without opening a second tool:

```console
$ sudo -E PYTHONPATH=src python3 -m engine.main \
    --socket-path /run/xsypher/stream.sock \
    --rules /etc/xsypher/rules.yaml \
    --enforce-kernel --verbose
  [ok] loaded 6 rules from /etc/xsypher/rules.yaml; alert log /var/log/xsypher/alerts.jsonl (chain seq=0)
  [..] audit hash chain verified (8 record(s))
  [ok] prometheus exporter listening on 0.0.0.0:9109/metrics
  [..] kernel enforcement is ON (wire_policy_cmd_t -> eBPF maps)

  ║ lineage : mcp-server -> python3 -> sh[1042]
  ║ actions : quarantine_cgroup(12289)=ok
-> quarantine_cgroup(cgroup_id=12289)
```

Colour is suppressed when stdout is not a TTY or `NO_COLOR` is set, so `| tee` and journald both
capture something readable.

---

## 10. Metrics and audit

![Metrics view: four headline counters, a rule evaluation latency histogram with p50, p95 and p99 markers, and an enforcement panel](docs/fig-metrics.svg)

*Figure 8. The two rows that matter operationally are the denial counter and the failed-command counter: together they separate a sensor that is watching from one that is enforcing.*

```console
$ curl -s localhost:9109/metrics | grep -E '^xsypher_(alerts|mitigations|lsm|commands_failed)'
xsypher_alerts_total{rule="MCP_SHELL_BREAKOUT",severity="critical"} 1
xsypher_commands_failed_total{reason="send_error"} 0
xsypher_lsm_blocks_seen{type="lsm_block"} 7
xsypher_mitigations_total{action="quarantine_cgroup"} 1
```

Every alert appends one JSONL record, chained by SHA-256 so that editing a line invalidates every later
hash. No external service, no database:

```text
hash_n = SHA256( hex(hash_{n-1}) || canonical_json(record_n without "hash", "prev_hash", "alert_id") )
hash_0 = "0" * 64
```

```console
$ PYTHONPATH=src python3 -c "from engine.mitigator import AlertLog; \
print(AlertLog.verify('/var/log/xsypher-alerts.jsonl'))"
(True, 8, None)
```

The engine re-verifies at startup and reports `audit hash chain is INVALID: line N` rather than refusing
to run, because alerting into a suspect log beats not alerting at all.

---

## 11. Install

```console
$ make check-deps          # clang, bpftool, g++
toolchain: clang / g++ / bpftool

$ make -j"$(nproc)"
[bpf] xsypher.bpf.c -> build/xsypher.bpf.o (x86)
[bpf] generating skeleton build/xsypher.skel.h
[cxx] compiling build/xsypher-collector
[ok]  built build/xsypher-collector
```

| Target | Does |
|---|---|
| `make` | BPF object, skeleton, collector |
| `make test` | unit tests, 59 cases |
| `make verify` | ABI parity, tests, end-to-end simulation |
| `make install` | binary, engine package, rules, systemd units |

`include/vmlinux.h` is generated from the running kernel's BTF and is never committed. Without BTF and
`bpftool` the script emits a reduced header for type checking only and says so.

```console
# kernel side
$ sudo ./build/xsypher-collector --socket-path /run/xsypher/stream.sock --block-imds --enforce
[xsypher] listening on /run/xsypher/stream.sock (SOCK_SEQPACKET)
[xsypher] status bpf: loaded=yes programs=8 lsm=active | ringbuf=118422 sent=118420 bad=0 | clients=1 | cmd=2 dropped=0 | resolver hits=117891 misses=531 | events=118422 drops=0 lsm_blocks=7 imds=1 ip=1 denials=2
```

Other paths: systemd (`sudo make install`, enable `xsypher-collector` and `xsypher-engine`), Docker
Compose (`cd deploy && docker compose up --build`), Kubernetes
(`kubectl apply -f deploy/kubernetes-daemonset.yaml`). Evaluate without root on any host:

```bash
pip install -r requirements.txt
PYTHONPATH=src python3 -m engine.main --simulate --metrics-port 9109
```

---

## 12. Performance

Reference host: 2 vCPU, Debian 12, g++ 12, CPython 3.11, 10,016 events, repeated runs.

| Metric | Observed |
|---|---|
| Rule evaluation, p50 | 6.2 µs |
| Rule evaluation, p95 | 8.3 to 11.7 µs |
| Rule evaluation, p99 | 14.8 to 17.3 µs |
| Budget per event | 500 µs |
| Engine, in-process replay | 136,000 to 151,000 events/s |
| Engine, end to end | 34,000 to 38,000 events/s |
| Detection to kernel map | 2.1 to 3.8 ms |
| Ring buffer | 16 MiB, about 26,000 queued records |

The first constraint at sustained load is the ring buffer, not rule evaluation: roughly 30× headroom
remains at p99. Preferred order of response is kernel-side filtering, then rule narrowing, then CPU.

Method, cost model and measurement gaps: [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

---

## 13. Failure modes

| Mode | Signal | Blast radius | Response |
|---|---|---|---|
| No BPF LSM | `lsm=unavailable`, `NOTICE: inline enforcement is inactive` | no enforcement, telemetry intact | enable `CONFIG_BPF_LSM` and `lsm=bpf`, or rely on `--active-kill` |
| Collector down | engine retries each second, `socket_reconnects_total` climbs | no telemetry, no new policy | restart the unit |
| Engine down | collector `clients=0`, `drops` climbs | no detection; installed policy persists | restart |
| Ring buffer full | `drops` in the status line | events lost, nothing retroactively blocked | narrow the filter, add CPU |
| Invalid rules | startup aborts naming the rule | no service | fix the document; this is P4 |
| Broken audit chain | `audit hash chain is INVALID: line N` | tamper or truncation; detection continues | restore, investigate the writer |
| Metrics port busy | `metrics exporter disabled` | no scraping | change `--metrics-port` |

---

## 14. Operations

| Objective | Target |
|---|---|
| Detection latency, event to alert | p99 under 25 ms |
| Enforcement latency, alert to map | p99 under 10 ms |
| Sensor availability | 99.9% per node per month |
| Telemetry completeness | under 0.1% loss, from `drops` over `events` |
| Audit completeness | 100% of alerts, chain verified at startup |

```console
$ curl -fsS localhost:9109/healthz
ok
$ curl -s localhost:9109/metrics | grep '^xsypher_events_total'
xsypher_events_total{type="connect"} 1784
xsypher_events_total{type="execve"} 6102
xsypher_events_total{type="openat"} 2108
```

Two alerts matter more than the rest and they are deliberately different shapes: a silent sensor
(`rate(xsypher_events_total[10m]) == 0`) and a broken policy channel
(`increase(xsypher_commands_failed_total[5m]) > 0`). Together they separate "nothing is happening" from
"we are not watching".

Alert rules, audit forensics, capacity planning, upgrade, rollback, uninstall and the troubleshooting
table: [docs/OPERATIONS.md](docs/OPERATIONS.md).

---

## 15. Sensor security

The collector is the only privileged component and the only code in the data path that runs as root. It
parses fixed-size kernel records and does not interpret policy: it validates magic, version and command
type on 32 bytes, then performs one map update. There is no policy language in the privileged process.

| Control | Where |
|---|---|
| Least privilege | `CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_IPC_LOCK` |
| No new privileges | `NoNewPrivileges=true` on both units |
| Syscall filter | `SystemCallFilter=@system-service bpf perf_event_open` |
| Filesystem | `ProtectSystem=strict`, `ProtectHome=true`, `ReadWritePaths=/run/xsypher` |
| Engine container | `readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]` |
| Memory | `MemoryDenyWriteExecute=true` |
| Transport | `AF_UNIX` only, never a TCP port, directory mode `0750` |

Treat write access to the socket as equivalent to enforcement authority, and never mount
`/run/xsypher` into a workload. Report vulnerabilities per [SECURITY.md](SECURITY.md).

---

## 16. Development

```console
$ make test
59 passed, 31 subtests passed in 0.55s

$ PYTHONPATH=src python3 tests/simulate_mcp_attack.py
  [1/3] streamed 10000 benign events in 0.28s (36,331 events/s)
  [2/3] injecting attack chains
        ok  chain A: MCP prompt injection -> interactive shell (2.1 ms)
        ok  chain B: MCP recon tool + reverse shell port (2.2 ms)
        ok  chain C: Cloud IMDS credential theft (2.2 ms)
        ok  chain D: Host credential harvest (2.2 ms)
        ok  chain E: Fileless payload staging via memfd (2.2 ms)
  [3/3] verifying enforcement packets
        enforcement pkts : 8 (expected 8)
        audit chain      : verified (8 record(s))
RESULT: PASSED
```

| Suite | Count | Covers |
|---|---|---|
| `tests/test_wire_protocol.py` | 23 | sizes and offsets, C to Python parity by compiling the header, codec round trips, malformed frames, a real socket round trip |
| `tests/test_lineage_and_rules.py` | 36 | ancestry and TTL, eviction, every rule firing and staying quiet, cooldowns, validation, audit chain write and tamper, metrics rendering |
| `tests/simulate_mcp_attack.py` | end to end | 10,000 benign events plus five chains over a real socket, byte comparison of all eight expected commands |

Figures in `docs/` are hand-written SVG with no external assets and no animation. Two checks guard them,
and both run in CI:

```console
$ make check-docs
python3 scripts/audit_svg.py docs/*.svg
ok   docs/architecture.svg (1120x440, 15 boxes)
ok   docs/fig-coverage.svg (1120x560, 70 boxes)
ok   docs/fig-deployment.svg (1120x560, 12 boxes)
ok   docs/fig-frame.svg (1120x520, 16 boxes)
ok   docs/fig-killchain.svg (1120x620, 9 boxes)
ok   docs/fig-metrics.svg (1120x430, 14 boxes)
ok   docs/fig-quarantine.svg (1120x580, 10 boxes)
ok   docs/fig-terminal.svg (1120x660, 4 boxes)
python3 scripts/check_docs.py
ok   11 documents: links, anchors, images, fences, style, figure references
```

`audit_svg.py` estimates the set width of every `<text>` element from font metrics and fails a figure whose
label would leave its box, cross the viewBox, or sit under a rotated neighbour. `check_docs.py` fails a
broken link, a dead anchor, a missing image, an unbalanced code fence, an em dash, an emoji, or a figure
that no document embeds. Neither needs a renderer, so both run on a plain runner. For eyeballing a change,
`python3 scripts/preview_svg.py docs/fig-frame.svg /tmp/frame.png` rasterises the element subset the
figures use.

```
include/xsypher_abi.h     normative binary ABI, static assertions
src/bpf/xsypher.bpf.c     five tracepoints, three LSM hooks, six maps
src/collector/            bpf_loader, cgroup_resolver, uds_server, main reactor
src/engine/               abi, lineage, rule_engine, mitigator, metrics, tui, main
config/rules.yaml         detection content
deploy/                   Dockerfile, compose, DaemonSet, systemd units
scripts/                  gen_vmlinux.sh, verify_and_benchmark.sh, audit_svg.py, check_docs.py
docs/                     nine reference documents and eight figures
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) before a pull request. Two rules dominate review: a rule change
needs a positive and a negative test, and an ABI change needs a version bump, a mirrored `abi.py` change
and updated layout assertions in the same commit.

---

## 17. Limits and non-goals

- `args` captures four `argv` pointers of 64 bytes. Enough for a command line, not for a payload.
- Container identity depends on cgroup layouts. Unknown runtimes resolve to `host`, which disables
  `container_only` rules.
- `file_open` sees the dentry basename, so its credential-path branch cannot match absolute prefixes.
  Effective in-kernel file protection is write denial inside a quarantined domain.
- `openat2` is a separate tracepoint and is not hooked.
- IMDS denial covers IPv4 in the hook; `fd00:ec2::254` is detected after the fact.
- `--active-kill` is a user-space `SIGKILL` and races a fork loop. The kernel quarantine is authoritative.
- Single-node correlation only. No cross-host lineage.
- Not a sandbox, an image scanner, an admission controller or an immutable boot chain. The sensor is
  removable by a privileged attacker, and it does not attempt to prevent that.

---

## 18. Compatibility

| Axis | Support |
|---|---|
| Kernel | 5.10 to 6.x, one CO-RE object |
| Architectures | x86_64, aarch64 |
| Distributions | any with BTF: Ubuntu 20.04+, Debian 11+, RHEL 9+, Amazon Linux 2023, Bottlerocket, Talos |
| Container runtimes | Docker, containerd, CRI-O; anything else reports `host` |
| Python | 3.10, 3.11, 3.12 (reference), 3.13 |
| libbpf | 1.0+, 1.1+ for the epoll-driven ring buffer |
| Inline enforcement | `CONFIG_BPF_LSM=y` plus `lsm=bpf` |

---

## 19. License

Apache-2.0 for user space; see [LICENSE](LICENSE). The eBPF program declares `SEC("license") = "GPL"`
because BPF-LSM program types and the helpers it uses require a GPL-compatible licence; GPL-2.0 terms
apply to that compilation unit and the object built from it.
