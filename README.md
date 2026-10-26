# xSypher-Stream

Kernel-level visibility and in-kernel policy enforcement for Linux hosts running AI agents and
Model Context Protocol (MCP) servers.

xSypher-Stream records process execution, outbound connections, file access and memory-backed file
creation with eBPF, reconstructs the process ancestry behind each event, evaluates a declarative rule
set, and applies quarantine policy through BPF LSM hooks. Enforcement happens in the syscall path: it
does not require the workload to cooperate and does not require a container restart.

[![ci](https://github.com/anwariqbaldawar/Zero-Trust-Kernel-Log-Streamer/actions/workflows/ci.yml/badge.svg)](https://github.com/anwariqbaldawar/Zero-Trust-Kernel-Log-Streamer/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)
![abi](https://img.shields.io/badge/wire%20abi-v2-lightgrey?style=flat-square)
![kernel](https://img.shields.io/badge/kernel-5.10%2B-lightgrey?style=flat-square)

| | |
|---|---|
| Version | 2.0.0, wire ABI v2 |
| Platforms | Linux 5.10 and later with BTF; x86_64 and aarch64 |
| Enforcement | Requires `CONFIG_BPF_LSM=y` and `lsm=bpf`; telemetry works without them |
| Licenses | Apache-2.0; the eBPF object is GPL-2.0 (kernel requirement) |

**Documentation:** [Architecture and wire protocol](docs/ARCHITECTURE.md) ·
[Configuration reference](docs/CONFIGURATION.md) · [Operations runbook](docs/OPERATIONS.md) ·
[Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

## Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Detections](#detections)
- [Configuration](#configuration)
- [Operations](#operations)
- [Security](#security)
- [Development](#development)
- [License](#license)

---

## Overview

An MCP server exposes tools to a language model. When a prompt injection succeeds, the model calls
those tools on the attacker's behalf: a shell is spawned, a metadata endpoint is queried, a credential
file is read. The activity uses legitimate binaries, legitimate credentials and legitimate network
paths, so image scanning, admission control and static network policy do not see it, and agents that
poll `/proc` are too slow for a chain that completes in milliseconds.

xSypher-Stream observes at the syscall boundary and enforces at the LSM boundary.

**Collected events**

| Event | Kernel hook | Filtering |
|---|---|---|
| Process execution | `tp/syscalls/sys_enter_execve` | none; first four `argv` entries captured |
| Outbound connection | `tp/syscalls/sys_enter_connect` | `AF_INET` and `AF_INET6` |
| File open | `tp/syscalls/sys_enter_openat` | filtered in kernel: credential paths, any `.env` file, and write-like opens under `/tmp`, `/dev/shm`, `/usr/bin`, `/usr/local/bin` |
| Memory-backed file | `tp/syscalls/sys_enter_memfd_create` | none |
| Process exit | `tp/sched/sched_process_exit` | also removes the tgid from the quarantine map |

**Enforcement, when the kernel supports BPF LSM**

| Hook | Denies |
|---|---|
| `lsm/bprm_check_security` | executing a program inside a quarantined PID or cgroup |
| `lsm/socket_connect` | connecting to blocked IPv4 addresses; metadata service access from a quarantined cgroup |
| `lsm/file_open` | reading credential files, and any write, inside a quarantined domain |

**What it is not.** Not a sandbox, an admission controller, an image scanner or an immutable boot
chain. It observes the behaviour of running processes; an attacker with root on the host can unload
the sensor. Deploy it alongside, not instead of, immutable infrastructure and centralised log
shipping.

---

## Architecture

![Data flow: eBPF programs to ring buffer to C++20 collector to Python engine, with policy commands returning to the BPF maps](docs/architecture.svg)

| Component | Language | Source | Responsibility |
|---|---|---|---|
| Kernel programs | restricted C, BPF CO-RE | `src/bpf/xsypher.bpf.c` | collect events, enforce LSM policy |
| Collector | C++20, libbpf | `src/collector/` | drain the ring buffer, enrich with container identity, transport |
| Engine | Python 3.12, asyncio | `src/engine/` | decode, lineage, rules, mitigation, observability |

An event travels five hops: a tracepoint fills a 640-byte record on a 16 MiB ring buffer; the collector
polls the buffer, resolves the cgroup and pid to a container identifier, and wraps the record in a
720-byte frame with a monotonic sequence number; the frame crosses an `AF_UNIX`/`SOCK_SEQPACKET` socket;
the engine decodes it, updates the lineage graph and evaluates the rules; on a match, a 32-byte policy
command returns over the same socket and the collector applies it with `bpf_map_update_elem`.

Four properties hold by design:

- The kernel never blocks on user space. With no reader, events are dropped and counted in
  `metrics_map`; the syscall path is unaffected.
- Policy is applied asynchronously. Losing the engine does not clear policy already installed in the
  maps.
- Rule documents are validated at load time. An invalid file aborts startup rather than running with
  fewer detections.
- Quarantine is cgroup-scoped where possible. PIDs are recycled quickly and a fork outruns user-space
  enumeration; the cgroup covers current and future tasks.

Structure, maps, wire protocol and design rationale: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Requirements

| Item | Requirement |
|---|---|
| Kernel | 5.10 or later; BTF at `/sys/kernel/btf/vmlinux` |
| Kernel config, telemetry | `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_DEBUG_INFO_BTF` |
| Kernel config, enforcement | `CONFIG_BPF_LSM=y` and `lsm=bpf` on the kernel command line |
| Build | `clang` >= 12, `bpftool`, `libbpf` >= 1.0, `libelf`, `zlib`, C++20 compiler, `make` or CMake |
| Collector runtime | root, or `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_RESOURCE`, with `RLIMIT_MEMLOCK=infinity` |
| Engine runtime | Python >= 3.10 (3.12 recommended), PyYAML; no other third-party packages |

```bash
# Debian / Ubuntu
sudo apt-get install -y clang llvm bpftool libbpf-dev libelf-dev zlib1g-dev \
                        build-essential cmake pkg-config python3 python3-yaml
```

Confirm enforcement support before depending on it:

```console
$ cat /sys/kernel/security/lsm
capability,landlock,lockdown,yama,integrity,apparmor,bpf
$ grep -o 'lsm=[^ ]*' /proc/cmdline
lsm=lockdown,yama,integrity,apparmor,bpf
```

Without `bpf` in that list the collector still runs and streams telemetry; it logs
`NOTICE: inline enforcement is inactive` and reports `lsm=unavailable` in its status line.

---

## Quick start

Build:

```bash
git clone https://github.com/anwariqbaldawar/Zero-Trust-Kernel-Log-Streamer.git
cd Zero-Trust-Kernel-Log-Streamer

make check-deps          # clang, g++, bpftool
make -j"$(nproc)"        # build/xsypher.bpf.o, build/xsypher.skel.h, build/xsypher-collector
```

`include/vmlinux.h` is generated from the running kernel's BTF by `scripts/gen_vmlinux.sh` and is not
committed. If the host has no BTF and no `bpftool`, the script emits a reduced header suitable for type
checking only and prints a warning; regenerate with `FORCE=1 ./scripts/gen_vmlinux.sh` before loading
on a real host.

Run, with two terminals:

```bash
# kernel side, needs CAP_BPF/CAP_PERFMON
sudo ./build/xsypher-collector --socket-path /run/xsypher/stream.sock --block-imds --enforce

# policy side
sudo -E PYTHONPATH=src python3 -m engine.main \
    --socket-path /run/xsypher/stream.sock \
    --rules config/rules.yaml \
    --alert-log /var/log/xsypher-alerts.jsonl \
    --enforce-kernel
```

Evaluate without root, kernel changes or eBPF, using the synthetic generator. This exercises the whole
Python path: decoder, lineage, rules, mitigation, audit log, metrics and terminal output.

```bash
pip install -r requirements.txt
PYTHONPATH=src python3 -m engine.main --simulate --metrics-port 9109
curl -s localhost:9109/metrics | grep '^xsypher_alerts_total'
```

Other installation paths: CMake (`cmake -S . -B build && cmake --build build -j"$(nproc)"`), systemd
(`sudo make install`, then enable `xsypher-collector` and `xsypher-engine`), Docker Compose
(`cd deploy && docker compose up --build`), Kubernetes
(`kubectl apply -f deploy/kubernetes-daemonset.yaml`). Container and unit files are in
[`deploy/`](deploy).

---

## Detections

Six rules ship in [`config/rules.yaml`](config/rules.yaml). All are data; none requires a rebuild.

| Rule ID | Severity | Trigger | Actions | ATT&CK |
|---|---|---|---|---|
| `MCP_SHELL_BREAKOUT` | critical | an AI/MCP runtime ancestor executes a shell or terminal multiplexer | `quarantine_cgroup`, `kill` | T1059, T1059.004 |
| `MCP_RECON_OR_EXFIL_TOOL` | high | an AI/MCP runtime ancestor executes `curl`, `wget`, `nc`, `socat`, `nmap`, `ssh`, `scp`, `base64`, `chisel`, `ngrok` and similar | `quarantine_pid`, `kill` | T1046, T1041, T1105 |
| `CLOUD_IMDS_CREDENTIAL_THEFT` | critical | a container connects to `169.254.169.254` or `fd00:ec2::254` | `quarantine_cgroup`, `block_ipv4`, `kill` | T1552.005 |
| `SENSITIVE_CREDENTIAL_HARVEST` | critical | a non-authorised process opens `/etc/shadow`, `/etc/sudoers`, `/root/.ssh`, the Kubernetes service-account token, `.env`, `id_rsa`, `credentials.json` or `/proc/kcore` | `quarantine_pid`, `kill` | T1003.008, T1552.001 |
| `FILELESS_MEMFD_EXECUTION` | critical | `memfd_create`, or execution from `/memfd:`, `/proc/self/fd/`, `/dev/shm/`, `/run/shm/` | `quarantine_cgroup`, `kill` | T1620, T1027.009 |
| `SUSPICIOUS_OUTBOUND_C2_PORT` | high | a container or web/MCP worker connects to `4444`, `1337`, `31337`, `5555`, `6667`, `9001` | `quarantine_pid`, `block_ipv4`, `kill` | T1571, T1071 |

`SENSITIVE_CREDENTIAL_HARVEST` excludes system binaries that legitimately read the listed paths
(`sshd`, `login`, `sudo`, `su`, `passwd`, `systemd`, `unix_chkpwd`, `polkitd`, `gdm`, `lightdm`, `cron`,
`kubelet`). Extend that list for platform-specific consumers.

---

## Configuration

A rule is a mapping with an id, severity, event types, conditions and actions:

```yaml
  - id: MCP_SHELL_BREAKOUT
    title: "MCP/AI agent spawned an interactive shell"
    severity: critical
    event_types: [execve]
    conditions:
      exe_in: [sh, bash, zsh, dash, ksh, tmux, screen, dtach]
      ancestor_has_ai_runtime: true
      ancestor_min_depth: 1
    actions: [quarantine_cgroup, kill]
```

Conditions in one mapping are ANDed; list values are ORed; `any_of:` groups are ORed with each other.
Validate a document without starting the service:

```bash
PYTHONPATH=src python3 -c "from engine.rule_engine import RuleEngine; \
RuleEngine.from_file('config/rules.yaml')"
```

Full option tables for both binaries, environment variables, exit codes, the complete condition
reference and worked examples: [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

---

## Operations

| Check | Command |
|---|---|
| Engine liveness | `curl -fsS localhost:9109/healthz` |
| Enforcement active | `curl -s localhost:9109/metrics \| grep xsypher_lsm_blocks_seen` |
| Telemetry flowing | `curl -s localhost:9109/metrics \| grep '^xsypher_events_total'` |
| Audit chain intact | `PYTHONPATH=src python3 -c "from engine.mitigator import AlertLog; print(AlertLog.verify('/var/log/xsypher-alerts.jsonl'))"` |

Every alert is appended to a JSONL log as one record, chained by SHA-256 so that modification is
detectable without an external service:

```text
hash_n = SHA256( hex(hash_{n-1}) || canonical_json(record_n excluding "hash" and "alert_id") )
```

Measured on a 2 vCPU sandbox over repeated runs: rule evaluation p50 6.2 µs, p95 8.3 to 11.7 µs, p99
14.8 to 17.3 µs against a 500 µs budget; 136,000 to 151,000 events/s in-process and 34,000 to 38,000
events/s end to end; 2.1 to 3.8 ms from detection to kernel map update. Percentiles move by a few
microseconds between runs; treat them as an order of magnitude, not a contract.

Health-check detail, metric reference, alerting rules, capacity sizing, upgrade and rollback, and the
troubleshooting table: [docs/OPERATIONS.md](docs/OPERATIONS.md).

---

## Security

The collector is the only privileged component. It parses nothing but fixed-size kernel records and
does not interpret policy: it applies 32-byte commands after validating magic, version and command
type. The engine holds no capabilities; its only influence on the kernel is that command channel.

Shipped defaults: the collector listens only on an `AF_UNIX` socket, never on a TCP port; the systemd
unit creates `/run/xsypher` with mode `0750` and runs the collector with `CapabilityBoundingSet=CAP_BPF
CAP_PERFMON CAP_SYS_RESOURCE CAP_IPC_LOCK`, `NoNewPrivileges` and a `@system-service` syscall filter;
the engine unit adds `ProtectSystem=strict`, `ProtectHome`, `MemoryDenyWriteExecute`,
`RestrictAddressFamilies` and `RestrictNamespaces`; the Kubernetes manifest drops all capabilities from
the engine container and mounts its root filesystem read-only.

Fail-safe behaviour: without BPF LSM the system degrades to telemetry and says so; killing the engine
leaves installed policy active in the kernel; a full ring buffer drops events and increments a counter;
an invalid rule document aborts startup; graceful shutdown releases every quarantine the engine applied.

Limitations worth planning around: `args` captures four `argv` entries of 64 bytes each; container
identity depends on Docker/containerd/CRI-O cgroup layouts; `--active-kill` is a user-space `SIGKILL`
and races against a fast fork loop, so the kernel quarantine is the authoritative control; IMDS denial
covers IPv4 in the LSM hook, with the IPv6 equivalent handled by rule evaluation.

Report vulnerabilities privately per [SECURITY.md](SECURITY.md).

---

## Development

```bash
pip install -r requirements.txt pytest
make test                          # unit tests
./scripts/verify_and_benchmark.sh  # ABI parity, build, tests, end-to-end simulation
```

| Suite | Count | Covers |
|---|---|---|
| `tests/test_wire_protocol.py` | 23 | structure sizes and offsets, C-to-Python parity by compiling the header, codec round trips, malformed frames, a real `SOCK_SEQPACKET` round trip |
| `tests/test_lineage_and_rules.py` | 36 | ancestry and TTL semantics, eviction, all six rules firing and staying quiet on benign traffic, cooldowns, rule validation, audit chain write/verify/tamper/resume, metrics rendering and HTTP fetch |
| `tests/simulate_mcp_attack.py` | end to end | 10,000 benign events plus five attack chains over a real socket, byte comparison of every expected policy command, audit verification, benchmarks |

```console
$ python3 -m pytest tests -q
59 passed, 31 subtests passed in 0.8s

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

Repository layout:

```
include/xsypher_abi.h     shared binary ABI (normative)
src/bpf/                  tracepoints, LSM hooks, maps
src/collector/            libbpf lifecycle, cgroup resolver, UDS server, main loop
src/engine/               abi, lineage, rule_engine, mitigator, metrics, tui, main
config/rules.yaml         detection content
deploy/                   Dockerfile, compose, Kubernetes DaemonSet, systemd units
scripts/                  gen_vmlinux.sh, verify_and_benchmark.sh
tests/                    unit tests and the end-to-end attack simulation
docs/                     architecture, configuration, operations, diagrams
```

CI runs on `ubuntu-24.04`: engine, ABI parity and simulation; a full clang, bpftool and CMake build
with warnings treated as errors; and a check that `config/rules.yaml` and the Kubernetes ConfigMap copy
have not drifted. Where `clang`, `bpftool` or `libbpf-dev` are unavailable, the verification script
reports those two steps as `SKIP` rather than failing, and type-checks the BPF program with the host C
compiler instead.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Two rules dominate review: a
rule change needs a positive and a negative test, and an ABI change needs a version bump, a mirrored
change in `src/engine/abi.py`, and updated layout assertions in the same commit.

---

## License

Apache-2.0 for user space; see [LICENSE](LICENSE). The eBPF program in `src/bpf/xsypher.bpf.c` declares
`SEC("license") = "GPL"` because the kernel requires a GPL-compatible licence for BPF-LSM program types
and GPL-only helpers; GPL-2.0 terms apply to that compilation unit and the object built from it.
