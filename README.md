<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="assets/logo-light.svg">
    <img src="assets/logo-light.svg" alt="xSypher-Stream: a hexagon with three telemetry paths stopped by one enforcement bar" width="560">
  </picture>
</p>

<p align="center">
  <strong>Kernel-verified runtime defence for AI agent hosts.</strong><br>
  eBPF CO-RE telemetry, a policy decision in user space, an inline LSM denial in the kernel.
</p>

<p align="center">
  <a href="https://github.com/anwariqbaldawar/Zero-Trust-Kernel-Log-Streamer/actions/workflows/ci.yml"><img src="https://github.com/anwariqbaldawar/Zero-Trust-Kernel-Log-Streamer/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <img src="https://img.shields.io/badge/version-2.0.0-0369a1" alt="Version 2.0.0">
  <img src="https://img.shields.io/badge/wire%20ABI-v2-0369a1" alt="Wire ABI v2">
  <img src="https://img.shields.io/badge/kernel-5.10%2B-334155" alt="Kernel 5.10 or newer">
  <img src="https://img.shields.io/badge/python-3.10%2B-334155" alt="Python 3.10 or newer">
  <img src="https://img.shields.io/badge/license-Apache--2.0%20%2F%20GPL--2.0-475569" alt="Licensed Apache-2.0, kernel programs GPL-2.0">
</p>

<p align="center">
  <a href="#features">Features</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="docs/">Docs</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

<p align="center">
  <img src="assets/demo.gif" alt="Terminal recording: the engine runs against the synthetic kernel, raises a critical MCP shell breakout alert with its lineage, applies the quarantine command, then the end-to-end harness reports five attack chains contained and eight policy commands delivered" width="838">
</p>

<p align="center"><sub>Recorded from two real runs on the reference host: the operator view, then <code>tests/simulate_mcp_attack.py</code>. Rebuild it with <code>make demo</code>.</sub></p>

# xSypher-Stream

An MCP server publishes tools to a language model. The model calls those tools with arguments it chose.
Every control around that loop assumes the arguments are benign: `/bin/sh` is in the image, link-local is
reachable, the secrets are mounted on the process that reads them. A prompt injection turns that into a
working exploit in under ten milliseconds, using nothing but syscalls the workload is already allowed to
make.

xSypher-Stream watches those syscalls from the kernel, decides with the ancestry of the process in hand,
and denies at the LSM hook so the rest of the chain cannot run. Built for platform and security engineers
who have to run agent frameworks in production containers and cannot answer "what stops the shell?" with
"nothing yet".

- **Decision in user space, denial in the kernel.** The rule engine is readable Python; the refusal is a
  `-EPERM` returned from a BPF LSM program that no userspace process can be tricked into skipping.
- **Lineage, not signatures.** `mcp-server -> python3 -> sh -> curl` is the signal, so a legitimate binary
  doing an illegitimate thing is still caught.
- **Auditable after the fact.** Every alert lands in a SHA-256 chained JSONL log that verifies offline.

---

## Why this exists

| The gap | What the alternatives see |
|---|---|
| An injected tool call spawns `sh -c curl http://169.254.169.254` | Image scanners finished before the pod started; the binary and the command are both "expected" |
| The chain completes in single-digit milliseconds | A `/proc` poll on a 1 s interval is blind for the whole chain |
| Everything is authorised: same UID, same namespace, allowed egress | Policy engines that key on identity have nothing to key on |
| Credentials leave over TLS to an ordinary address | L7 inspection sees a valid `POST` to a legitimate host |

The distinguishing signal is not the operation. It is **who** issued it and **what it is trying to reach**.
xSypher-Stream keys on exactly that, at the syscall boundary, where the answer is still cheap.

## Features

| Area | What ships |
|---|---|
| **Kernel telemetry** | eBPF CO-RE programs on 5 tracepoints (`execve`, `connect`, `openat`, `memfd_create`, `sched_process_exit`) streaming fixed 640-byte records through a 16 MiB ring buffer |
| **Inline enforcement** | 3 BPF LSM hooks (`bprm_check_security`, `socket_connect`, `file_open`) returning `-EPERM` / `-EACCES` for a quarantined process, cgroup or address |
| **Lineage graph** | Ancestry resolution up to 8 hops with a 5 s post-exit TTL, bounded at 200,000 tracked processes, so `node -> npx -> sh -> curl` is one query |
| **Declarative rules** | 6 YAML rules as data, not code: 4 critical, 2 high, each with explicit actions and a 5 s per-subject cooldown |
| **Mitigation** | `quarantine_pid`, `quarantine_cgroup`, `block_ipv4`, `block_imds`, optional user-space `SIGKILL`, all translated into 32-byte commands validated by the collector before they touch a map |
| **Forensics** | SHA-256 chained JSONL audit log, verified on startup and on demand, tamper-evident without a database |
| **Observability** | Prometheus text exporter on `:9109` (events, alerts by rule, mitigations by action, latency summary, ring-buffer drops, failed commands) |
| **Operator surface** | ANSI terminal monitor that degrades to plain lines for log shippers, `NO_COLOR` aware |
| **Safety** | Audit-only mode where detection, metrics and the audit chain behave identically but nothing is denied |

## Quick start

Three commands, no root, no kernel toolchain:

```bash
git clone https://github.com/anwariqbaldawar/Zero-Trust-Kernel-Log-Streamer.git
cd Zero-Trust-Kernel-Log-Streamer && pip install -r requirements.txt
PYTHONPATH=src python3 -m engine.main --simulate
```

Real output from that sequence on a clean clone (`--simulate` drives the engine with a synthetic kernel, so
you can read the alert format before you touch a real host):

```console
$ PYTHONPATH=src python3 -m engine.main --simulate --simulate-count 160

  xSypher-Stream  zero-trust kernel telemetry & inline LSM enforcement
  mode=AUDIT_ONLY rules=6 kill=off collector=connected socket=(simulation)
  metrics=http://0.0.0.0:9109/metrics   (Ctrl-C to stop)
  --------------------------------------------------------------------------------------------------------------
  [..] simulation mode: no kernel, no collector socket
  [ok] loaded 6 rules from /tmp/qs/config/rules.yaml; alert log /tmp/xsypher-alerts.jsonl (chain seq=8763)
  [..] audit hash chain verified (8763 record(s))
  [ok] prometheus exporter listening on 0.0.0.0:9109/metrics
12:41:49.080 EXEC  pid=1001    tgid=1001    cont=bb5d75b895f6 uvicorn          /usr/local/bin/uvicorn
12:41:49.080 EXEC  pid=1002    tgid=1002    cont=bb5d75b895f6 git              /usr/bin/git
12:41:49.080 EXEC  pid=1003    tgid=1003    cont=bb5d75b895f6 ls               /usr/bin/ls
```

Two lines there are worth reading: the alert log fell back to `/tmp` because the default under `/var/log`
is not writable here, and the chain sequence is 8763 because this host had already written records. Both are
the engine reporting its own state rather than hiding it.

Add `--enforce-kernel` to see the quarantine commands the engine would push into the kernel maps.

## Installation

### Requirements

| Component | Needs |
|---|---|
| Engine only (simulation, rule authoring, replay) | Python 3.10+ and `PyYAML`. That is the entire dependency list |
| Kernel telemetry | Linux 5.10+, BTF at `/sys/kernel/btf/vmlinux`, `clang` 12+, `bpftool`, `libbpf` 1.0+, `libelf`, `zlib` |
| Inline enforcement | The above plus `CONFIG_BPF_LSM=y` and `lsm=bpf` in the kernel command line, and `CAP_BPF` + `CAP_PERFMON` for the collector |

Telemetry works without BPF LSM. Without it the collector logs the degradation and stays read-only unless
you pass `--no-lsm-fallback`, which turns the degradation into a startup failure.

### From source

```bash
git clone https://github.com/anwariqbaldawar/Zero-Trust-Kernel-Log-Streamer.git
cd Zero-Trust-Kernel-Log-Streamer
pip install -r requirements.txt
make vmlinux          # generate include/vmlinux.h from this host's BTF
make all              # BPF object, libbpf skeleton, C++20 collector
PYTHONPATH=src python3 -m engine.main --rules config/rules.yaml
```

`make` targets: `all`, `vmlinux`, `bpf`, `collector`, `test`, `simulate`, `verify`, `run`, `engine`,
`check-docs`, `demo`, `brand`, `clean`, `install`. Run `make help` for the list.

> [!NOTE]
> The kernel-side build needs `bpftool`, and CI skips it when the runner image cannot supply a usable
> binary. The engine, ABI parity, simulation, rule-parity and docs jobs always run. `make verify` prints
> `SKIP` per skipped step instead of pretending it passed.

### Containers and Kubernetes

`deploy/` carries a multi-stage image, a two-container compose file, a DaemonSet and two systemd units.

```bash
docker compose -f deploy/docker-compose.yml up --build          # collector + engine
kubectl apply -f deploy/kubernetes-daemonset.yaml               # hostPID, privileged collector
```

The collector needs the host BTF and the host PID namespace; the engine needs neither and runs
unprivileged. Both paths are exercised by the project's own deployments rather than by CI, which has no
privileged runner. See [docs/OPERATIONS.md](docs/OPERATIONS.md) before rolling out.

## Usage

### Run the enforced pipeline against real traffic

```bash
sudo build/xsypher-collector --socket-path /run/xsypher/stream.sock --enforce --block-imds
PYTHONPATH=src python3 -m engine.main --socket-path /run/xsypher/stream.sock --enforce-kernel
```

The collector takes `--socket-path`, `--enforce`, `--block-imds`, `--no-lsm-fallback`, `--no-status`,
`--verbose`. The engine takes the flags in [Configuration](#configuration).

### Watch an attack chain end to end

```console
$ PYTHONPATH=src python3 tests/simulate_mcp_attack.py
==============================================================================
 xSypher-Stream :: end-to-end MCP attack simulation
==============================================================================
  benign evts : 10000
  chains      : 5 attack scenarios
  engine      : connected

  [1/3] streamed 10000 benign events in 0.29s (34,873 events/s)

  [2/3] injecting attack chains
        ok  chain A: MCP prompt injection -> interactive shell (2.1 ms)
        ok  chain B: MCP recon tool + reverse shell port (2.2 ms)
        ok  chain C: Cloud IMDS credential theft (2.2 ms)
        ok  chain D: Host credential harvest (2.2 ms)
        ok  chain E: Fileless payload staging via memfd (2.1 ms)

  [3/3] verifying enforcement packets
        enforcement pkts : 8 (expected 8)
        audit chain      : verified (8 record(s))
RESULT: PASSED - all attack chains were detected and contained, every expected wire_policy_cmd_t was delivered.
```

Every command in that run goes over a real `AF_UNIX` `SOCK_SEQPACKET` socket and is compared byte for byte
against the structure the collector expects.

### Scrape metrics

```console
$ curl -sS http://127.0.0.1:9109/metrics | grep -E '^(xsypher_lsm_blocks_seen|xsypher_mitigations_total|xsypher_commands_failed_total)'
xsypher_mitigations_total{action="block_ipv4"} 1
xsypher_mitigations_total{action="quarantine_cgroup"} 2609
xsypher_mitigations_total{action="quarantine_pid"} 2609
xsypher_commands_failed_total{reason="disconnected"} 5219
```

`xsypher_commands_failed_total{reason="disconnected"}` rising means the engine is enforcing a policy the
collector never received. Pair it with `xsypher_lsm_blocks_seen` in an alert: the first counter proves the
sensor is alive, the second proves it is actually denying.

### Verify the audit chain

```bash
python3 - <<'PY'
import sys; sys.path.insert(0, "src")
from engine.mitigator import AlertLog
print(AlertLog.verify("/var/log/xsypher-alerts.jsonl"))
PY
```

### Write a rule

```yaml
- id: MCP_SHELL_BREAKOUT
  title: MCP/AI agent spawned an interactive shell
  severity: critical
  event_types: [execve]
  conditions:
    exe_in: [sh, bash, zsh, dash, ksh]
    ancestor_has_ai_runtime: true
    container_only: true
  actions: [quarantine_cgroup, kill]
  cooldown_seconds: 5
```

Conditions inside a rule are ANDed; list values are ORed; `any_of:` holds alternative condition groups.
Full schema and every condition key: [docs/CONFIGURATION.md](docs/CONFIGURATION.md) and
[docs/DETECTIONS.md](docs/DETECTIONS.md).

## Configuration

### Engine

| Flag | Default | Purpose |
|---|---|---|
| `--socket-path` | `/run/xsypher/stream.sock` | Collector socket |
| `--rules` | `config/rules.yaml` | Rule document, YAML or JSON |
| `--alert-log` | `/var/log/xsypher-alerts.jsonl` | Hash-chained audit log; falls back to `/tmp` when unwritable |
| `--metrics-host` / `--metrics-port` | `0.0.0.0` / `9109` | Prometheus exporter; `0` picks an ephemeral port |
| `--enforce-kernel` | off | Push quarantine commands into the BPF LSM maps |
| `--active-kill` | off | Also `SIGKILL` from user space |
| `--simulate` / `--simulate-count` / `--simulate-seed` | off / `0` / `1337` | Synthetic kernel |
| `--lineage-ttl` / `--max-tracked` | `5.0` / `200000` | Ancestry retention and graph bound |
| `--fsync-alerts` | off | `fsync` after every audit record |
| `--no-color` / `--quiet` / `--verbose` | off | Terminal behaviour |

Environment: `XSYPHER_SOCKET`, `XSYPHER_RULES`, `XSYPHER_ALERT_LOG` (flags win), `NO_COLOR`.

<details>
<summary>Rule document settings and the shipped rules</summary>

```yaml
settings:
  max_ancestry_depth: 8
  cooldown_seconds: 5.0
  verify_chain_on_start: true
```

| Rule | Severity | Actions |
|---|---|---|
| `MCP_SHELL_BREAKOUT` | critical | `quarantine_cgroup`, `kill` |
| `MCP_RECON_OR_EXFIL_TOOL` | high | `quarantine_pid`, `kill` |
| `CLOUD_IMDS_CREDENTIAL_THEFT` | critical | `quarantine_cgroup`, `block_ipv4`, `kill` |
| `SENSITIVE_CREDENTIAL_HARVEST` | critical | `quarantine_pid`, `kill` |
| `FILELESS_MEMFD_EXECUTION` | critical | `quarantine_cgroup`, `kill` |
| `SUSPICIOUS_OUTBOUND_C2_PORT` | high | `quarantine_pid`, `block_ipv4`, `kill` |

</details>

## How it works

```mermaid
flowchart LR
    subgraph K["Kernel space"]
        direction TB
        TP["5 tracepoints<br/>execve · connect · openat<br/>memfd_create · sched_process_exit"]
        RB[("ring buffer<br/>16 MiB")]
        LSM["3 BPF LSM hooks<br/>bprm_check_security<br/>socket_connect · file_open"]
        MAPS[("policy maps<br/>quarantined_pids<br/>quarantined_cgroups<br/>blocked_ipv4 · config")]
        TP -->|"640 B records"| RB
        LSM -->|"EVENT_LSM_BLOCK"| RB
        MAPS -->|"deny decision"| LSM
    end
    subgraph U["User space"]
        COL["xsypher-collector<br/>C++20 libbpf, epoll<br/>CAP_BPF + CAP_PERFMON"]
        ENG["xSypher-Stream engine<br/>Python asyncio<br/>no capabilities"]
        OUT["terminal monitor<br/>/metrics :9109<br/>alerts.jsonl"]
    end
    RB -->|"720 B frame"| COL
    COL -->|"AF_UNIX SOCK_SEQPACKET"| ENG
    ENG -->|"32 B policy command"| COL
    COL -->|"bpf_map_update_elem"| MAPS
    ENG --> OUT
```

The wire is three fixed structures, and `include/xsypher_abi.h` is their only definition:

| Structure | Size | Direction |
|---|---|---|
| `kernel_event_t` | 640 B | kernel ring buffer record |
| `wire_event_msg_t` | 720 B | collector to engine (80 B header + the event) |
| `wire_policy_cmd_t` | 32 B | engine to collector |

Both sides validate magic `0x58535950` and version `2` on every message and reject a mismatch with a logged
reason, so a partial rollout fails at the first frame instead of misreading a layout. `src/engine/abi.py`
mirrors the header with `ctypes` and asserts every size and offset at import; `make verify` re-derives the
layout by compiling the C header.

The collector is the only privileged process. It accepts exactly the 32-byte command structure, validates
it, and applies it with `bpf_map_update_elem`. It cannot be asked to write files, execute anything, or touch
an arbitrary map. The engine holds no capabilities and reaches the kernel only through that socket.

<p align="center">
  <img src="docs/architecture.svg" alt="Component and data flow: kernel tracepoints and LSM hooks, a 16 MiB ring buffer, the C++20 collector, the AF_UNIX socket, the Python engine, and 32-byte policy commands returning to the BPF maps" width="1120">
</p>

<sub>Component view, drawn from the code. The kernel never blocks on either user-space process: telemetry and
policy travel on one socket, in opposite directions.</sub>

| Figure | What it shows |
|---|---|
| [`docs/fig-killchain.svg`](docs/fig-killchain.svg) | a five-step MCP compromise against image scanning, a 1 s poll and the tracepoint |
| [`docs/fig-frame.svg`](docs/fig-frame.svg) | the byte layout of all three wire structures |
| [`docs/fig-quarantine.svg`](docs/fig-quarantine.svg) | the policy state machine and the audit-only path |
| [`docs/fig-coverage.svg`](docs/fig-coverage.svg) | ten techniques against the six rules, including the gaps |
| [`docs/fig-deployment.svg`](docs/fig-deployment.svg) | node topology and the single listening socket |
| [`docs/fig-metrics.svg`](docs/fig-metrics.svg) | the metric surface after a full run |

## When something else is the better answer

| | xSypher-Stream | [Falco](https://github.com/falcosecurity/falco) | [Tetragon](https://github.com/cilium/tetragon) | [KubeArmor](https://github.com/kubearmor/KubeArmor) |
|---|---|---|---|---|
| Shape | single node, MCP and AI-agent focused, 6 curated rules | cloud native runtime threat detection, large rule ecosystem | eBPF observability and runtime enforcement, Kubernetes first | cloud native workload policy enforcement |
| Policy | YAML over 6 syscall event types plus lineage predicates | Falco rules over a much wider field set | `TracingPolicy` custom resources | CRD policies for process, file and network |
| Inline denial | BPF LSM hooks plus map state | detection first, response handled by companion projects | yes | yes, through AppArmor, SELinux or BPF LSM |
| Best fit | you need to stop a specific agent-host chain today and read the code that does it | you want broad detection and a mature output pipeline | you want Kubernetes-native observability plus enforcement | you want declarative workload policy across a cluster |

Pick xSypher-Stream when the threat model is narrow and the code path matters: about 5,900 lines across
BPF, C++ and Python, one socket, no dependencies beyond `PyYAML`. Pick Falco, Tetragon or KubeArmor when you
need fleet-wide management, a large maintained rule set, or policy that outlives one host.

## Project structure

```
include/xsypher_abi.h   normative binary ABI, static assertions on every size
src/bpf/                eBPF CO-RE: 5 tracepoints, 3 LSM hooks, 6 maps
src/collector/          C++20: loader, cgroup resolver, UDS server, epoll reactor
src/engine/             abi, lineage, rule_engine, mitigator, metrics, tui, main
config/rules.yaml       the 6 shipped rules
deploy/                 Dockerfile, compose, DaemonSet, systemd units
scripts/                verify, ABI parity, docs checks, asset generators
tests/                  59 tests, 31 subtests, plus the end-to-end harness
docs/                   eight reference documents and eight figures
assets/                 logo, banner, social preview, demo GIF and its transcript
```

## Verification

```console
$ make test
59 passed, 31 subtests passed in 0.45s

$ ./scripts/verify_and_benchmark.sh --quick
  PASS  struct layouts identical in C and Python (640 720 32)
  SKIP  clang/bpftool/libbpf headers unavailable - kernel object not compiled
  SKIP  libbpf headers unavailable - collector not compiled
  PASS  pytest suite
  PASS  simulation: all attack chains detected and contained
  passed=3 failed=0 skipped=2
```

Measured on the reference host from that same run: rule evaluation p50 6.08 µs, p95 8.34 µs, p99 14.46 µs;
mitigation latency 2.1 to 2.2 ms per chain; 8 of 8 policy commands delivered; 10,016 events streamed at
34,873 events/s end to end. Numbers move with the machine; the harness prints its own.

Figures are hand-written SVG with no external assets. Two checks keep them true, and both run in CI:

```console
$ make check-docs
python3 scripts/audit_svg.py docs/*.svg
ok   docs/architecture.svg (1120x440, 15 boxes)
ok   docs/fig-coverage.svg (1120x560, 70 boxes)
...
ok   docs/fig-terminal.svg (1120x660, 4 boxes)
python3 scripts/check_docs.py
ok   11 documents: links, anchors, images, fences, style, figure references
```

## Limits and non-goals

- `openat2` is a separate tracepoint and is not hooked, so a credential read through `openat2` is invisible.
- `file_open` sees only the dentry basename; the credential-path branch cannot match absolute prefixes.
  Effective in-kernel file protection today is write denial inside a quarantined domain.
- IMDS denial covers IPv4. `fd00:ec2::254` over IPv6 is detected after the fact on the connect event.
- The C2 rule is a port blocklist. A custom port is not covered; that needs behaviour scoring, not a list.
- `core_pattern` writes are captured by the `openat` filter but no shipped rule reads them.
- `args` captures four `argv` pointers of 64 bytes: a command line, not a payload.
- Container identity depends on cgroup layout. Unknown runtimes resolve to `host`, which disables
  `container_only` rules.
- `--active-kill` is a user-space `SIGKILL` and races a fork loop. The kernel quarantine is authoritative.
- This is a sensor, not an immutable boot chain. An attacker with `CAP_SYS_ADMIN` can unload it.

## Roadmap

There are no `TODO` markers in the tree, so there is no hidden backlog. The honest candidate list is the
documented gaps above, in the order they would close the most coverage: hook `sys_enter_openat2`; extend
`socket_connect` to `AF_INET6`; add one rule over the `core_pattern` write that is already captured; replace
the C2 port list with behaviour scoring. None of these are commitments, and none are implemented.

## Contributing

Bug reports, rule ideas and pull requests are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first: a rule
change needs a positive and a negative test, an ABI change needs a version bump plus the mirrored `abi.py`
change in the same commit, and a new figure needs to pass `make check-docs`.

## Security

Report vulnerabilities privately through GitHub's advisory flow (Security, then Advisories, then Report a
vulnerability). Do not open a public issue. [SECURITY.md](SECURITY.md) lists scope, the invariants that count
as vulnerabilities, and response targets.

## License

Apache-2.0 for everything outside the kernel; the BPF programs are dual `GPL-2.0 OR Apache-2.0` because the
kernel requires a GPL-compatible licence string for BPF helpers. See [LICENSE](LICENSE).

## Acknowledgements

The libbpf and bpftool maintainers, whose tooling this project depends on and would not exist without; the
Linux BPF LSM authors; and the eBPF community projects listed above, whose documentation set the bar this
repository tries to meet.

<sub>Deep reference: [threat model](docs/THREAT-MODEL.md) · [architecture](docs/ARCHITECTURE.md) ·
[wire protocol](docs/WIRE-PROTOCOL.md) · [detections](docs/DETECTIONS.md) ·
[enforcement](docs/ENFORCEMENT.md) · [configuration](docs/CONFIGURATION.md) ·
[operations](docs/OPERATIONS.md) · [performance](docs/PERFORMANCE.md) · [contributing](CONTRIBUTING.md) ·
[security policy](SECURITY.md)</sub>
