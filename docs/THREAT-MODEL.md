# Threat model

Scope: a Linux host, or a fleet of them, running AI agents and Model Context Protocol servers that
invoke tools on behalf of a language model. This document states what is being protected, what the
adversary can do, which boundaries the design depends on, and what is deliberately out of scope.

---

## 1. Assets

| Asset | Why it matters | How it is exposed to this deployment |
|---|---|---|
| Cloud IAM credentials reachable through IMDS | the instance role often grants object storage and queue access | any process that can open a TCP connection to `169.254.169.254` |
| Kubernetes service-account tokens | cluster-scoped API access, usually over-privileged | mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token` |
| SSH private keys and `.env` secrets | lateral movement and third-party API access | baked into images, bind mounted, or written by entrypoints |
| Host credentials | `/etc/shadow`, `/etc/sudoers`, `/root/.ssh` | any process outside a user namespace |
| The agent's own tool surface | an LLM with `exec` or `fetch` tools is a remote shell and an HTTP client | the tool schema the model was given |
| Audit integrity | enforcement decisions must be defensible after the fact | the JSONL log on disk and in transit |

---

## 2. Adversary model

The adversary is assumed to be remote, to control the model's input, and to have no prior presence on the
host.

| # | Capability | Assumed | Rationale |
|---|---|---|---|
| A1 | Craft prompt content that reaches the model | yes | the standard delivery vector: tool output, retrieved document, issue comment, web page |
| A2 | Cause the model to call any tool the server exposes | yes | prompt injection into a tool-using agent |
| A3 | Execute commands inside the workload container as the workload UID | yes | consequence of A2 when an `exec` or `shell` tool exists |
| A4 | Reach any address the container's egress permits | yes | most clusters allow broad egress by default |
| A5 | Read files the workload UID can read | yes | includes mounted secrets and image content |
| A6 | Write to `/tmp`, `/dev/shm`, and image directories | yes | writable by the workload |
| A7 | Enumerate the environment and namespaces | yes | `/proc/self/*` |
| A8 | Persist inside the container | yes | cron, modified entrypoint, dropped binary |
| A9 | Read the audit log and modify it | yes, on the host | log integrity must not depend on the adversary's honesty |

Explicitly not assumed, and therefore out of scope:

| # | Capability | Rationale |
|---|---|---|
| N1 | Root on the host, or `CAP_SYS_ADMIN` in the host user namespace | such an adversary can detach every BPF program; this sensor is removable by root by design |
| N2 | Kernel code execution, or an eBPF verifier bypass | a kernel compromise defeats every in-kernel control; report upstream |
| N3 | Physical access, or control of the boot chain | Secure Boot and measured boot are separate controls |
| N4 | Compromise of the Python engine's interpreter or dependencies | the engine is unprivileged; a compromise yields no kernel authority, only forged alerts |
| N5 | Denial of service by flooding events | drops are the designed back-pressure and are exported as a metric |

---

## 3. Trust boundaries

```
┌───────────────────────────── attacker controlled ─────────────────────────────┐
│  prompt text  →  model  →  tool call arguments                                │
└───────────────────────────────────┬───────────────────────────────────────────┘
                                    │  boundary 1: workload cannot be trusted
┌───────────────────────────────────▼───────────────────────────────────────────┐
│  container: MCP server, watched by kernel tracepoints and LSM hooks            │
└───────────────────────────────────┬───────────────────────────────────────────┘
                                    │  boundary 2: kernel to user space, fixed 640 B records
┌───────────────────────────────────▼───────────────────────────────────────────┐
│  collector: privileged, parses only fixed records and 32 B commands            │
└───────────────────────────────────┬───────────────────────────────────────────┘
                                    │  boundary 3: AF_UNIX SOCK_SEQPACKET, 720 B frames / 32 B commands
┌───────────────────────────────────▼───────────────────────────────────────────┐
│  engine: unprivileged, holds policy, lineage and the audit chain               │
└───────────────────────────────────┬───────────────────────────────────────────┘
                                    │  boundary 4: JSONL audit log, SHA-256 chained
┌───────────────────────────────────▼───────────────────────────────────────────┐
│  log pipeline, SIEM, long-term storage                                         │
└───────────────────────────────────────────────────────────────────────────────┘
```

| Boundary | Crossing data | Validation at the boundary |
|---|---|---|
| 1 to kernel | syscalls | the kernel is the authority; the workload cannot opt out |
| 2 | 640-byte records | fixed layout, all fields bounded, strings NUL-terminated by the kernel |
| 3 inbound | 720-byte frames | exact length, magic, version; failures counted as malformed |
| 3 outbound | 32-byte commands | exact length, magic, version, command type in 10 to 16; the privileged side never evaluates policy |
| 4 | JSONL records | canonical JSON plus chained SHA-256; verification on startup and on demand |

The important property is that boundary 3 is narrow in the outbound direction. The privileged collector
does not accept instructions in a policy language, cannot be told to run a command, and cannot be
redirected to a path or an address that is not a fixed field in a 32-byte structure.

---

## 4. Attack paths and control points

| Path | Preconditions | Detected by | Stopped by |
|---|---|---|---|
| Prompt injection to shell | an `exec` or `shell` tool | `MCP_SHELL_BREAKOUT` on `execve` plus ancestry | cgroup quarantine, `bprm_check_security` denies further exec, optional `SIGKILL` |
| Agent as network proxy | a `fetch` or `http` tool, or a shell | `MCP_RECON_OR_EXFIL_TOOL` on `execve`, `SUSPICIOUS_OUTBOUND_C2_PORT` on `connect` | pid quarantine, address block in `socket_connect` |
| IMDS credential theft | egress to link-local | `CLOUD_IMDS_CREDENTIAL_THEFT` on `connect` and on the resulting `lsm_block` | address block in `socket_connect`, cgroup quarantine, `--block-imds` preloads the address at startup |
| Credential harvesting | read access to a mounted secret | `SENSITIVE_CREDENTIAL_HARVEST` on `openat` | pid quarantine, and write denial for the quarantined domain |
| Fileless staging | writable `/dev/shm` or `memfd_create` available | `FILELESS_MEMFD_EXECUTION` on `memfd_create` and on execution from memory paths | cgroup quarantine, exec denied |
| C2 channel on a common port | any outbound egress | `SUSPICIOUS_OUTBOUND_C2_PORT` on `connect` | address block, pid quarantine |
| Container escape via `core_pattern` | write access to `/proc/sys` | captured by the `openat` filter, no rule today | not stopped; documented gap |

---

## 5. Security invariants

These are the properties the implementation is designed to hold, and the ones worth reporting when they
break.

| Id | Invariant | Mechanism | Failure signature |
|---|---|---|---|
| P1 | The traced syscall never blocks on user space | ring buffer with reserve and submit; drops counted in `metrics_map` | `drops` rising while the traced workload's latency is unchanged |
| P2 | Policy survives engine restart | policy lives in BPF maps, not in the engine | enforcement continues after engine exit |
| P3 | Degradation is never silent | `lsm=unavailable` in the status line, `NOTICE` on stderr, audit record `delivered: false` in audit-only mode | a node that claims enforcement without `xsypher_lsm_blocks_seen` moving under test |
| P4 | No partial rule sets | validation at load, startup aborts | process exits with the offending rule named |
| P5 | Audit is tamper-evident | `hash_n = SHA256(hash_{n-1} || canonical_json(record_n))` | `audit hash chain is INVALID: line N` |
| P6 | Enforcement is reversible | inverse commands on graceful shutdown | `released N kernel policy entries` on stop, empty maps after |
| P7 | Privileged parsing is bounded | 32-byte fixed command, no policy evaluation in the collector | review of `uds_server.cpp` and `bpf_loader.cpp` |

---

## 6. Abuse of the sensor itself

An attacker who reaches the collector socket could clear quarantine state. Mitigations in the default
deployment, and what remains:

| Vector | Control |
|---|---|
| Connecting to `/run/xsypher/stream.sock` | directory mode `0750`, owned by root via `RuntimeDirectoryMode`; the engine runs as the `xsypher` user |
| Reading the socket from a container | it is not mounted into workloads; a shared host path mount would be a misconfiguration |
| Forging telemetry to the engine | the engine only reads; a forged frame can raise a false alert but cannot remove policy |
| Flushing policy by sending `UNQUARANTINE_*` | requires write access to the socket, which requires host access |
| Editing the audit log | breaks the chain at the edited line and every subsequent line |

Residual risk: any process that can write to the socket can alter kernel policy. Treat socket access as
equivalent to enforcement authority, and do not mount the directory into a workload.

---

## 7. Out of scope, stated plainly

- Sandboxing. This is not a jail, a seccomp profile, or a user namespace boundary. It observes and denies
  specific behaviours; it does not confine the process to a policy the way a sandbox does.
- Image assurance. Nothing here inspects an image's contents, provenance or signature.
- Admission control. Rejecting workloads at creation time is a different control plane.
- Network policy. Address and port blocks are node-wide reactions to observed behaviour, not a
  declarative egress policy.
- Immutable infrastructure. The sensor can be removed by a privileged attacker.
- Data-loss prevention. `args` holds four arguments, not a payload; content is not inspected.
