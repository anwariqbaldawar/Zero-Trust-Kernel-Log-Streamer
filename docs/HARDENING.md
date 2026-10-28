# Production hardening

This document describes the four-phase production hardening of xSypher-Stream and the
runtime invariants each phase installs. It is the operational companion to
[WIRE-PROTOCOL.md](WIRE-PROTOCOL.md), [ENFORCEMENT.md](ENFORCEMENT.md) and
[ARCHITECTURE.md](ARCHITECTURE.md).

## Phase summary

| Phase | Contract | Ships in | Runtime invariant |\n|---|---|---|---|\n| 1. ABI v3 | `include/xsypher_abi.h`, `src/engine/abi.py`, `tests/test_wire_protocol.py` | the wire, the encoder, the collector, the tests | both sides reject a frame that disagrees on magic, version 3, or any layout assertion |\n| 2a. BPF LSM | `src/bpf/xsypher.bpf.c`, `include/xsypher_abi.h` | the kernel objects | five LSM hooks deny inline, never merely log |\n| 2b. Collector | `src/collector/*.cpp`, `src/collector/*.hpp` | the privileged daemon | every control-plane command is validated before a map write, and no command writes a file or executes anything |\n| 2c. Engine | `src/engine/lineage.py`, `rule_engine.py`, `mitigator.py`, `metrics.py` | the unprivileged engine | declared enforcement actions apply to a subject the engine resolved from kernel events |\n

## 1. ABI v3

The wire is three fixed structures defined once in [`include/xsypher_abi.h`](../include/xsypher_abi.h)
and mirrored in [`src/engine/abi.py`](../src/engine/abi.py). v3 adds target inode identity,
in-kernel lineage propagation, a heartbeat that the kernel reads directly, a fail-closed switch,
and tamper-protection commands. See [WIRE-PROTOCOL.md](WIRE-PROTOCOL.md) for the exact layout.

`XSYPHER_ABI_VERSION` is 3. A rollout that mixes a v2 collector with a v3 engine fails at the first
frame: both sides assert magic and version and reject a mismatch with a logged reason.

## 2a. Inline enforcement

Five `bpf/lsm` hooks enforce the policy in the kernel, synchronously, in about 0 ms:

- `bprm_check_security`: denies a tracked AI lineage that executes a restricted shell or a binary
  whose inode was re-registered under a new path, and denies the execution of the collector binary
  when `fail_closed` is set.
- `socket_connect`: denies a quarantined pid or cgroup, the cloud metadata addresses (IPv4 and IPv6),
  and IPv4-mapped IPv6, inline.
- `file_open`: denies `O_WRONLY`/`O_RDWR`/`O_APPEND`/`O_TRUNC`/`O_CREAT` inside a quarantined domain,
  denies writes to sensitive credentials inside that domain, and denies writes to
  `/proc/sys/kernel/core_pattern`, the eBPF tracing directory and the audit log.
- `task_kill`: blocks `SIGKILL`, `SIGTERM` and `SIGTERM` against protected PIDs unless the caller is
  the owning cgroup or carries an authenticated shutdown token.
- `bpf`: blocks `BPF_MAP_CREATE`, `BPF_MAP_UPDATE_ELEM`, `BPF_MAP_DELETE_ELEM`, `BPF_PROG_LOAD` and
  `BPF_BTF_LOAD` that would mutate an xSypher map.

Every denial emits a `wire_event_msg_t` with `enforced_inline = 1` and an `open_flags` reason code.

## 2b. Collector validation

The collector is the only privileged process. It owns the BPF object, the skeleton and every policy
map. The engine reaches it over a single `AF_UNIX` `SOCK_SEQPACKET` socket and can send only
`wire_policy_cmd_t` frames. For each command the collector:

1. validates the frame size and the magic and version fields;
2. accepts `cmd_type` in the known set and rejects an unknown type with a logged warning;
3. translates the command into map writes through `bpf_map_update_elem` or `bpf_map_delete_elem`
   and never calls `system()`, `execv()` or opens a file.

Runtime-comm and inode registration are convenience wrappers over the same map writes; they resolve
paths with `stat()` in user space and push `(ino, dev)` keys the kernel can compare.

## 2c. Engine lineage and fail-closed

The engine decodes each frame with the mirrored `ctypes` structures, so a layout change is caught at
import. The lineage graph resolves ancestry from the kernel-provided `ppid`, `tgid` and the
`lineage_root_pid`/`lineage_flags` the `sched_process_fork` hook propagates, and the engine heartbeats
its liveness into `runtime_comms_map` so the kernel can fail closed when the engine stops answering.

The heartbeat covers two cases the agent cannot argument its way out of: the engine process is killed,
and the `AF_UNIX` socket between the engine and the collector is torn down. In both cases the
collector stops seeing heartbeats and the kernel denies tracked AI lineages at the LSM hooks.

## Tamper protection

Protected PIDs (the collector, the engine, the MCP server) cannot be killed from user space through
`SIGKILL`, `SIGTERM` or `SIGTERM` while `task_kill` is attached. The `lsm/bpf` hook stops an
unprivileged process from mutating the policy maps directly. Both are lifted only by an
authenticated shutdown token pushed through `CMD_SET_SHUTDOWN_TOKEN`.

## Operational reading

- `xsypher_heartbeat_age_seconds` rising past the fail-closed threshold means the engine is not
  heartbeating; the kernel is now denying tracked AI lineages.
- `xsypher_enforced_inline_events_total` counts synchronous in-kernel denials; a steady count proves
  the LSM hooks are attached and answering.
- `xsypher_collector_status` is 1 when the collector is up and 0 when it has exited.

## Limits

- An attacker with `CAP_SYS_ADMIN` can unload the BPF objects; this is a sensor, not an immutable
  boot chain.
- `--active-kill` is a user-space `SIGKILL` and races a fork loop; the kernel quarantine is
  authoritative.
- Resident memory follows the number of live tracked processes, bounded by `--max-tracked`.
