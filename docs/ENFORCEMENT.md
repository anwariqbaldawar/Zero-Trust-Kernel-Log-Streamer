# Enforcement

How a rule match becomes a kernel denial, what each hook actually stops, and where the model leaks.

---

![Quarantine state machine, audit-only path and denying hooks](fig-quarantine.svg)

*Policy state lives in BPF maps; the audit-only mode skips the denial, not the detection.*

## 1. State

Two levels of state exist, and only one of them is a decision.

| State | Location | Written by | Meaning |
|---|---|---|---|
| Enforcement mode | `config_map[0]`, `u32` | `--enforce` at startup, `CMD_SET_ENFORCEMENT_MODE` | 0 audit only, 1 inline block |
| Domain state | `quarantined_pids_map`, `quarantined_cgroups_map`, value `u8` | `CMD_QUARANTINE_PID`, `CMD_QUARANTINE_CGROUP`, and their inverses | 0 observe, 1 block |
| Config | `config_map[0]`, `xsypher_config_t` | collector at startup, `CMD_SET_*` | enforcement mode, fail-closed, heartbeat age, shutdown token |
| Protected PIDs | `protected_pids_map`, key `tgid` | `CMD_PROTECT_PID`, `CMD_UNPROTECT_PID` | guard a pid against task_kill |
| Restricted inodes | `restricted_inodes_map`, key `(ino, dev)` | `CMD_REGISTER_INODE` | deny a re-registered binary by inode |
| Runtime comms | `runtime_comms_map`, key comm | engine heartbeat, `CMD_SET_HEARTBEAT` | fail-closed liveness |
| Blocked IPs | `blocked_ipv4_map`, key address | `CMD_BLOCK_IPV4`, `CMD_UNBLOCK_IPV4` | node-wide address block |

A domain is denied when the mode is inline **and** either its cgroup id or its tgid maps to
`QUARANTINE_BLOCK`. The cgroup check runs first, because it is the broader and more durable of the two.
With `fail_closed` set, a domain is also denied when the engine heartbeat is stale and the process is a
tracked AI lineage, whether or not it was previously quarantined.

```
                     ┌──────────────────────┐
     execve/connect  │ should_block(tgid,   │   mode != INLINE  ──▶ allow
     /file_open ────▶│ cgroup_id)           │   cgroup == BLOCK ──▶ deny (METRIC_QUARANTINE_DENIES)
                     │                      │   pid    == BLOCK ──▶ deny (METRIC_QUARANTINE_DENIES)
                     └──────────────────────┘   otherwise         ──▶ allow
```

`socket_connect` is the exception: it evaluates the global address map before consulting quarantine
state, because a blocked address is a node-wide decision rather than a domain decision.

---

## 2. Quarantine lifecycle

```
                     alert fires (rule match)
                              │
                              ▼
              engine builds CMD_QUARANTINE_CGROUP(cgroup_id)
              and/or CMD_QUARANTINE_PID(tgid), deduplicated
                              │
                              ▼
              collector: bpf_map_update_elem(value = QUARANTINE_BLOCK)
                              │
                              ▼
    ┌─────────────── kernel denies new syscalls in the domain ───────────────┐
    │  bprm_check_security  -EPERM   no new program image                    │
    │  socket_connect       -EPERM   no connection to blocked addresses      │
    │  file_open            -EACCES  no write-like opens                     │
    └────────────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┴────────────────┐
              ▼                                ▼
   sched_process_exit deletes         engine shutdown emits
   the tgid entry                     UNQUARANTINE_* for every entry
                                      it installed, then closes
```

Deduplication is engine-side and per object: `_quarantined_cgroups`, `_quarantined_pids` and
`_blocked_ips`. A fork storm that matches the same rule a thousand times produces one map update and one
audited mitigation entry for the first match, then cooldown-suppressed alerts.

---

## 3. Hook semantics

### `lsm/bprm_check_security`

| Aspect | Behaviour |
|---|---|
| Fires | before a new program image replaces the current one |
| Denies | `-EPERM` when the calling task is quarantined |
| Emits | one `EVENT_LSM_BLOCK` with reason 1 and `filename` from `bprm->filename` |
| Counters | `METRIC_LSM_BLOCKS` |
| Stops | `execve`, `execveat`, and therefore any fork-then-exec chain in the quarantined domain |
| Does not stop | an already running image continuing to execute, or `fork()` without `exec` |

This is the hook that makes quarantine meaningful: a shell that spawned before the update still cannot
replace itself with `curl`, and a child cannot exec a payload.

### `lsm/socket_connect`

| Aspect | Behaviour |
|---|---|
| Fires | after `move_addr_to_kernel()`, so the address is read with `bpf_probe_read_kernel` |
| Denies | `-EPERM` for any IPv4 destination present in `blocked_ipv4_map`, regardless of quarantine |
| Denies | `-EPERM` for `169.254.169.254` when the caller is quarantined |
| Emits | `EVENT_CONNECT` converted to `EVENT_LSM_BLOCK`, reason 3 (blocked IP) or 2 (IMDS) |
| Counters | `METRIC_LSM_BLOCKS`, plus `METRIC_IP_BLOCKS` or `METRIC_IMDS_BLOCKS` |
| Requires | inline mode; in audit mode the hook returns immediately |

Two properties follow. First, `block_ipv4` is a node-wide block: once the engine blocks a C2 address,
every process on the host loses it, which is the intended effect of a confirmed-bad destination and the
reason the engine only emits the action from rules that identify infrastructure-hostile addresses.
Second, IMDS denial is domain-scoped: it needs both a quarantined domain and the metadata address, so a
healthy workload that legitimately reads metadata is unaffected.

IPv4-mapped IPv6 and the IPv6 metadata address `fd00:ec2::254` are denied inline here, before the
connection attempt; see §7 for what remains a detection-only case.

### `lsm/file_open`

| Aspect | Behaviour |
|---|---|
| Fires | on the successful-open path only (`if (ret != 0) return ret`) |
| Reads | `file->f_path.dentry->d_name.name`, that is the **basename**, not a full path |
| Denies | `-EACCES` when the task is quarantined and the open is write-like, or when the name matches the credential list |
| Emits | `EVENT_OPENAT` converted to `EVENT_LSM_BLOCK`, reason 4 (credential read) or 5 (write denied) |
| Counters | `METRIC_LSM_BLOCKS` |

`-EACCES` rather than `-EPERM` is deliberate: it is the error a process normally sees for a permission
problem, so a denied write inside a quarantined container looks like an ordinary EACCES to the workload
and does not reveal the presence of the sensor.

### `lsm/task_kill`

| Aspect | Behaviour |
|---|---|
| Fires | on `sigkill` and `sigterm` (and `sigstop`, a stop rather than a terminate) |
| Reads | `info->si_pid` (the target tgid) and the caller's cgroup |
| Denies | `-EPERM` when the target is protected and the caller is neither its owning cgroup nor a task carrying the shutdown token |
| Emits | `EVENT_LSM_BLOCK`, reason 10 (tamper kill) |
| Counters | `METRIC_LSM_BLOCKS` |

This is the hook that stops a compromised agent from killing the collector or the engine out from under
the pipeline. `SIGKILL` cannot be trapped in user space, so the guard has to live in the kernel.

### `lsm/bpf`

| Aspect | Behaviour |
|---|---|
| Fires | on the BPF syscall for map create/update/delete, prog load and BTF load |
| Reads | the `union bpf_attr` target map id or the requested program type |
| Denies | `-EPERM` on a mutation whose map id belongs to xSypher, unless the task carries the shutdown token |
| Emits | `EVENT_LSM_BLOCK`, reason 11 (tamper bpf) |
| Counters | `METRIC_LSM_BLOCKS` |

The kernel must permit the collector to load the program at startup, so the check excludes the loading
task (the collector, which owns the maps) and denies everyone else. An unprivileged process that finds a
map id cannot mutate policy state, block_ipv4 entries or the heartbeat map directly.

---

## 4. What quarantine stops, exactly

| Operation | Stopped | Why |
|---|---|---|
| `execve` of a new program | yes | `bprm_check_security` |
| `fork()` without `exec` | no | no hook denies process creation in this design |
| `connect()` to a blocked address | yes | `socket_connect` |
| `connect()` to a new, unblocked address | no | the address is not known-bad |
| `connect()` on an already-open socket | no | existing file descriptors survive |
| `write()` to an open file | no | only new opens are denied |
| `openat()` for write in the domain | yes | `file_open` |
| `read()` from a credential file, by absolute path | detected, not denied in the hook | the hook sees the basename only |
| `mmap()` of an existing mapping | no | not a hooked operation |

This is a deliberate trade between durability and precision. Quarantine is a containment measure for a
domain that has already shown hostile behaviour, paired with `kill` for the immediate case and with the
audit chain for the after-action record. It is not a sandbox.

---

## 5. Return codes

| Hook | Code | Numeric | Caller sees |
|---|---|---|---|
| `bprm_check_security` | `-EPERM` | `-1` | `execve` fails with `EPERM` |
| `socket_connect` | `-EPERM` | `-1` | `connect` fails with `EPERM` |
| `file_open` | `-EACCES` | `-13` | `open` fails with `EACCES` |

All denials also set `blocked_by_lsm = 1` and `retval = -EPERM` on the emitted record so a consumer can
group enforcement evidence without parsing the reason code.

---

## 6. Race conditions

| Race | Why it exists | Mitigation in this implementation | Residual risk |
|---|---|---|---|
| Fork storm | children are created between the rule match and the map update | cgroup quarantine covers all tasks in the cgroup, including ones created after the update | children that leave the cgroup (only possible with privilege) are not covered |
| PID reuse | the target exits and its pid is recycled before the command lands | `sched_process_exit` deletes the pid entry; the engine never kills `pid <= 2`; cgroup scoping is preferred for destructive rules | a pid-scoped quarantine could in principle hit a recycled pid within the update window, which is why cgroup scope is the default for the critical rules |
| Exec already in flight | the process was inside `execve` when the rule fired | `bprm_check_security` runs before the new image is committed | none for the denied exec |
| Engine crash between alert and dispatch | commands are built before they are sent | the audit record's `delivered` is set from the send result, never assumed | the alert exists with `delivered: false`, which is the correct record |
| Collector restart | maps are recreated empty | the engine re-sends `CMD_SET_ENFORCEMENT_MODE` on reconnect; the next matching event re-quarantines | enforcement is briefly absent for previously quarantined domains |
| Two engines attached | both observe the same events | dedup is per process, so commands are idempotent map writes | duplicate audit records in two logs |
| Clock skew | kernel monotonic versus engine wall clock | both timestamps are recorded | latency computation must subtract monotonic values, not wall-clock ones |

---

## 7. Known enforcement gaps

Stated here so that no reader infers coverage that does not exist.

**Credential reads by basename.** `file_open` receives the dentry name, so `prefix_matches(path,
"/etc/shadow", 11)` cannot match a basename of `shadow`. The credential-read branch of the hook is
therefore effectively inert, and the working protection is write denial inside a quarantined domain.
Detection of credential reads is unaffected: the `openat` tracepoint reads the user-space path and
`SENSITIVE_CREDENTIAL_HARVEST` fires on it, after which the pid is quarantined. The correct fix is to
resolve the full path in the hook, for example with `bpf_d_path()` on kernels that permit it in LSM
contexts, or to compare a curated set of credential **basenames**. Until then, treat in-kernel file
protection as write-only.

**IPv6 metadata.** `fd00:ec2::254` is not evaluated in `socket_connect`. The rule fires on the connect
event and quarantines the cgroup, so subsequent attempts fail at `bprm_check_security`, but the first
IPv6 connection to the metadata service is not denied by the hook.

**Unblocked egress.** Only addresses that a rule has blocked, and the metadata service from a quarantined
domain, are denied. A quarantined domain can still reach any other address it has not been blocked from,
which is why `quarantine_cgroup` is paired with `block_ipv4` in the C2 and IMDS rules.

**Existing descriptors.** A quarantined process keeps its sockets and open files. Only new operations are
denied.

---

## 8. Verification

Enforcement is observable from three places, and a deployment should check all three after any change:

```console
# 1. the collector says whether the hooks attached
$ journalctl -u xsypher-collector -n 5 | grep -o 'lsm=[a-z]*'
lsm=active

# 2. the kernel counters prove denials are happening
$ curl -s localhost:9109/metrics | grep -E 'lsm_blocks_seen|mitigations_total'
xsypher_lsm_blocks_seen{type="lsm_block"} 7
xsypher_mitigations_total{action="quarantine_cgroup"} 1

# 3. the audit record shows what was applied and whether it was delivered
$ grep -o '"mitigations":\[[^]]*\]' /var/log/xsypher-alerts.jsonl | head -1
"mitigations":[{"action":"quarantine_cgroup","command":"quarantine_cgroup","target":40961,"delivered":true}]
```

Simulation covers the command-construction path without a kernel: `tests/simulate_mcp_attack.py` asserts
the exact bytes of all eight expected commands. Map application is exercised by CI only on kernels with
BPF LSM; on other hosts the verification script reports `SKIP` rather than pretending to pass.
