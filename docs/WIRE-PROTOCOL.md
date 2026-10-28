# Wire protocol

The binary contract between the kernel object, the collector and the engine. `include/xsypher_abi.h` is
normative; `src/engine/abi.py` mirrors it with `ctypes` and asserts every size and offset at import; a
test compiles the header with the host C compiler and compares both representations.

![Byte layout of the three wire structures](fig-frame.svg)

*Band width is proportional to field size.*

Three structures, all `packed, aligned(8)`, all integers little-endian:

| Structure | Size | Direction | Transport |
|---|---|---|---|
| `struct kernel_event_t` | 656 B | kernel to collector | `BPF_MAP_TYPE_RINGBUF`, 16 MiB |
| `struct wire_event_msg_t` | 736 B | collector to engine | `AF_UNIX` / `SOCK_SEQPACKET`, one datagram |
| `struct wire_policy_cmd_t` | 32 B | engine to collector | `AF_UNIX` / `SOCK_SEQPACKET`, one datagram |

---

## 1. Constants

| Name | Value | Meaning |
|---|---|---|
| `XSYPHER_WIRE_MAGIC` | `0x58535950` | bytes `50 59 53 58`, `PYSX` little-endian |
| `XSYPHER_ABI_VERSION` | `2` | bumped on any layout change |
| `MAX_COMM_LEN` | 16 | kernel `TASK_COMM_LEN` |
| `MAX_PATH_LEN` | 256 | path buffer |
| `MAX_ARGS_LEN` | 256 | joined `argv` buffer |
| `MAX_CONTAINER_ID_LEN` | 64 | one full container identifier |
| `XSYPHER_RINGBUF_BYTES` | 16,777,216 | 16 MiB |

---

## 2. `struct kernel_event_t`, 656 bytes

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | `timestamp_ns` | `bpf_ktime_get_ns()`, monotonic, not wall clock |
| 8 | 8 | `cgroup_id` | `bpf_get_current_cgroup_id()` |
| 16 | 4 | `pid` | thread id |
| 20 | 4 | `tgid` | process id |
| 24 | 4 | `ppid` | `real_parent->tgid`, 0 for kernel threads |
| 28 | 4 | `uid` | |
| 32 | 4 | `gid` | |
| 36 | 4 | `mnt_ns_id` | `nsproxy->mnt_ns->ns.inum` |
| 40 | 4 | `pid_ns_id` | `nsproxy->pid_ns_for_children->ns.inum` |
| 44 | 4 | `net_ns_id` | `nsproxy->net_ns->ns.inum` |
| 48 | 4 | `event_type` | see §5 |
| 52 | 4 | `retval` | syscall or hook return, `-1` when the read failed |
| 56 | 1 | `blocked_by_lsm` | 1 when an LSM hook denied the operation |
| 57 | 1 | `af_family` | `AF_INET` (2) or `AF_INET6` (10) |
| 58 | 2 | `dport` | network byte order |
| 60 | 2 | `sport` | network byte order |
| 62 | 2 | `reserved0` | explicit padding, keeps `daddr_v4` 4-byte aligned |
| 64 | 4 | `daddr_v4` | raw network byte order |
| 68 | 4 | `saddr_v4` | raw network byte order |
| 72 | 16 | `daddr_v6` | raw 16-byte address |
| 88 | 4 | `open_flags` | `openat` flags, `f_mode` in `file_open`, or the LSM block reason when `blocked_by_lsm` is set |
| 92 | 16 | `comm` | NUL terminated |
| 108 | 16 | `parent_comm` | NUL terminated |
| 124 | 256 | `filename` | `execve` path, opened path, or dentry name |
| 380 | 256 | `args` | up to four `argv` entries joined by spaces |
| 636 | 4 | `target_ino` | inode of the target binary / opened file |
| 640 | 4 | `target_dev` | `st_dev` of the target binary / opened file |
| 644 | 4 | `lineage_root_pid` | tgid of the root AI-runtime ancestor (0 = none) |
| 648 | 4 | `lineage_flags` | `LINEAGE_FLAG_*` bitmask |
| 652 | 1 | `enforced_inline` | 1 = synchronous 0 ms in-kernel denial |
| 653 | 1 | `reserved2` | zero |
| 654 | 2 | `reserved3` | zero |

`open_flags` is overloaded on purpose: a `LSM_BLOCK` / `ENFORCED_INLINE` record carries a reason code there
instead of a flag set, which saves a field in the hot structure. Reason codes: 0 none, 1 quarantine exec,
2 IMDS, 3 blocked IP, 4 credential read, 5 write denied, 6 restricted shell, 7 restricted inode,
8 IMDS IPv6, 9 fail-closed, 10 tamper kill, 11 tamper bpf, 12 path evasion.

---

## 3. `struct wire_event_msg_t`, 736 bytes

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | `magic` | `0x58535950` |
| 4 | 2 | `version` | 3 |
| 6 | 2 | `msg_type` | 1 telemetry event, 2 heartbeat |
| 8 | 8 | `seq_no` | monotonic per collector, not per client |
| 16 | 64 | `container_id` | see §6 |
| 80 | 656 | `event` | an embedded `kernel_event_t`, byte for byte |

### Hexdump

A real frame produced by `encode_wire_frame()` with a full 64-character container id and `seq_no`
118423 (`0x0001CE97`):

```
0000  50 59 53 58 02 00 01 00 97 ce 01 00 00 00 00 00  |PYSX............|
0010  32 36 31 30 31 64 36 65 30 34 30 65 35 38 32 35  |26101d6e040e5825|
0020  61 36 66 30 63 33 61 31 62 37 64 32 65 34 66 36  |a6f0c3a1b7d2e4f6|
0030  61 38 62 39 63 30 64 31 65 32 66 33 61 34 62 35  |a8b9c0d1e2f3a4b5|
0040  63 36 64 37 65 38 66 39 61 30 62 31 63 32 64 33  |c6d7e8f9a0b1c2d3|
0050  24 cf 3e b3 0e 16 72 18 01 a0 00 00 00 00 00 00  |$.>...r.........|
0060  6d 09 00 00 6d 09 00 00 b0 04 00 00 e8 03 00 00  |m...m...........|
0070  e8 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
```

| Bytes | Decode |
|---|---|
| `50 59 53 58` | magic, `PYSX` |
| `03 00` | version 3 |
| `01 00` | `MSG_TELEMETRY_EVENT` |
| `97 ce 01 00 00 00 00 00` | `seq_no` 118423 |
| `32 36 31 30 ... 64 33` | 64 ASCII hex characters, no NUL terminator |
| `24 cf 3e b3 0e 16 72 18` | `timestamp_ns` at the start of the event |
| `01 a0 00 00 00 00 00 00` at 0x58 | `cgroup_id` 40961 (`0xA001`) |
| `6d 09 00 00` twice | pid and tgid 2413 |
| `b0 04 00 00` | ppid 1200 |
| `e8 03 00 00` twice | uid and gid 1000 |

---

## 4. `struct wire_policy_cmd_t`, 32 bytes

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | `magic` | `0x58535950` |
| 4 | 2 | `version` | 3 |
| 6 | 2 | `cmd_type` | 10 to 22 |
| 8 | 8 | `target_cgroup_id` | `QUARANTINE_CGROUP`, `UNQUARANTINE_CGROUP` |
| 16 | 4 | `target_pid` | `QUARANTINE_PID`, `UNQUARANTINE_PID` |
| 20 | 4 | `target_ipv4` | raw network byte order |
| 24 | 4 | `enforcement_mode` | 0 audit, 1 inline block |
| 28 | 4 | `value` | general 32-bit payload (was `reserved0`) |

### Hexdump

`PolicyCommand.quarantine_cgroup(40961)`:

```
0000  50 59 53 58 02 00 0c 00 01 a0 00 00 00 00 00 00  |PYSX............|
0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
```

Command type 12 (`0x000c`) is `CMD_QUARANTINE_CGROUP`; the target occupies offset 8. The unused fields are
zero, which matters: a decoder that accepts a non-zero `value` for an unrelated command is not validating.

---

## 5. Enumerations

### Event types

| Name | Value | Emitted by |
|---|---|---|
| `EVENT_UNKNOWN` | 0 | never |
| `EVENT_EXECVE` | 1 | `execve` tracepoint, and `bprm_check_security` denials |
| `EVENT_CONNECT` | 2 | `connect` tracepoint, and `socket_connect` denials |
| `EVENT_OPENAT` | 3 | `file_open` LSM hook (on open and on denial) |
| `EVENT_MEMFD_CREATE` | 4 | `memfd_create` tracepoint |
| `EVENT_PROCESS_EXIT` | 5 | `sched_process_exit` tracepoint |
| `EVENT_LSM_BLOCK` | 6 | all five LSM hooks when they deny |
| `EVENT_ENFORCED_INLINE` | 7 | `bprm_check_security` when it denies an in-kernel lineage or a tampering attempt |
### Message types

| Name | Value |
|---|---|
| `MSG_TELEMETRY_EVENT` | 1 |
| `MSG_HEARTBEAT` | 2 |

### Command types

| Name | Value | Field used |
|---|---|---|
| `CMD_QUARANTINE_PID` | 10 | `target_pid` |
| `CMD_UNQUARANTINE_PID` | 11 | `target_pid` |
| `CMD_QUARANTINE_CGROUP` | 12 | `target_cgroup_id` |
| `CMD_UNQUARANTINE_CGROUP` | 13 | `target_cgroup_id` |
| `CMD_BLOCK_IPV4` | 14 | `target_ipv4` |
| `CMD_UNBLOCK_IPV4` | 15 | `target_ipv4` |
| `CMD_SET_ENFORCEMENT_MODE` | 16 | `enforcement_mode` |
| `CMD_PROTECT_PID` | 17 | `target_pid` (value: token) |
| `CMD_UNPROTECT_PID` | 18 | `target_pid` |
| `CMD_SET_FAIL_CLOSED` | 19 | `value` (1 fail-closed, 0 clear) |
| `CMD_SET_SHUTDOWN_TOKEN` | 20 | `value` (authenticated shutdown token) |
| `CMD_REGISTER_INODE` | 21 | `target_ipv4` = dev, `value` = ino |
| `CMD_SET_HEARTBEAT` | 22 | `value` = uptime_ms the kernel accepts as fresh |

---

## 6. Conventions

**Container identity.** A 64-hex identifier fills the field completely and is therefore not NUL
terminated. Short values such as `host` are NUL padded. Python decodes with a bounded read of the first
NUL, and treats an empty result as `host`. Writing a 64-character value plus a terminator would be a
buffer overflow into `event.magic`; the encoder truncates instead.

**Byte order.** Addresses and ports are exactly as the kernel received them in `sockaddr_in` and
`sockaddr_in6`, that is network byte order. On little-endian hosts `169.254.169.254` is stored as
`0xFEA9FEA9`. Never convert to host order in the kernel, never assume host order in the engine; use
`XSYPHER_IMDS_IPV4_RAW` in C and `abi.IMDS_IPV4_RAW` in Python.

**Frame boundaries.** `SOCK_SEQPACKET` preserves datagram boundaries. A read of fewer than 736 bytes is a
protocol error, not a partial frame to be reassembled. The engine decodes with `strict=True`, which
rejects anything that is not exactly 736 bytes.

**Sequence numbers.** `seq_no` is monotonic per collector process and resets on restart. It is written to
the audit record as `event.seq_no` so a gap in a shipped log can be traced to a collector restart rather
than to log tampering.

**Timestamps.** The kernel timestamp is monotonic and comparable only within one boot. The audit record
carries both `event_timestamp_ns` (kernel) and `timestamp_ns` (engine wall clock), so latency can be
computed without trusting either clock alone.

---

## 7. Connection state machine

```
            engine                                   collector
              │                                          │
              │  connect(AF_UNIX, SOCK_SEQPACKET)        │
              ├─────────────────────────────────────────▶│  accept4(), non-blocking
              │                                          │
              │  ── no handshake, no negotiation ──      │
              │                                          │
              │◀──────────── 736 B frames ───────────────┤  broadcast to every client
              │                                          │
              ├──────────── 32 B commands ──────────────▶│  validate, then bpf_map_update_elem
              │                                          │
              │  read() returns 0 or EPIPE                │
              │◀────────────── disconnect ───────────────┤  client removed from the epoll set
              │                                          │
              │  retry every 1 s                          │
```

There is no version negotiation. Both sides assert magic and version on every message and reject
mismatches, so a partial rollout fails loudly at the first frame instead of misinterpreting a layout.
Reconnect is unconditional: the engine retries once per second, and on every successful connect it sends
`CMD_SET_ENFORCEMENT_MODE` when `--enforce-kernel` is set, which restores inline mode after a collector
restart recreated `config_map` with the startup default.

---

## 8. Validation rules

Engine side, per inbound frame:

| Check | Failure action |
|---|---|
| length exactly 736 bytes | frame counted as malformed and discarded |
| `magic == 0x58535950` | malformed |
| `version == 2` | malformed, reason logged |
| `container_id` decodes to printable ASCII or empty | treated as `host` |

Collector side, per inbound command:

| Check | Failure action |
|---|---|
| length exactly 32 bytes | frame dropped, `dropped_frames_` incremented |
| magic and version | dropped with a warning naming the value |
| `cmd_type` in the known set | dropped, `WARNING: unknown policy cmd N` |
| target field non-zero where required | `WARNING: policy cmd N failed: map not available` or a map error |

The collector never trusts a command further than the map call. It applies the update, logs the failure
if the kernel rejects it, and continues serving other clients.

---

## 9. Versioning policy

A change to any structure, offset, size, or enumerated value is a breaking change and increments
`XSYPHER_ABI_VERSION`. In one commit:

1. Change `include/xsypher_abi.h`.
2. Mirror it in `src/engine/abi.py`, including explicit padding.
3. Update the `XSYPHER_STATIC_ASSERT` block in C and the size and offset assertions in Python.
4. Update the literal sizes and offsets in `tests/test_wire_protocol.py`, which asserts integers on
   purpose to force this review.
5. Update the tables in this document.
6. Describe the migration in the pull request for any deployment that may run mismatched components.

Both components reject a mismatched magic or version and log the reason. There is no compatibility
shim and no best-effort parse; a mismatch is an operator error, and silently decoding it would be worse
than refusing.
