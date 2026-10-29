# Kernel validation and policy operations

## Validation status

The QEMU workflow builds upstream Linux v6.12, enables BPF LSM and BTF, generates real CO-RE types,
compiles the collector and BPF object, then loads and attaches every program with a strict skeleton
loader. No telemetry-only retry is used. A successful workflow establishes load/attach compatibility
with that kernel, not correctness of every policy or portability to every distribution kernel.
The workflow has not been executed in the development sandbox. Native BPF compilation and verifier
acceptance remain unverified there because clang, bpftool, libbpf development files and CMake are absent.

Before deployment, run positive and negative live syscall tests on the target kernel, including openat2,
io_uring, short sockaddr lengths, both IPv6 IMDS encodings, port 443, worker-thread exit, fork/exec storms,
ring-buffer saturation and policy reloads. Load/attach CI is not a substitute for these behavioral tests.

## Map policy contract

`lineage_map` is a 65,536-entry LRU keyed by TGID. Fork propagates state before the child runs;
exec classifies runtime basenames using `runtime_comms_map`. Existing runtime names are broad profiles,
not authenticated identities: Python and Node workloads may be classified even when they are not agents.
Processes already running at attachment are not recursively inventoried. LRU eviction can lose ancestry;
this is not an adversarially lossless process tracking mechanism. Size the map for the workload and test
pressure behavior before enabling enforcement. Renames and pre-existing processes need explicit review.

The `egress_allowlist` HASH key is the 40-byte `egress_key_t` in `include/xsypher_abi.h`:

- cgroup ID, executable inode and device identify the caller;
- family is host-order AF_INET or AF_INET6;
- port is network-order;
- address is network-order, with IPv4 in the first four bytes and the remainder zero.

The one-byte value must be nonzero to grant access. There are no wildcard entries. An empty map denies
all tracked AI IPv4/IPv6 connections in inline mode, including connections by runtime roots. Quarantine
and IMDS denials override grants. IPv4-mapped IPv6 requires its own IPv6 grant. Provision entries with
privileged libbpf tooling or `bpftool map update id <map-id> key hex ... value hex 01`, using the exact
layout above. Find the live map ID with `bpftool map show`; never assume IDs survive collector restart.
No authenticated remote egress provisioning protocol is implemented. Re-provision before enabling
inline enforcement after every restart or executable replacement. Inode/device is not a content hash;
privileged in-place executable mutation is outside this identity guarantee.

`audit_config_map` is an ARRAY with one u32 value. Zero (default) suppresses untainted exec, connect and
exit telemetry. One enables full audit. Sensitive file and memfd events and inline denials remain visible.
For example, after locating its map ID:

```bash
sudo bpftool map update id "$AUDIT_MAP_ID" key hex 00 00 00 00 value hex 01 00 00 00
```

This map does not change enforcement mode. Frames remain ABI v3 (656-byte events, 736-byte wire frames).
`sendmmsg` batches up to 32 distinct SEQPACKET frames, so Python requires no framing changes. Partial
sends are counted as dropped frames; there is no unbounded retry backlog. The fixed-capacity batch is
owned by the collector reactor and must not be accessed from other threads.

## Scope and performance

Synchronous LSM enforcement removes the Python round-trip decision window. It does not have literally
zero runtime cost. Alert reservation/submission happens after the denial decision but before the hook
returns; ring-buffer failure cannot turn denial into permission. No live-kernel 100k-events/sec result
has been established. Run workload-specific measurements with audit both enabled and disabled.

Path rules are namespace-relative. Hardlinks, bind mounts, inherited descriptors, existing sockets,
UDP sendto and delegated network helpers need additional policy/testing; socket_connect is not a complete
network firewall. Credential path resolution failures in tracked inline workloads are denied. Other
LSMs' nonzero return values are preserved. Privileged attackers can still detach the programs.
