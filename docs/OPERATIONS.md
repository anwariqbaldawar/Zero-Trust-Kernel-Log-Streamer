# Operations runbook

Day-two procedures: health checks, metrics and alerting, the audit log, capacity, upgrades and
troubleshooting.

- [Health checks](#health-checks)
- [Metrics](#metrics)
- [Alerting](#alerting)
- [Audit log](#audit-log)
- [Capacity planning](#capacity-planning)
- [Upgrade and rollback](#upgrade-and-rollback)
- [Uninstall](#uninstall)
- [Troubleshooting](#troubleshooting)

---

## Health checks

| Check | Command | Expected |
|---|---|---|
| Collector running, socket present | `test -S /run/xsypher/stream.sock && echo ok` | `ok` |
| Socket path and mode | `ls -ld /run/xsypher /run/xsypher/stream.sock` | directory `0750`, socket owned by root |
| Kernel enforcement active | `curl -s localhost:9109/metrics \| grep xsypher_lsm_blocks_seen` | series present and increasing under test load |
| Engine liveness | `curl -fsS localhost:9109/healthz` | `ok` |
| Telemetry flowing | `curl -s localhost:9109/metrics \| grep '^xsypher_events_total'` | counters increasing |
| Policy channel healthy | `curl -s localhost:9109/metrics \| grep commands_failed_total` | `0` |
| Audit chain intact | see [Audit log](#audit-log) | `(True, n, None)` |

The collector writes a status line every ten seconds to stderr unless `--no-status` is set:

```
[xsypher] status bpf: loaded=yes programs=8 lsm=active | ringbuf=118422 sent=118420 bad=0 | clients=1 | cmd=2 dropped=0 | resolver hits=117891 misses=531 | events=118422 drops=0 lsm_blocks=7 imds=1 ip=1 denials=2
```

`lsm=unavailable` means the LSM programs could not attach; telemetry is unaffected but nothing will be
blocked, and the collector prints `WARNING: BPF-LSM unavailable (...); continuing in telemetry-only
mode`. `drops` is the kernel side ring buffer drop counter; when it rises the consumer cannot keep up.

---

## Metrics

Prometheus text format at `:9109/metrics`.

| Series | Type | Interpretation |
|---|---|---|
| `xsypher_events_total{type}` | counter | event throughput by type |
| `xsypher_alerts_total{rule,severity}` | counter | detections; the primary alerting signal |
| `xsypher_mitigations_total{action}` | counter | enforcement actions actually delivered |
| `xsypher_active_tracked_processes` | gauge | lineage graph occupancy, a proxy for memory |
| `xsypher_rule_cooldowns_active` | gauge | sustained suppression, i.e. a repeated subject such as a fork loop |
| `xsypher_lsm_blocks_seen{type}` | counter | kernel denials; proves enforcement is live rather than merely configured |
| `xsypher_ringbuf_frames_dropped` | gauge | frames the collector could not forward to the engine |
| `xsypher_commands_sent_total{command}` | counter | policy commands accepted by the collector |
| `xsypher_commands_failed_total{reason}` | counter | policy commands that did not reach the collector |
| `xsypher_socket_reconnects_total` | counter | collector restarts or socket interruptions |
| `xsypher_rule_eval_seconds` | summary | evaluation latency (`_sum`, `_count`) |
| `xsypher_engine_uptime_seconds` | gauge | process age |

```console
$ curl -s localhost:9109/metrics | grep -E '^xsypher_(alerts|mitigations|lsm)_'
xsypher_alerts_total{rule="MCP_SHELL_BREAKOUT",severity="critical"} 1
xsypher_lsm_blocks_seen{type="lsm_block"} 7
xsypher_mitigations_total{action="quarantine_cgroup"} 1
```

### Carding the exporter

- Bind to `127.0.0.1` (`--metrics-host`) when Prometheus runs on the same node.
- The endpoint exposes no secrets: series names and labels only. Process names do not appear as
  labels, so cardinality is bounded by the rule set.

---

## Alerting

```yaml
groups:
  - name: xsypher
    rules:
      - alert: XsypherEnforcementBlind
        expr: increase(xsypher_commands_failed_total[5m]) > 0
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: Policy commands are not reaching the collector
          runbook: https://github.com/anwariqbaldawar/Zero-Trust-Kernel-Log-Streamer/blob/main/docs/OPERATIONS.md#troubleshooting

      - alert: XsypherSensorSilent
        expr: rate(xsypher_events_total[10m]) == 0
        for: 15m
        labels: { severity: critical }
        annotations:
          summary: No kernel telemetry for 15 minutes; the sensor is detached or stopped

      - alert: XsypherAlertBurst
        expr: sum(rate(xsypher_alerts_total[5m])) > 5
        for: 10m
        labels: { severity: critical }
        annotations:
          summary: Sustained breakout attempts across the fleet

      - alert: XsypherLineagePressure
        expr: xsypher_active_tracked_processes > 150000
        for: 15m
        labels: { severity: warning }
        annotations:
          summary: Lineage graph near its limit; raise --max-tracked or investigate a fork storm
```

`XsypherSensorSilent` and `XsypherEnforcementBlind` are the two that matter: they distinguish "nothing
is happening" from "we are not watching".

---

## Audit log

Default path `/var/log/xsypher-alerts.jsonl`, one JSON object per line, append-only.

Each record commits to the hash of the previous one:

```
hash_n = SHA256( hex(hash_{n-1}) || canonical_json(record_n excluding "hash" and "alert_id") )
hash_0 = "0" * 64
```

```json
{
  "schema": "xsypher.alert.v2",
  "alert_id": "5f26e3f956c98122",
  "sequence": 0,
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "hash": "5f26e3f956c98122995f6a9f5f6ea9529a6790a484fcb803c736f5d39807e026",
  "timestamp": "2026-10-26T16:24:16.647876388Z",
  "rule": "MCP_SHELL_BREAKOUT",
  "severity": "critical",
  "reason": "exe=sh container=26101d6e040e",
  "subject": { "pid": 2413, "tgid": 2413, "comm": "sh", "uid": 1000,
               "cgroup_id": 40961, "container_id": "26101d6e040e5825...",
               "mnt_ns_id": 4026531840, "pid_ns_id": 4026531836 },
  "event": { "type": "execve", "filename": "/bin/sh",
             "args": "-c 'curl http://169.254.169.254/latest/meta-data/iam/'" },
  "ancestry": ["python3", "mcp-server"],
  "mitigations": [ { "action": "quarantine_cgroup", "command": "quarantine_cgroup",
                     "target": 40961, "delivered": true } ],
  "enforced": true
}
```

Verify a log at any time, including after shipping or restoring it:

```console
$ PYTHONPATH=src python3 -c "from engine.mitigator import AlertLog; \
print(AlertLog.verify('/var/log/xsypher-alerts.jsonl'))"
(True, 8, None)
```

The engine re-verifies on startup and logs `audit hash chain is INVALID: line N: ...` if a record was
altered. Editing or deleting a line invalidates every later hash. Run one engine per log path; two
writers will produce a chain that fails verification.

**Shipping.** Use your existing agent (Vector, Fluent Bit, Filebeat, journald-forward). Keep `hash` and
`prev_hash` in the shipped payload so consumers can verify independently. Since the file is the system
of record for enforcement decisions, prefer `--fsync-alerts` where throughput allows.

**Data handling.** Records contain process command lines, file paths and namespace identifiers, which
may include usernames, internal hostnames or customer data. Treat the file as confidential, apply the
standard retention policy for security telemetry, and restrict read access. The systemd unit sets
`LogsDirectory=xsypher` and the engine runs as the `xsypher` user.

---

## Capacity planning

Measured on a 2 vCPU sandbox (Debian 12, g++ 12, CPython 3.11), 10,016 events:

| Property | Value |
|---|---|
| Rule evaluation, p50 | 6.2 µs |
| Rule evaluation, p95 | 8.3 to 11.7 µs |
| Rule evaluation, p99 | 14.8 to 17.3 µs |
| Rule evaluation budget | 500 µs per event |
| Engine throughput, in-process | 136,000 to 151,000 events/s |
| Engine throughput, end to end (encode, socket, decode, rules, audit) | 34,000 to 38,000 events/s |
| Detection to kernel map update | 2.1 to 3.8 ms |
| Ring buffer | 16 MiB, roughly 10,000 queued records before drops |
| Collector resident memory | ~10 MB plus libbpf accounting |
| Engine resident memory | ~60 MB at 200,000 tracked processes |

Deployment shape:

- one collector per node; it is per-kernel and cannot be shared across hosts
- one engine per node, or one engine per group of nodes if it can reach each collector's socket
- size the engine for peak `xsypher_events_total`, leaving headroom for the audit `fsync` if enabled

When `drops` is non-zero and sustained, in order of preference: narrow the `openat` filter in
`src/bpf/xsypher.bpf.c`, reduce the number of rules that need ancestry resolution, then increase CPU.

---

## Upgrade and rollback

1. Stop the engine: `systemctl stop xsypher-engine`. It emits `UNQUARANTINE_*` for every entry it
   installed, so the node is not left locked down.
2. Replace the collector binary and restart it. Policy maps are recreated empty.
3. Start the new engine. It prints the enforcement mode after connecting.

A wire ABI change requires both components to move together. A mismatch is rejected at the frame
level with a logged reason (`unsupported ABI version N`), never misinterpreted. Rollback is the same
sequence with the previous binaries.

Kubernetes: the DaemonSet uses `RollingUpdate` with `maxUnavailable: 10%` and a `PodDisruptionBudget`,
so sensor coverage is maintained during the rollout. Both containers in a pod are replaced together,
which keeps the ABI consistent.

---

## Uninstall

```bash
sudo systemctl disable --now xsypher-engine xsypher-collector
sudo rm -f /usr/lib/systemd/system/xsypher-collector.service \
           /usr/lib/systemd/system/xsypher-engine.service
sudo rm -rf /usr/local/lib/xsypher /etc/xsypher
sudo rm -f /usr/local/bin/xsypher-collector /run/xsypher/stream.sock
sudo systemctl daemon-reload
```

Retain `/var/log/xsypher/alerts.jsonl` according to your retention policy. No BPF objects are pinned,
so stopping the collector detaches all programs and frees the maps.

---

## Troubleshooting

| Symptom | Cause | Resolution |
|---|---|---|
| `WARNING: BPF-LSM unavailable (...) continuing in telemetry-only mode` | Kernel rejected the LSM programs: `CONFIG_BPF_LSM` disabled, or `lsm=bpf` missing from the command line | Enable both and reboot, or accept telemetry-only mode and add `--active-kill` |
| `xsypher_bpf__load failed: ... EPERM` | Insufficient privilege or `RLIMIT_MEMLOCK` | Run as root or grant `CAP_BPF` + `CAP_PERFMON`; the unit sets `LimitMEMLOCK=infinity` |
| `cannot bind /run/xsypher/stream.sock (Permission denied)` | `/run` not writable by the launching user | `install -d -m 0750 /run/xsypher`, or let the collector fall back to `/tmp` |
| `unable to connect to collector socket` | Engine started before the collector, or wrong path | Start the collector first; the engine retries once per second and logs reconnects |
| Alerts logged but nothing blocked | Engine started without `--enforce-kernel`, or LSM inactive | Restart with the flag; confirm `xsypher_lsm_blocks_seen` increases |
| `audit hash chain is INVALID` | Log edited or truncated, or two engines writing one file | Restore from backup; run one engine per log path |
| `no usable kernel BTF found` | Host lacks BTF and `bpftool` | Install `linux-image-$(uname -r)-dbg` or `bpftool`, then `FORCE=1 ./scripts/gen_vmlinux.sh` |
| `bpftool: command not found` at build time | `linux-tools` package missing | `apt-get install bpftool` or `linux-tools-$(uname -r)` |
| High event volume from one host | `openat` filter too permissive for the workload | Narrow `is_writable_staging_path()` in `xsypher.bpf.c`, or add rule conditions |
| `drops` rising in the status line | Ring buffer overflow; engine cannot keep up | Narrow kernel-side filtering, reduce ancestry-heavy rules, add CPU |

Log locations: collector to stderr (journald or container runtime), engine to stdout, audit records to
the configured JSONL path.
