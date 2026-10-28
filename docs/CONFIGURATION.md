# Configuration reference

Complete option, environment variable and rule-schema reference. For why a rule is shaped the way it is,
see [DETECTIONS.md](DETECTIONS.md); for what each action does in the kernel, see
[ENFORCEMENT.md](ENFORCEMENT.md).

- [Collector options](#collector-options)
- [Engine options](#engine-options)
- [Environment variables](#environment-variables)
- [Exit codes](#exit-codes)
- [Rule schema](#rule-schema)
- [Condition reference](#condition-reference)
- [Actions](#actions)
- [Rule validation](#rule-validation)
- [Worked examples](#worked-examples)

---

## Collector options

`xsypher-collector` (defaults shown).

| Flag | Default | Description |
|---|---|---|
| `--socket-path <path>` | `/run/xsypher/stream.sock` | Socket to bind. If the path cannot be bound and the flag was not set explicitly, the collector retries `/tmp/xsypher-stream.sock` and logs the substitution. |
| `--enforce` | off | Initialise `config_map[0]` to `INLINE_BLOCK`. Without it the LSM hooks return 0. |
| `--block-imds` | off | Insert `169.254.169.254` into `blocked_ipv4_map` at startup, before any event is processed. |
| `--no-lsm-fallback` | off | Exit with an error if the LSM programs cannot be attached, instead of continuing in telemetry-only mode. |
| `--no-status` | off | Suppress the ten-second status line on stderr. |
| `--verbose` | off | Enable libbpf debug logging (LIBBPF_DEBUG). |
| `-h`, `--help` | | Usage. |
| `-V`, `--version` | | Supported wire ABI version. |

## Engine options

`python3 -m engine.main` (defaults shown).

| Flag | Default | Description |
|---|---|---|
| `--socket-path <path>` | `/run/xsypher/stream.sock` | Collector socket. |
| `--rules <path>` | `config/rules.yaml` | Rule document, YAML or JSON. |
| `--alert-log <path>` | `/var/log/xsypher-alerts.jsonl` | Hash-chained audit log. If the directory is not writable and the default was not overridden, the engine falls back to `/tmp/xsypher-alerts.jsonl` and warns. |
| `--metrics-host <addr>` | `0.0.0.0` | Prometheus exporter bind address. |
| `--metrics-port <port>` | `9109` | Prometheus exporter port; `0` selects an ephemeral port. |
| `--enforce-kernel` | off | Send `QUARANTINE_*` and `BLOCK_IPV4` commands to the collector. Without it the engine is audit-only. |
| `--active-kill` | off | Additionally send `SIGKILL` to the offending process from user space. |
| `--heartbeat-interval <seconds>` | `2.0` | How often the engine pushes a heartbeat command to the collector. A stale heartbeat is what enables fail-closed. |
| `--fail-closed-seconds <n>` | `0` | When set, the engine declares a failure window of `n` seconds; past it the kernel denies tracked AI lineages if heartbeats stop. `0` disables the declaration. |
| `--shutdown-token <token>` | unset | Authenticated token that lifts task_kill and bpf tamper protection. Required to stop a protected PID from user space. |
| `--simulate` | off | Synthetic event generator; requires no kernel access and no privileges. |
| `--simulate-count <n>` | `0` | Stop after `n` synthetic events; `0` runs indefinitely. |
| `--simulate-seed <n>` | `1337` | Seed for the synthetic generator. |
| `--lineage-ttl <seconds>` | `5.0` | How long an exited process remains resolvable for ancestry lookups. |
| `--max-tracked <n>` | `200000` | Lineage graph size limit; oldest entries are evicted first. |
| `--fsync-alerts` | off | `fsync` after every audit record. Costs throughput; use where the log is the system of record. |
| `--no-color` | off | Disable ANSI colour. Colour is also disabled when stdout is not a TTY or `NO_COLOR` is set. |
| `--quiet` | off | Print alerts only, not every telemetry line. |
| `--verbose` | off | Verbose diagnostics, including each policy command sent. |
| `--version` | | Engine version. |

## Environment variables

| Variable | Read by | Equivalent flag |
|---|---|---|
| `XSYPHER_SOCKET` | engine | `--socket-path` |
| `XSYPHER_RULES` | engine | `--rules` |
| `XSYPHER_ALERT_LOG` | engine | `--alert-log` |
| `NO_COLOR` | engine | `--no-color` |
| `PYTHONPATH` | engine | must include the directory that contains the `engine` package |

Command-line flags take precedence over environment variables.

## Exit codes

| Component | Code | Meaning |
|---|---|---|
| collector | 0 | Clean shutdown after `SIGINT`/`SIGTERM`; socket unlinked |
| collector | 1 | BPF object could not be loaded, or the socket could not be created |
| collector | 2 | Invalid command line |
| engine | 0 | Clean shutdown; installed policy released |
| engine | 1 | Rule document invalid, collector unreachable, or audit log directory unusable |
| engine | 2 | Invalid command line |
| engine | 130 | Interrupted before shutdown completed |

---

## Rule schema

```yaml
version: "2"

settings:
  max_ancestry_depth: 8      # ancestors inspected per event (default 8)
  cooldown_seconds: 5.0      # per (rule, pid) duplicate suppression (default 5.0)
  verify_chain_on_start: true

rules:
  - id: MCP_SHELL_BREAKOUT           # required, unique, stable
    title: "MCP/AI agent spawned an interactive shell"
    severity: critical               # required: info | low | medium | high | critical
    description: >-
      Free-form analyst context. Copied into the audit record.
    enabled: true                    # default true
    monitor_only: false              # default false; alert without enforcing
    event_types: [execve]            # execve connect openat memfd_create process_exit lsm_block
    conditions:
      exe_in: [sh, bash, zsh, dash, ksh, tmux, screen, dtach]
      ancestor_has_ai_runtime: true
      ancestor_min_depth: 1
    actions: [quarantine_cgroup, kill]
    tags: [mcp, prompt-injection, rce]
```

`version` is informational. `settings` values are defaults; the engine flags
`--lineage-ttl` and `--max-tracked` control the rest of the graph behaviour.

## Condition reference

A `conditions:` mapping is ANDed: every entry must hold. A list value is ORed internally: any element
matching is sufficient. `any_of:` takes a list of condition groups that are ORed with each other,
which is how one rule covers two structurally different shapes.

| Condition | Type | Matches |
|---|---|---|
| `event_types` | list | kernel event type |
| `exe_in` | list | subject executable basename |
| `exe_not_in` | list | subject executable basename is not in the list |
| `exe_prefix_in` | list | raw `filename` starts with a listed prefix |
| `exe_suffix_in` | list | raw `filename` ends with a listed suffix |
| `comm_in` / `comm_not_in` | list | 16-byte kernel `comm` |
| `path_prefix_in` | list | opened path starts with a listed prefix |
| `path_suffix_in` | list | opened path ends with a listed suffix |
| `path_contains` | list | opened path contains a listed substring |
| `args_contains` | list | joined `argv` contains a listed substring |
| `dport_in` | list of int | destination port, host order |
| `daddr_in` | list | destination IPv4 or IPv6 literal |
| `uid_in` / `uid_not_in` | list of int | subject uid |
| `container_only` | bool | only fire inside a non-host cgroup |
| `container_or_comm_in` | list | in a container, or comm in the list |
| `ancestor_has_ai_runtime` | bool | any ancestor is a known AI/MCP runtime |
| `ancestor_any_in` | list | any ancestor basename in the list |
| `ancestor_min_depth` | int | at least this many ancestors present |
| `monitor_only` | bool | alert without enforcing |
| `any_of` | list | OR of condition groups |

For non-exec events (`connect`, `openat`, `memfd_create`), `exe_in` is evaluated against the process
image recorded in the lineage graph, because `filename` refers to the resource, not the process. For
`execve` it is the basename of the executed path.

Recognised AI/MCP runtimes: `node`, `nodejs`, `deno`, `bun`, `python`, `python3` and versioned variants,
`uvicorn`, `gunicorn`, `hypercorn`, `fastapi`, `claude-mcp`, `mcp-server`, `mcp`, `npx`, `ollama`,
`llama-server`, `vllm`.

## Actions

| Action | Effect | Sent to |
|---|---|---|
| `quarantine_pid` | `CMD_QUARANTINE_PID` for the subject tgid | collector, then `quarantined_pids_map` |
| `quarantine_cgroup` | `CMD_QUARANTINE_CGROUP` for the subject cgroup | collector, then `quarantined_cgroups_map` |
| `block_ipv4` | `CMD_BLOCK_IPV4` for the destination address (falls back to the IMDS address if the event has none) | collector, then `blocked_ipv4_map` |
| `block_imds` | `CMD_BLOCK_IPV4` for `169.254.169.254` | collector, then `blocked_ipv4_map` |
| `kill` | `SIGKILL` to the subject tgid | user space; only with `--active-kill` |
| `protect` | `PROTECT_PID` for the subject tgid | collector map write; guards the pid against task_kill |
| `fail_closed` | `SET_FAIL_CLOSED` with the declared window | collector map write; enables kernel fail-closed |
| `shutdown_token` | `SET_SHUTDOWN_TOKEN` with the configured token | collector map write; lifts tamper protection |
| `register_inode` | `REGISTER_INODE` for a path resolved in user space | collector map write; binds an inode to the restricted set |

Enforcement requires `--enforce-kernel` on the engine and `INLINE_BLOCK` mode in `config_map`.

Identical commands are deduplicated: a cgroup already quarantined is not quarantined again, and the
audit record records the action with `delivered: false` when the engine is in audit mode.

## Rule validation

Loading fails, naming the offending rule, on any of:

- missing or duplicate `id`
- missing `actions`, or an action outside the table above
- an unknown `severity`
- an unknown condition key
- an unknown event type name
- `conditions` present but not a mapping, or `any_of` not a list of mappings
- an empty `rules` list, or no enabled rules after filtering

Both YAML and JSON documents are accepted. JSON needs no PyYAML:

```bash
PYTHONPATH=src python3 -m engine.main --rules /etc/xsypher/rules.json
```

Validate without starting the service:

```console
$ PYTHONPATH=src python3 - <<'PY'
from engine.rule_engine import RuleEngine
engine = RuleEngine.from_file("config/rules.yaml")
for rule in engine.rules:
    print(f"{rule.id:32} {rule.severity:9} {','.join(rule.actions)}")
PY
MCP_SHELL_BREAKOUT               critical  quarantine_cgroup,kill
MCP_RECON_OR_EXFIL_TOOL          high      quarantine_pid,kill
CLOUD_IMDS_CREDENTIAL_THEFT      critical  quarantine_cgroup,block_ipv4,kill
SENSITIVE_CREDENTIAL_HARVEST     critical  quarantine_pid,kill
FILELESS_MEMFD_EXECUTION         critical  quarantine_cgroup,kill
SUSPICIOUS_OUTBOUND_C2_PORT      high      quarantine_pid,block_ipv4,kill
```

---

## Worked examples

### Deny IMDS access for every container on the node

Keep the shipped rule, and start the collector with the pre-blocked address so the first attempt is
denied before the engine has seen anything:

```bash
xsypher-collector --block-imds --enforce
```

### Alert only, for a two-week trial

```bash
python3 -m engine.main --socket-path /run/xsypher/stream.sock   # no --enforce-kernel
```

The LSM hooks stay in audit mode; alerts, metrics and the audit log are produced as normal, and every
mitigation is recorded with `delivered: false`.

### Add a detection for a specific MCP server

```yaml
  - id: ACME_MCP_TOOL_SHELL
    title: "Acme MCP server spawned a shell"
    severity: critical
    event_types: [execve]
    conditions:
      exe_in: [sh, bash]
      ancestor_any_in: [acme-mcp-server, acme-agent-runtime]
      ancestor_min_depth: 1
    actions: [quarantine_cgroup, kill]
    tags: [acme, mcp]
```

### Narrow a noisy detection

If a build host legitimately writes to `/dev/shm`, keep the rule but exclude that cgroup by moving the
write-staging condition out of `FILELESS_MEMFD_EXECUTION` and handling it per workload, or restrict the
rule to execution only:

```yaml
    conditions:
      any_of:
        - event_types: [memfd_create]
        - exe_prefix_in: ["/memfd:", "/proc/self/fd/"]
```

### Run rules against a captured stream

`RuleEngine.evaluate_many()` and `LineageGraph` are usable without the collector, which is how the test
suite exercises the detection content:

```console
$ PYTHONPATH=src python3 - <<'PY'
from engine.abi import Event, EventType
from engine.lineage import LineageGraph
from engine.rule_engine import RuleEngine

rules = RuleEngine.from_file("config/rules.yaml")
graph = LineageGraph()

# the MCP server process, then a shell it spawned
graph.observe(Event(pid=100, tgid=100, ppid=1, comm="python3",
                    filename="/usr/bin/python3", event_type=EventType.EXECVE,
                    container_id="host"))
attack = Event(pid=120, tgid=120, ppid=100, comm="sh", filename="/bin/sh",
               event_type=EventType.EXECVE, container_id="host")
graph.observe(attack)

print([m.rule_id for m in rules.evaluate(attack, graph)])
PY
['MCP_SHELL_BREAKOUT']
```

The same event without the `python3` ancestor produces `[]`, which is the property the rule tests
assert.
