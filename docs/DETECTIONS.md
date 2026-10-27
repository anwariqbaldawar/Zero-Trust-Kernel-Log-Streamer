# Detection engineering

How the shipped rules are constructed, why each one is shaped the way it is, what they miss, and how to
change them without regressing coverage. Rule syntax and the full condition reference are in
[CONFIGURATION.md](CONFIGURATION.md).

---

## 1. Rule anatomy

```yaml
  - id: MCP_SHELL_BREAKOUT            # unique, stable, referenced in every audit record
    title: "MCP/AI agent spawned an interactive shell"
    severity: critical
    description: >-                   # copied verbatim into the audit record
      ...
    enabled: true
    monitor_only: false               # alert without enforcing
    event_types: [execve]             # selects the candidate index
    conditions:
      exe_in: [sh, bash, zsh, ...]    # ANDed with the entries below
      ancestor_has_ai_runtime: true
      ancestor_min_depth: 1
    actions: [quarantine_cgroup, kill]
    tags: [mcp, prompt-injection, rce]
```

Evaluation order for one event:

1. **Index.** Only rules whose `event_types` include this event type are candidates. A rule may list
   several, and `event_types` inside an `any_of` group also contributes to the index.
2. **Subject resolution.** For `execve`, the subject executable is the basename of `filename`. For
   `connect`, `openat`, `memfd_create` and `lsm_block`, `filename` is a resource, so the subject comes
   from the lineage node, falling back to `comm`.
3. **Ancestry.** Computed once per event, only if a candidate rule needs it. Depth is
   `settings.max_ancestry_depth`, default 8, nearest ancestor first.
4. **Base group.** Every key in `conditions` must hold. A list value is ORed internally.
5. **`any_of`.** If present, at least one group must also hold; the matching group index is recorded in
   the reason string as `variant=N`.
6. **Cooldown.** A per-`(rule, pid)` window, `settings.cooldown_seconds`, default 5 s.

Two properties keep the rule set cheap: the index means an `execve` never evaluates `connect` rules, and
ancestry is computed once rather than per rule.

---

![Detection coverage matrix of ten techniques against the six rules](fig-coverage.svg)

*Coverage per technique, with the four documented gaps and the change that closes each one.*

## 2. Rule catalogue

| Rule | Severity | Event types | Actions | ATT&CK |
|---|---|---|---|---|
| `MCP_SHELL_BREAKOUT` | critical | `execve` | quarantine cgroup, kill | T1059, T1059.004 |
| `MCP_RECON_OR_EXFIL_TOOL` | high | `execve` | quarantine pid, kill | T1046, T1041, T1105 |
| `CLOUD_IMDS_CREDENTIAL_THEFT` | critical | `connect`, `lsm_block` | quarantine cgroup, block IPv4, kill | T1552.005 |
| `SENSITIVE_CREDENTIAL_HARVEST` | critical | `openat` | quarantine pid, kill | T1003.008, T1552.001 |
| `FILELESS_MEMFD_EXECUTION` | critical | `memfd_create`, `execve` | quarantine cgroup, kill | T1620, T1027.009 |
| `SUSPICIOUS_OUTBOUND_C2_PORT` | high | `connect` | quarantine pid, block IPv4, kill | T1571, T1071 |

---

## 3. `MCP_SHELL_BREAKOUT`

**Signal.** `execve` of a shell or terminal multiplexer by a process whose ancestry contains an AI
runtime.

```yaml
      exe_in: [sh, bash, zsh, dash, ksh, fish, csh, tcsh,
               tmux, screen, dtach]
      ancestor_has_ai_runtime: true
      ancestor_min_depth: 1
```

**Why it works.** An MCP server is a long-running process launched from `node`, `python3`, `uvicorn`,
`deno`, `bun` or a wrapper such as `mcp-server` or `claude-mcp`. Legitimate tool implementations call
libraries, not shells. The ancestry condition is what makes the rule specific: `sh` alone is one of the
most common binaries on any host, and this rule fires on the tiny subset launched by an agent runtime.

`ancestor_min_depth: 1` guards against the case where the process itself is the AI runtime, for example a
`python3` that invoked `sh` through `os.system` from the server's own `argv[0]`. In that case the
ancestor chain is non-empty and the depth check holds, but a mislabelled node cannot match on an empty
chain.

**Runtime classification.** `AI_RUNTIME_BASENAMES` in `src/engine/lineage.py` is an exact set (`node`,
`nodejs`, `deno`, `bun`, `python`, `python3`, `python3.10` through `3.13`, `uvicorn`, `gunicorn`,
`hypercorn`, `fastapi`, `claude-mcp`, `mcp-server`, `mcp`, `npx`, `ollama`, `llama-server`, `vllm`) with
prefix handling for versioned interpreters (`python3.12`, `node18`) and for anything beginning with
`mcp`.

**False positives.**

| Case | Assessment | Response |
|---|---|---|
| A developer runs an interactive `python3` and types `bash` | matches, but the ancestor is a shell, not an agent, so the chain is usually `bash -> python3 -> bash`; the rule does fire | this is the largest FP source; deploy `monitor_only: true` for the first two weeks and review |
| A build tool invoked by a Node service shells out | matches | exclude the build cgroup by moving the rule to `ancestor_any_in` with an explicit agent list |
| A notebook server spawning shells on behalf of a human | matches | expected: a notebook is an agent runtime by any reasonable definition |

**Evasion.** `execve("/bin/sh")` with `argv[0]` set to something else still has `filename` `/bin/sh`, and
the rule matches on `filename`, not `argv`. Static binaries copied into the container are not in the shell
list; that is why `FILELESS_MEMFD_EXECUTION` and the credential rules exist as overlapping coverage.
`posix_spawn` of a non-shell interpreter (`perl`, `ruby`, `php`) does not match this rule.

**Tuning.** For a fleet where every workload is a Node service, replace `ancestor_has_ai_runtime` with
`ancestor_any_in: [mcp-server, claude-mcp, acme-agent]` to trade recall for precision.

---

## 4. `MCP_RECON_OR_EXFIL_TOOL`

**Signal.** Network, transfer or encoding tooling executed by a process with an AI-runtime ancestor.

```yaml
      exe_in: [curl, wget, nc, ncat, netcat, socat, nmap, masscan, ssh, scp,
               sftp, rsync, ftp, tftp, telnet, base64, xxd, od, chisel, ngrok]
      ancestor_has_ai_runtime: true
      ancestor_min_depth: 1
```

**Why it works.** An agent has no reason to launch `nmap` or `ngrok`. The list mixes three behaviours:
reach (`curl`, `wget`, `ssh`, `scp`, `rsync`, `ftp`, `tftp`, `telnet`), scan (`nmap`, `masscan`), and
exfiltrate or tunnel (`nc`, `socat`, `chisel`, `ngrok`, `base64`, `xxd`, `od`).

**Severity and actions.** High rather than critical, because a `curl` from an agent runtime is plausible
in a poorly designed tool, and the action set is `quarantine_pid` rather than the cgroup so a mislabelled
tool does not take down the whole server.

**False positives.** Health-check scripts that `curl` from inside a Node service, and image build steps
that run under a `node` base layer. Both are visible in baseline telemetry before enforcement is enabled.

**Evasion.** Python `urllib`, Node `fetch` and `http.client` make no exec, so nothing fires here; that is
what `SUSPICIOUS_OUTBOUND_C2_PORT` and `CLOUD_IMDS_CREDENTIAL_THEFT` cover at the `connect` layer.
Statistically encoded transfers inside an existing HTTPS session are invisible to a syscall sensor by
design.

---

## 5. `CLOUD_IMDS_CREDENTIAL_THEFT`

**Signal.** `connect` to `169.254.169.254` or `fd00:ec2::254` from a container, or the LSM block record
produced by a denied attempt.

```yaml
      event_types: [connect, lsm_block]
      daddr_in: ["169.254.169.254", "fd00:ec2::254"]
      container_only: true
```

**Why it works.** IMDSv1 answers any request from the instance without authentication. Nothing in a
normal container image has a legitimate reason to read it, and the address is fixed by the cloud
providers, so the rule needs no heuristics.

Including `lsm_block` in `event_types` means a denied attempt still produces an alert. Enforcement and
detection are the same signal.

**Why `container_only`.** Host daemons on some images do query metadata for region and instance identity.
The condition restricts the rule to events whose container id is not `host`.

**Actions.** `quarantine_cgroup` rather than pid, because the request is usually made by a short-lived
child; `block_ipv4` to cut further attempts from any process; `kill` for the immediate case. Note that
`block_ipv4` is node-wide (see [ENFORCEMENT.md](ENFORCEMENT.md)), which for a link-local metadata address
is exactly the desired blast radius.

**False positives.** Cloud-init and node bootstrap processes running inside a container; IAM-aware
sidecars that legitimately fetch instance identity documents. Both should be baselined by
`container_or_comm_in` exclusion or by running the rule in `monitor_only` for those workloads.

**Evasion.** `169.254.169.253` (the ECS task metadata endpoint is `169.254.170.2`) is a different
address and is not covered. IPv6 is detected after the fact, not denied in the hook.

---

## 6. `SENSITIVE_CREDENTIAL_HARVEST`

**Signal.** An `openat` of a credential path or secret file by a process outside the exclusion list.

```yaml
      exe_not_in: [sshd, login, sudo, su, passwd, chpasswd, systemd, unix_chkpwd,
                   polkitd, gdm, lightdm, cron, crond, kubelet]
      any_of:
        - path_prefix_in: ["/etc/shadow", "/etc/sudoers", "/etc/gshadow", "/root/.ssh",
                           "/var/run/secrets/kubernetes.io/serviceaccount/token", "/proc/kcore"]
        - path_suffix_in: [".env", ".pem", ".key"]
        - path_contains: ["id_rsa", "id_ed25519", "id_ecdsa", "credentials.json"]
```

**Why it works.** Only a short list of system binaries reads these paths as normal operation, and the
list is explicit rather than inferred, so the rule's intent is auditable. The three branches are an
`any_of`, because the shapes differ: absolute paths, file suffixes anywhere, and key-file names anywhere.

**False positives.** Backup agents, configuration management and secret-injection init containers. Add
them to `exe_not_in` after baselining, rather than widening the path list.

**Coverage interaction that matters.** The kernel `openat` filter runs before this rule. It emits an
`openat` record for a credential prefix, an `.env` suffix, or a write-like open under a staging
directory. A `.pem` or `.key` file outside those prefixes, or an `id_rsa` outside the captured prefixes,
is not emitted at all unless it is written into a staging directory, so those branches of the rule are
narrower than they read. The fix is a kernel-side change, not a rule change: extend
`is_sensitive_read_path()` in `src/bpf/xsypher.bpf.c` with the additional names and rebuild.

**Evasion.** `openat2` has its own tracepoint (`sys_enter_openat2`) and is not hooked here, so a
credential read through `openat2` produces no event and no alert. `open_by_handle_at` and direct `stat` of
metadata are likewise unhooked. A process that reads a secret through an already-open descriptor produces
no event.

---

## 7. `FILELESS_MEMFD_EXECUTION`

**Signal.** `memfd_create`, or execution from a memory-backed or shared-memory path.

```yaml
      event_types: [memfd_create, execve]
      any_of:
        - event_types: [memfd_create]
        - exe_prefix_in: ["/memfd:", "/proc/self/fd/", "/dev/shm/", "/run/shm/"]
```

**Why it works.** `memfd_create` is rare in normal workloads and is the standard way to stage an
executable without writing to disk: create the descriptor, write the ELF, `fexecve` it. Execution from
`/proc/self/fd/` is the alternative route, and `/dev/shm` is the common drop point. The rule needs no
ancestry condition, because none of these are normal behaviour for any process in a container.

The `any_of` split exists because the two branches need different preceding conditions: the first is
event-type-only, the second needs a path check on the executed file.

**Actions.** `quarantine_cgroup`, because a memfd payload is usually executed by a child of the process
that created it.

**False positives.** Browsers and some JIT runtimes use `memfd_create` for anonymous memory; JVM and
Chromium in particular. If a workload does, scope the rule with `container_or_comm_in` or exclude that
comm.

**Evasion.** `shm_open` backed by `/dev/shm` writes are captured by the `openat` filter only for
write-like opens under `/dev/shm`. An ELF mapped with `mmap` and executed through a JIT produces no
`execve` at all and is out of scope for a syscall-level sensor.

---

## 8. `SUSPICIOUS_OUTBOUND_C2_PORT`

**Signal.** An outbound connection to a well-known reverse-shell or C2 port from a container or a web or
agent worker.

```yaml
      dport_in: [4444, 1337, 31337, 5555, 6667, 9001]
      container_or_comm_in: [node, nodejs, python, python3, uvicorn, gunicorn,
                             nginx, httpd, apache2, php-fpm, java, ruby, deno, bun,
                             mcp-server, claude-mcp]
```

**Why it works.** `4444` is Metasploit's default handler port, `1337` and `31337` are convention, and
`6667` is IRC, all three of which are rarely used by production services. The `container_or_comm_in`
condition limits the alert to workloads where such a destination is implausible.

**Actions.** `quarantine_pid` and `block_ipv4`: the pid is precise, and the address block stops the whole
node from reaching a confirmed handler.

**False positives.** A test harness or a legitimate service that happens to use `9001` (Tor's default
SOCKS port) or `5555` (common in Android tooling and some RPC). Prefer `daddr_in` allowlisting over
removing the port.

**Evasion.** Any non-standard port defeats the rule entirely. This is port-blocklist detection: useful,
cheap, and never sufficient on its own. `MCP_RECON_OR_EXFIL_TOOL` covers the tooling, and the audit log
provides the evidence trail for whatever the port list misses.

---

## 9. Coverage summary

| Behaviour | Rule coverage | Kernel capture |
|---|---|---|
| Shell spawned by an agent | `MCP_SHELL_BREAKOUT` | `execve`, unfiltered |
| Recon or transfer tooling by an agent | `MCP_RECON_OR_EXFIL_TOOL` | `execve`, unfiltered |
| Metadata credential theft, IPv4 | `CLOUD_IMDS_CREDENTIAL_THEFT` | `connect` plus hook denial |
| Metadata credential theft, IPv6 | detected after the fact | `connect`, not hook-denied |
| Credential file read via `openat` | `SENSITIVE_CREDENTIAL_HARVEST` | filtered `openat` |
| Credential file read via `openat2` | no coverage | not hooked, `sys_enter_openat2` is a separate tracepoint |
| Credential file write in a quarantined domain | hook denial, reason 5 | `file_open` |
| `core_pattern` write (container escape) | captured, no rule | filtered `openat` |
| Fileless staging via `memfd` | `FILELESS_MEMFD_EXECUTION` | `memfd_create` |
| Execution from `/dev/shm` | `FILELESS_MEMFD_EXECUTION` | `execve`, unfiltered |
| Reverse shell on a known port | `SUSPICIOUS_OUTBOUND_C2_PORT` | `connect` |
| Reverse shell on an arbitrary port | no rule | `connect` (available for a new rule) |
| DNS tunnelling | no rule | not captured, resolver traffic is `AF_INET` to a normal address |
| Data encoded in a TLS upload | no rule | not visible at syscall level |

---

## 10. Adding a rule

1. Start in `monitor_only: true` and collect a week of alerts.
2. Classify each alert as true or false positive, and record the reason.
3. Narrow the rule, not the alert count: add `exe_not_in`, `ancestor_any_in` or `container_only` rather
   than deleting conditions.
4. Add both a positive test (the event you expect to fire) and a negative test (benign traffic that must
   stay quiet) to `tests/test_lineage_and_rules.py`. The existing rule tests do exactly this.
5. Remove `monitor_only` only after the negative test reproduces the baseline you observed.

Validation is enforced at load time, so a typo fails startup with the offending rule named. That is
preferable to a rule that silently never fires.
