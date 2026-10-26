# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 2.x (ABI v2) | supported, security fixes |
| 1.x (ABI v1) | end of life |

## Reporting a vulnerability

**Do not open a public issue, discussion, or pull request for a security problem.**

Report privately through GitHub's [private vulnerability reporting][ghsa] on this repository
(*Security → Advisories → Report a vulnerability*). If that is unavailable, contact the maintainer
listed in the repository profile and ask for a secure channel before sharing details.

Please include:

- affected component (`src/bpf`, `src/collector`, `src/engine`, `deploy`, `scripts`) and version/commit,
- kernel version, architecture, and whether `CONFIG_BPF_LSM` is enabled,
- a reproduction (event sequence, rule document, or minimal harness),
- the impact you believe is achievable, especially any path that could cause
  **false enforcement** (blocking a legitimate workload) or **silent non-enforcement**.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement | 2 business days |
| Triage + severity (CVSS 3.1) | 5 business days |
| Fix or documented mitigation | 30 days for high/critical, 90 days for others |
| Coordinated disclosure | after a release containing the fix, credit on request |

## Scope

In scope: anything that breaks one of these invariants:

1. **Kernel safety.** A verifier rejection is a bug; a program that can be made to read out of bounds,
   infinite-loop, or leak kernel memory is critical.
2. **Trust boundary between collector and engine.** The collector is privileged; the engine is not.
   Any input from the engine that can make the collector do more than apply a validated 32-byte
   policy command (file writes, arbitrary BPF map writes, command execution) is critical.
3. **Audit integrity.** Any way to alter, truncate, or forge a record in the JSONL audit log
   *without* breaking the SHA-256 chain, or to make `AlertLog.verify()` return success for a
   modified log.
4. **Silent failure.** A configuration or kernel condition that disables enforcement while the
   system reports itself as enforcing.
5. **Rule bypass.** A realistic MCP/prompt-injection technique that defeats the shipped detections
   *and* is not already documented as a limitation in the README.

Out of scope:

- Attacks requiring an attacker who already has `CAP_SYS_ADMIN`/root on the host and can unload the
  sensor (documented non-goal: xSypher-Stream is a sensor, not an immutable boot chain).
- Denial of service through intended resource limits (e.g. flooding events until ring buffer drops are
  counted; drops are the designed back-pressure and are exported as a metric).
- Vulnerabilities in kernels, libbpf, or Python itself. Report those upstream.
- The synthetic simulator (`--simulate`) and test fixtures.

## Hardening baseline

Deployments should follow the shipped units and manifests: one privileged collector per node, an
unprivileged engine with `cap_drop: ALL` and `no-new-privileges`, a `0750` socket directory, alert log
shipping to append-only storage, and the Prometheus alerts listed in `docs/OPERATIONS.md` (notably
`xsypher_commands_failed_total` and `xsypher_events_total` stalls).

[ghsa]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability
