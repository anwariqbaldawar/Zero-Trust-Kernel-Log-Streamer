<!--
  xSypher-Stream PR template.
  Keep it short; reviewers care about the threat model and the proof.
-->

## What and why

<!-- One paragraph. What changes, and which attack/bug/operational gap it closes. -->

## Threat-model impact

- [ ] No change to kernel-visible behaviour
- [ ] Changes **detection** (rules / lineage conditions)
- [ ] Changes **enforcement** (BPF maps, LSM hooks, policy commands)
- [ ] Changes the **wire ABI** (requires an `XSYPHER_ABI_VERSION` bump — see CONTRIBUTING.md)

## How it was verified

```console
# paste the commands and their real output
$ make test
$ PYTHONPATH=src python3 tests/simulate_mcp_attack.py
$ ./scripts/verify_and_benchmark.sh
```

## Checklist

- [ ] `make test` passes (positive **and** negative case added for new detections)
- [ ] `./scripts/verify_and_benchmark.sh` passes
- [ ] `include/xsypher_abi.h` and `src/engine/abi.py` still agree byte for byte
      (sizes 640 / 720 / 32, offsets asserted in tests)
- [ ] No `TODO`, `FIXME`, dead code, commented-out blocks or debug prints
- [ ] No new runtime dependency (PyYAML remains the only non-stdlib package)
- [ ] Kernel-facing code: bounded loops, checked helper returns, no pointer dereferences
- [ ] A kernel **without** BPF-LSM still starts and reports `lsm=unavailable`
- [ ] Rule changes mirrored into `deploy/kubernetes-daemonset.yaml` when applicable
- [ ] Docs updated (`README.md`, `SECURITY.md`, `CONTRIBUTING.md`) if behaviour changed
- [ ] No secrets, tokens, hostnames or customer identifiers in code, logs, fixtures or screenshots

## Rollback

<!-- How does an operator disable or revert this change without redeploying the kernel object? -->
