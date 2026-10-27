# Contributing to xSypher-Stream

Thanks for helping. This project sits on a syscall hot path, so the bar is "provably correct", not
"works on my machine". Three rules cover almost everything:

1. **The ABI is a contract.** `include/xsypher_abi.h` and `src/engine/abi.py` must stay byte
   identical, forever.
2. **The kernel never waits for user space.** No design that makes a tracepoint or LSM hook block on
   the engine.
3. **Every change ships with a test that fails without it.**

---

## Development setup

```bash
git clone https://github.com/anwariqbaldawar/Zero-Trust-Kernel-Log-Streamer.git
cd Zero-Trust-Kernel-Log-Streamer

pip install -r requirements.txt pytest
make check-deps                     # clang / g++ / bpftool
make -j"$(nproc)"                   # BPF object + skeleton + collector
make test                           # 59 tests
./scripts/verify_and_benchmark.sh   # full verification + benchmarks
```

No root, no kernel access? Everything except the privileged collector runs in `--simulate` mode:

```bash
PYTHONPATH=src python3 -m engine.main --simulate --metrics-port 9109
PYTHONPATH=src python3 tests/simulate_mcp_attack.py --events 2000
```

---

## Repository map

| Path | Language | What belongs here |
|---|---|---|
| `include/xsypher_abi.h` | C | wire structs, constants, compile-time layout asserts |
| `src/bpf/xsypher.bpf.c` | restricted C | tracepoints, LSM hooks, maps, verifier-safe helpers |
| `src/collector/` | C++20 | libbpf lifecycle, ring buffer, enrichment, UDS server |
| `src/engine/` | Python 3.12 | decode, lineage, rules, mitigation, metrics, TUI |
| `config/rules.yaml` | YAML | detection content; most contributions land here |
| `tests/` | Python | unit + end-to-end proof |
| `deploy/`, `scripts/` | YAML/sh/Python | packaging, verification and asset generators |
| `docs/` | Markdown/SVG | reference documents and hand-written figures |
| `assets/` | SVG/GIF | logo, banner, social preview, demo GIF |

### Generated assets

Three scripts own everything visual, and each is committed next to its output, so no asset is hand-edited:

| Command | Writes | Needs |
|---|---|---|
| `make demo` | `assets/demo-session.txt`, `assets/demo.gif` | python3, PyYAML, Pillow |
| `make brand` | `assets/logo-*.svg`, `assets/banner.svg`, `assets/social-preview.svg` | python3 (add `PNG=1` for PNG siblings, needs resvg-py or rsvg-convert) |
| `make check-docs` | nothing; verifies figures, links, anchors and style | python3 |

`make demo` is two real runs captured through a pseudo terminal, so the GIF shows bytes the program actually
wrote. Never edit the GIF or the transcript by hand.

---

## Authoring a detection rule

Prefer rules over code: a new detection is usually a `config/rules.yaml` entry plus a test.

```yaml
- id: MY_DETECTION                # SCREAMING_SNAKE_CASE, stable forever
  title: "one line, present tense"
  severity: high                  # info | low | medium | high | critical
  description: >-
    What is happening, why it is malicious, and which benign case it must not catch.
  enabled: true
  event_types: [execve]           # execve connect openat memfd_create process_exit lsm_block
  conditions:
    exe_in: [some-binary]
    ancestor_has_ai_runtime: true
    ancestor_min_depth: 1
  actions: [quarantine_pid, kill]
  tags: [mcp, exfiltration]
```

Checklist before opening a PR:

- [ ] `id` is unique and describes the *behaviour*, not the tool version.
- [ ] At least one **positive** test (rule fires) and one **negative** test (benign traffic stays
      quiet) in `tests/test_lineage_and_rules.py`.
- [ ] Every `actions:` entry is one of `quarantine_pid`, `quarantine_cgroup`, `block_ipv4`,
      `block_imds`, `kill`.
- [ ] If the rule can block a legitimate workload, justify it in `description:` and consider
      `monitor_only: true` for the first release.
- [ ] The rule loads: `PYTHONPATH=src python3 -c "from engine.rule_engine import RuleEngine; \
      RuleEngine.from_file('config/rules.yaml')"`.
- [ ] If you also updated the copy in `deploy/kubernetes-daemonset.yaml`, keep both in sync.

Rules are matched against `exe` (lineage-resolved basename for non-exec events), `comm`, `filename`,
`args`, destination address/port, uid and the ancestry chain. Remember that **ports and addresses are
in network byte order on the wire**. The engine already presents them in host form, but anything you
write in C or C++ must use the raw constants (see `XSYPHER_IMDS_IPV4_RAW`).

---

## Changing the binary ABI

Any change to a struct, constant or enum is a **breaking change** and requires all of:

1. Bump `XSYPHER_ABI_VERSION` in `include/xsypher_abi.h` **and** `src/engine/abi.py`.
2. Mirror the change in `src/engine/abi.py` (fields, explicit padding, offsets).
3. Update the `XSYPHER_STATIC_ASSERT` block in C and the `assert`/offset map in Python.
4. Update the expected sizes/offsets in `tests/test_wire_protocol.py` (the sizes are literal
   integers on purpose, and that is what forces this review).
5. Update the structure and constant tables in `docs/ARCHITECTURE.md` if sizes or offsets changed.
6. Add a note to `CHANGELOG`-style section of the PR description describing the migration for any
   engine/collector that may be deployed out of step.

Never "fix" a layout by relying on compiler padding: order fields, add explicit reserved members, and
keep the structures `packed, aligned(8)`.

---

## Kernel-program rules (`src/bpf/`)

The verifier is the reviewer that matters. Keep changes verifier-friendly:

- bounded, preferably `#pragma unroll`ed loops with constant trip counts;
- no direct dereference of user or kernel pointers; always `bpf_probe_read_user*` /
  `BPF_CORE_READ*`;
- `BPF_CORE_READ` for every `task_struct`/`file`/`sock` field so CO-RE keeps working across kernels;
- reserve → fill → submit; never submit a partially filled ring buffer record;
- check every helper return value; count failures in `metrics_map` instead of retrying;
- keep the LSM hooks early-exit: `ret != 0` → return, not enforcing → return 0.

Test locally without a full toolchain:

```bash
FORCE=1 ./scripts/gen_vmlinux.sh /tmp/vmlinux.h
gcc -fsyntax-only -std=gnu11 -nostdinc -D__TARGET_ARCH_x86 \
    -D'__builtin_preserve_access_index(x)=(x)' -I/tmp -Iinclude -I/usr/include \
    src/bpf/xsypher.bpf.c
```

…and with the real toolchain before requesting review: `make bpf && sudo ./build/xsypher-collector --verbose`.

---

## Style

| Language | Rules |
|---|---|
| C (BPF) | kernel style: tabs, `__always_inline` helpers, no libc, comment every non-obvious verifier constraint |
| C++20 | 4-space indent, `snake_case` functions, `PascalCase` types, RAII only (no owning raw pointers), `-Wall -Wextra -Wpedantic` clean |
| Python | 4 spaces, `from __future__ import annotations`, type hints on public functions, `slots=True` dataclasses on hot paths, **stdlib first** (PyYAML is the only third-party runtime dependency) |
| YAML | 2 spaces; `id`, `title`, `severity`, `event_types`, `conditions`, `actions` in that order |

Keep comments about *why*, not *what*. Docstrings should state the invariant being protected.

---

## Diagrams

Figures are hand-written SVG in `docs/`, one file per figure, no external assets and no animation. They are
read at 1120 px wide and stay legible in print, so the canvas width is fixed and type never goes below
10 px. Adding a figure means:

1. Write `docs/fig-<name>.svg` with an explicit `viewBox`, a `<title>`, a `<desc>`, and a class-based
   `<style>` block. No `<image>` tags, no embedded fonts, no CDN references, no `<animate>`.
2. Run `python3 scripts/audit_svg.py docs/fig-<name>.svg`. It estimates text width from font metrics and
   fails a label that leaves its box or the canvas. Fix the layout, not the checker.
3. Run `python3 scripts/preview_svg.py docs/fig-<name>.svg /tmp/fig.png` to eyeball it, since no SVG
   renderer is required to build the project. The previewer implements only the element subset the figures
   use: rect, line, circle, path, text, tspans, classes and rotation.
4. Embed it with one image line and one italic caption line that states the claim the figure supports:

   ```markdown
   ![what it shows](docs/fig-name.svg)

   *What the reader should conclude from it.*
   ```

   A figure without a caption is decoration and will be rejected.
5. Run `make check-docs`. It fails a figure that no document embeds, a broken link or anchor, an unbalanced
   code fence, an em dash or an emoji.

Numbers inside a figure must come from the code or from a real run, the same rule as the prose.

---

## Commits and pull requests

Conventional Commits, one logical change per commit:

```
feat(engine): add MCP tool-name allowlist condition
fix(bpf): bound argv copy loop for the verifier
docs(rules): explain cooldown interaction with fork loops
test(abi): assert wire_policy_cmd_t tail padding
```

A PR should contain:

- a one-paragraph **why**, and the **threat model** impact,
- the exact commands you ran and their output (`make test`, `./scripts/verify_and_benchmark.sh`),
- for enforcement changes: what happens on a kernel *without* BPF-LSM,
- for rule changes: the positive **and** negative test cases,
- no `TODO`, no dead code, no commented-out blocks, no new runtime dependencies without discussion.

CI must be green. Maintainers may ask for a CHANGELOG entry and a README update for user-visible
behaviour. See `.github/PULL_REQUEST_TEMPLATE.md` for the checklist that is applied automatically.

---

## Code of conduct

Be precise, be kind, assume good faith. Harassment or disclosure of private vulnerability details in
public threads is not tolerated. Security reports go to [`SECURITY.md`](SECURITY.md), never a PR.

## Licence

By contributing you agree your work is licensed under Apache-2.0 for user space and GPL-2.0 for the
BPF object (kernel requirement).
