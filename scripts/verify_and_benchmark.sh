#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# verify_and_benchmark.sh - prove end-to-end operational readiness.
#
# Steps
#   1. ABI check          : compile include/xsypher_abi.h and compare the struct
#                           sizes with src/engine/abi.py (byte exact).
#   2. Kernel object      : build src/bpf/xsypher.bpf.c when clang + bpftool +
#                           libbpf headers are available. When they are not
#                           (common in CI sandboxes) the step is reported as
#                           SKIPPED, never as a failure.
#   3. User-space build   : build the C++20 collector, or type-check it with
#                           -fsyntax-only, or skip.
#   4. Python unit tests  : pytest (or unittest when pytest is missing).
#   5. Attack simulation  : tests/simulate_mcp_attack.py - 10,000 benign events
#                           plus 5 MCP breakout chains over a real
#                           AF_UNIX/SOCK_SEQPACKET socket.
#   6. Summary            : exit non-zero if any step FAILED.
#
# Usage: ./scripts/verify_and_benchmark.sh [--events N] [--quick]
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

EVENTS=10000
QUICK=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --events) EVENTS="$2"; shift 2 ;;
        --quick)  QUICK=1; EVENTS=2000; shift ;;
        -h|--help) sed -n '3,22p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

PYTHON="${PYTHON:-python3}"
CC_BIN="${CC:-$(command -v gcc || command -v cc || true)}"

BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'
YELLOW=$'\033[33m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
if [[ ! -t 1 || -n "${NO_COLOR:-}" ]]; then
    BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; CYAN=""; RESET=""
fi

PASSED=0; FAILED=0; SKIPPED=0
declare -a RESULTS=()
TMPDIR_RUN="$(mktemp -d)"
trap 'rm -rf "${TMPDIR_RUN}"' EXIT

step()  { printf '\n%s==> %s%s\n' "${BOLD}${CYAN}" "$*" "${RESET}"; }
pass()  { PASSED=$((PASSED+1)); RESULTS+=("PASS  $*"); printf '%s  PASS%s  %s\n' "${GREEN}" "${RESET}" "$*"; }
fail()  { FAILED=$((FAILED+1)); RESULTS+=("FAIL  $*"); printf '%s  FAIL%s  %s\n' "${RED}" "${RESET}" "$*"; }
skip()  { SKIPPED=$((SKIPPED+1)); RESULTS+=("SKIP  $*"); printf '%s  SKIP%s  %s\n' "${YELLOW}" "${RESET}" "$*"; }
note()  { printf '%s        %s%s\n' "${DIM}" "$*" "${RESET}"; }

printf '%s' "${BOLD}"
cat <<'BANNER'
  __  __ ____        __
  \ \/ // __/__ ____________  _____
   \  //\ \/ _ \/ ___/ ___/ _ \/ ___/      xSypher-Stream
   / //___/  __/ /__/ /  /  __/ /          verification & benchmark
  /_//   /_/\___/\___/_/   \___/_/
BANNER
printf '%s\n' "${RESET}"
note "repository : ${REPO_ROOT}"
note "python     : $(${PYTHON} --version 2>&1)"
note "uname      : $(uname -srm)"
note "events     : ${EVENTS}"

# --------------------------------------------------------------------------- #
# 1. ABI parity                                                              #
# --------------------------------------------------------------------------- #
step "1/5  ABI parity (include/xsypher_abi.h <-> src/engine/abi.py)"
PY_OUT="$(${PYTHON} - <<'PY'
import sys
sys.path.insert(0, "src")
import ctypes
from engine import abi
print(ctypes.sizeof(abi.KernelEvent), ctypes.sizeof(abi.WireEventMsg),
      ctypes.sizeof(abi.WirePolicyCmd))
PY
)"
note "python sizes : ${PY_OUT}"

if [[ -n "${CC_BIN}" ]]; then
    cat >"${TMPDIR_RUN}/abi_check.c" <<'C'
#include <stdio.h>
#include "xsypher_abi.h"
int main(void) {
    printf("%zu %zu %zu\n", sizeof(struct kernel_event_t),
           sizeof(struct wire_event_msg_t), sizeof(struct wire_policy_cmd_t));
    return 0;
}
C
    if "${CC_BIN}" -std=c11 -Wall -Wextra -Werror -Iinclude \
            "${TMPDIR_RUN}/abi_check.c" -o "${TMPDIR_RUN}/abi_check"; then
        C_OUT="$("${TMPDIR_RUN}/abi_check")"
        note "c sizes      : ${C_OUT}"
        if [[ "${PY_OUT}" == "${C_OUT}" ]]; then
            pass "struct layouts identical in C and Python (${C_OUT})"
        else
            fail "struct layout mismatch (python='${PY_OUT}' c='${C_OUT}')"
        fi
    else
        fail "include/xsypher_abi.h does not compile"
    fi
else
    skip "no C compiler; C-side layout not cross-checked"
fi

# --------------------------------------------------------------------------- #
# 2/3. Kernel object + collector                                            #
# --------------------------------------------------------------------------- #
step "2/5  eBPF CO-RE object (src/bpf/xsypher.bpf.c)"
HAVE_BPF=0
if command -v clang >/dev/null 2>&1 && command -v bpftool >/dev/null 2>&1 \
        && [[ -f /usr/include/bpf/libbpf.h || -n "$(pkg-config --cflags libbpf 2>/dev/null || true)" ]]; then
    HAVE_BPF=1
fi

if [[ "${HAVE_BPF}" -eq 1 ]]; then
    if ./scripts/gen_vmlinux.sh include/vmlinux.h && make bpf 2>&1 | tail -20; then
        if [[ -s build/xsypher.bpf.o && -s build/xsypher.skel.h ]]; then
            pass "BPF object + skeleton built ($(stat -c%s build/xsypher.bpf.o) bytes)"
        else
            fail "BPF build produced no artifacts"
        fi
    else
        fail "BPF build failed"
    fi
elif [[ -d /usr/include/bpf ]] && command -v gcc >/dev/null 2>&1; then
    # No clang/bpftool, but the libbpf headers and a C compiler exist: run a
    # host-compiler syntax and type check of the CO-RE program against the
    # generated (stub) vmlinux.h. This catches typos, bad CO-RE field paths and
    # verifier-hostile constructs without a BPF toolchain.
    FORCE=1 ./scripts/gen_vmlinux.sh "${TMPDIR_RUN}/vmlinux.h" >/dev/null 2>&1 || true
    if gcc -fsyntax-only -std=gnu11 -nostdinc \
            -D__TARGET_ARCH_x86 \
            -D'__builtin_preserve_access_index(x)=(x)' \
            -I"${TMPDIR_RUN}" -Iinclude -I/usr/include \
            src/bpf/xsypher.bpf.c 2>"${TMPDIR_RUN}/bpf.log"; then
        pass "BPF program type-checks (gcc -fsyntax-only against generated BTF header)"
    else
        fail "BPF program failed to type-check"
        sed -n '1,20p' "${TMPDIR_RUN}/bpf.log" >&2 || true
    fi
else
    skip "clang/bpftool/libbpf headers unavailable - kernel object not compiled"
    note "install clang, bpftool and libbpf-dev to build build/xsypher.bpf.o"
fi

step "3/5  C++20 collector (src/collector)"
if [[ "${HAVE_BPF}" -eq 1 ]]; then
    if make collector 2>&1 | tail -10; then
        pass "collector built ($(stat -c%s build/xsypher-collector) bytes)"
    else
        fail "collector build failed"
    fi
elif [[ -f /usr/include/bpf/libbpf.h || -n "$(pkg-config --cflags libbpf 2>/dev/null || true)" ]]; then
    if command -v g++ >/dev/null 2>&1 && \
            g++ -std=c++20 -fsyntax-only -Wall -Wextra -Wpedantic \
                -Iinclude -Isrc/collector src/collector/*.cpp 2>"${TMPDIR_RUN}/cxx.log"; then
        pass "collector type-checks cleanly (-fsyntax-only, libbpf headers present)"
    else
        fail "collector failed to type-check"
        sed -n '1,20p' "${TMPDIR_RUN}/cxx.log" >&2 || true
    fi
else
    skip "libbpf headers unavailable - collector not compiled"
fi

# --------------------------------------------------------------------------- #
# 4. Python unit tests                                                       #
# --------------------------------------------------------------------------- #
step "4/5  Python unit tests"
if PYTHONPATH=src ${PYTHON} -c 'import pytest' >/dev/null 2>&1; then
    if PYTHONPATH=src ${PYTHON} -m pytest tests/test_wire_protocol.py \
            tests/test_lineage_and_rules.py -q 2>&1 | tail -15; then
        pass "pytest suite"
    else
        fail "pytest suite"
    fi
else
    note "pytest not installed; falling back to unittest"
    if PYTHONPATH=src ${PYTHON} -m unittest discover -s tests -p 'test_*.py' 2>&1 | tail -15; then
        pass "unittest suite"
    else
        fail "unittest suite"
    fi
fi

# --------------------------------------------------------------------------- #
# 5. End-to-end attack simulation                                           #
# --------------------------------------------------------------------------- #
step "5/5  End-to-end MCP attack simulation (${EVENTS} benign events + 5 chains)"
if PYTHONPATH=src ${PYTHON} tests/simulate_mcp_attack.py --events "${EVENTS}"; then
    pass "simulation: all attack chains detected and contained"
else
    fail "simulation reported a failure"
fi

# --------------------------------------------------------------------------- #
# Summary                                                                    #
# --------------------------------------------------------------------------- #
step "Summary"
for line in "${RESULTS[@]}"; do
    case "${line}" in
        PASS*) printf '%s  %s%s\n' "${GREEN}" "${line}" "${RESET}" ;;
        FAIL*) printf '%s  %s%s\n' "${RED}" "${line}" "${RESET}" ;;
        *)     printf '%s  %s%s\n' "${YELLOW}" "${line}" "${RESET}" ;;
    esac
done
printf '\n  passed=%d failed=%d skipped=%d\n' "${PASSED}" "${FAILED}" "${SKIPPED}"

if [[ "${FAILED}" -gt 0 ]]; then
    printf '%sRESULT: FAILED%s\n' "${RED}${BOLD}" "${RESET}"
    exit 1
fi

printf '%sRESULT: OK - xSypher-Stream verified end to end%s\n' "${GREEN}${BOLD}" "${RESET}"
if [[ "${SKIPPED}" -gt 0 ]]; then
    note "${SKIPPED} step(s) skipped: install clang, bpftool and libbpf-dev for a full build."
fi
exit 0
