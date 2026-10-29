#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail
exec > >(tee kernel-verifier.log) 2>&1
uname -a
grep -qw bpf /sys/kernel/security/lsm
test -r /sys/kernel/btf/vmlinux
# Never permit the developer stub to stand in for real kernel types.
bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
cmake -S . -B build-kernel -DCMAKE_BUILD_TYPE=Release
cmake --build build-kernel -j2
cc -Wall -Wextra -Werror -Ibuild-kernel tests/kernel_load.c -lbpf -lelf -lz -o build-kernel/kernel-load
build-kernel/kernel-load
printf 'PASS: all CO-RE programs loaded and attached without fallback\n'
