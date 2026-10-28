# syntax=docker/dockerfile:1.6
# SPDX-License-Identifier: Apache-2.0
#
# xSypher-Stream multi-stage image.
#
#   docker build -f deploy/Dockerfile -t xsypher-stream:2.0.0 .
#
# The build stage compiles the eBPF CO-RE object against the *host* kernel BTF
# (mounted read-only), the libbpf skeleton, and the C++20 collector.  Building
# inside an image without /sys/kernel/btf is possible but will fall back to
# scripts/gen_vmlinux.sh's stub header, which is only good for compile checks -
# always rebuild on a host that exposes real BTF before deploying.
#
# The same image serves both roles:
#   collector : docker run --privileged --pid=host ... -v /sys/kernel/btf:/sys/kernel/btf:ro
#   engine    : docker run ... <image> python3 -m engine.main --enforce-kernel

# --------------------------------------------------------------------------- #
# Stage 1: build                                                              #
# --------------------------------------------------------------------------- #
FROM debian:bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        clang llvm bpftool libbpf-dev libelf-dev zlib1g-dev \
        build-essential cmake make pkg-config ca-certificates \
        python3 python3-yaml \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy the whole tree; .dockerignore keeps build/ and caches out.
COPY . .

# Kernel BTF is required for a *real* CO-RE object.  /sys/kernel/btf is not
# available inside a normal `docker build`, so it is bind-mounted read-only.
RUN --mount=type=bind,source=/sys/kernel/btf,target=/sys/kernel/btf,ro \
    if [ -r /sys/kernel/btf/vmlinux ]; then \
        echo "using host BTF for vmlinux.h"; \
    else \
        echo "WARNING: host BTF not mounted; generating a stub vmlinux.h"; \
    fi \
 && ./scripts/gen_vmlinux.sh include/vmlinux.h \
 && make -j"$(nproc)" all \
 && make check-deps \
 && ls -l build/xsypher-collector build/xsypher.bpf.o build/xsypher.skel.h

# Sanity: verify the userspace ABI is byte identical on the build host.
RUN python3 - <<'PY'
import ctypes, sys
sys.path.insert(0, "/src/src")
from engine import abi
sizes = (ctypes.sizeof(abi.KernelEvent), ctypes.sizeof(abi.WireEventMsg),
         ctypes.sizeof(abi.WirePolicyCmd))
assert sizes == (656, 736, 32), sizes
print("abi ok:", sizes)
PY

# --------------------------------------------------------------------------- #
# Stage 2: runtime                                                            #
# --------------------------------------------------------------------------- #
FROM debian:bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONPATH=/opt/xsypher/src \
    PYTHONUNBUFFERED=1 \
    XSYPHER_RULES=/etc/xsypher/rules.yaml

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libbpf1 libelf1 zlib1g python3 python3-yaml tini \
 && rm -rf /var/lib/apt/lists/*

# Collector binary
COPY --from=builder /src/build/xsypher-collector /usr/local/bin/xsypher-collector

# Python engine + rules
COPY --from=builder /src/src/engine /opt/xsypher/src/engine
COPY --from=builder /src/config/rules.yaml /etc/xsypher/rules.yaml

# Runtime directories: the socket lives on a volume so the engine sidecar can
# connect to it, and the audit log is appended to from the engine container.
RUN mkdir -p /run/xsypher /var/log \
 && chmod 0750 /run/xsypher

VOLUME ["/run/xsypher"]
EXPOSE 9109

# The container is unprivileged by default; the collector needs CAP_BPF +
# CAP_PERFMON (or --privileged) *and* cgroup/PID namespace visibility, which
# docker-compose.yml and the DaemonSet below provide.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/xsypher-collector"]
CMD ["--socket-path", "/run/xsypher/stream.sock", "--block-imds"]

LABEL org.opencontainers.image.title="xSypher-Stream" \
      org.opencontainers.image.description="Zero-trust kernel telemetry and inline LSM enforcement (eBPF CO-RE + C++20 + Python 3.12)" \
      org.opencontainers.image.version="2.0.0" \
      org.opencontainers.image.licenses="Apache-2.0"
