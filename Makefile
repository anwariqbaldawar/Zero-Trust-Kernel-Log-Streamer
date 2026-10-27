# SPDX-License-Identifier: Apache-2.0
#
# xSypher-Stream build system.
#
# Targets
#   make            build the BPF object, its skeleton and the collector
#   make vmlinux    (re)generate include/vmlinux.h from kernel BTF
#   make bpf        build build/xsypher.bpf.o + build/xsypher.skel.h
#   make collector  build build/xsypher-collector
#   make test       run the Python unit test suite
#   make simulate   10k-event end-to-end MCP attack simulation
#   make verify     full verification (build + tests + simulation)
#   make check-docs check the documentation: figures, links, anchors, style
#   make run        run the collector (needs root + BPF-LSM for enforcement)
#   make engine     run the Python engine in the foreground
#   make clean      remove build artifacts
#   make install    install binaries/config (DESTDIR aware)
#
# Requirements
#   clang (>= 12), bpftool, libbpf-dev (>= 1.0), libelf-dev, zlib1g-dev,
#   g++ (>= 12), python3 (>= 3.10) with PyYAML.

SHELL      := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

ARCH       ?= $(shell uname -m)
BUILD      ?= build
PREFIX     ?= /usr/local
DESTDIR    ?=

ifeq ($(ARCH),x86_64)
  BPF_ARCH        := x86
  TARGET_ARCH     := x86
else ifeq ($(ARCH),amd64)
  BPF_ARCH        := x86
  TARGET_ARCH     := x86
else ifeq ($(ARCH),aarch64)
  BPF_ARCH        := arm64
  TARGET_ARCH     := arm64
else ifeq ($(ARCH),arm64)
  BPF_ARCH        := arm64
  TARGET_ARCH     := arm64
else
  $(error unsupported architecture '$(ARCH)': expected x86_64 or aarch64)
endif

CLANG      ?= $(shell command -v clang-18 2>/dev/null || command -v clang-17 2>/dev/null \
                || command -v clang-16 2>/dev/null || command -v clang-15 2>/dev/null \
                || command -v clang 2>/dev/null || echo clang)
CXX        ?= $(shell command -v g++ 2>/dev/null || command -v clang++ 2>/dev/null || echo g++)
BPFTOOL    ?= bpftool
PYTHON     ?= python3
LIBBPF_CFLAGS ?= $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS   ?= $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf)

BPF_CFLAGS := -g -O2 -target bpf \
              -D__TARGET_ARCH_$(TARGET_ARCH) \
              -Wall -Wextra -Wno-unused-parameter \
              -Iinclude -I$(BUILD) \
              $(LIBBPF_CFLAGS)
CXXFLAGS  ?= -std=c++20 -O3 -g -Wall -Wextra -Wpedantic -Wno-unused-parameter
CPPFLAGS  += -Iinclude -Isrc/collector -I$(BUILD)
LDLIBS    := $(LIBBPF_LIBS) -lelf -lz -lpthread

BPF_SRC   := src/bpf/xsypher.bpf.c
BPF_OBJ   := $(BUILD)/xsypher.bpf.o
BPF_SKEL  := $(BUILD)/xsypher.skel.h
COLLECTOR := $(BUILD)/xsypher-collector
COLLECTOR_SRCS := $(wildcard src/collector/*.cpp)
COLLECTOR_HDRS := $(wildcard src/collector/*.hpp) include/xsypher_abi.h

.PHONY: all bpf collector vmlinux test simulate verify run engine clean install \
        check-deps help

all: $(COLLECTOR)

help:
	@sed -n '3,20p' Makefile

$(BUILD):
	@mkdir -p $@

# --------------------------------------------------------------------------- #
# Kernel BTF header                                                           #
# --------------------------------------------------------------------------- #
vmlinux: include/vmlinux.h

include/vmlinux.h:
	@./scripts/gen_vmlinux.sh $@

# --------------------------------------------------------------------------- #
# eBPF CO-RE object + libbpf skeleton                                         #
# --------------------------------------------------------------------------- #
bpf: $(BPF_SKEL)

$(BPF_OBJ): $(BPF_SRC) include/xsypher_abi.h include/vmlinux.h | $(BUILD)
	@printf '\033[36m[bpf]\033[0m %s -> %s (%s)\n' "$<" "$@" "$(TARGET_ARCH)"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BPF_SKEL): $(BPF_OBJ)
	@printf '\033[36m[bpf]\033[0m generating skeleton %s\n' "$@"
	$(BPFTOOL) gen skeleton $< > $@

# --------------------------------------------------------------------------- #
# C++20 collector                                                             #
# --------------------------------------------------------------------------- #
collector: $(COLLECTOR)

$(COLLECTOR): $(BPF_SKEL) $(COLLECTOR_SRCS) $(COLLECTOR_HDRS) | $(BUILD)
	@printf '\033[36m[cxx]\033[0m compiling %s\n' "$@"
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(COLLECTOR_SRCS) -o $@ $(LDFLAGS) $(LDLIBS)
	@printf '\033[32m[ok]\033[0m  built %s\n' "$@"

# --------------------------------------------------------------------------- #
# Python                                                                      #
# --------------------------------------------------------------------------- #
test:
	@if $(PYTHON) -c 'import pytest' >/dev/null 2>&1; then \
		PYTHONPATH=src $(PYTHON) -m pytest tests -q; \
	else \
		PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -t . -v; \
	fi

simulate:
	PYTHONPATH=src $(PYTHON) tests/simulate_mcp_attack.py

# Documentation gate: every figure passes the geometry audit, every link and
# anchor resolves, and the house style holds. No dependencies beyond python3.
.PHONY: check-docs
check-docs:
	$(PYTHON) scripts/audit_svg.py docs/*.svg
	$(PYTHON) scripts/check_docs.py

verify:
	./scripts/verify_and_benchmark.sh

# --------------------------------------------------------------------------- #
# Run                                                                         #
# --------------------------------------------------------------------------- #
run: $(COLLECTOR)
	$(COLLECTOR) --socket-path /run/xsypher/stream.sock --block-imds

engine:
	PYTHONPATH=src $(PYTHON) -m engine.main \
		--socket-path /run/xsypher/stream.sock --enforce-kernel

# --------------------------------------------------------------------------- #
# Housekeeping                                                                #
# --------------------------------------------------------------------------- #
clean:
	rm -rf $(BUILD)
	@rm -f include/vmlinux.h

install: $(COLLECTOR)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(COLLECTOR) $(DESTDIR)$(PREFIX)/bin/xsypher-collector
	install -d $(DESTDIR)$(PREFIX)/lib/xsypher/engine
	cp -r src/engine/*.py $(DESTDIR)$(PREFIX)/lib/xsypher/engine/
	install -d $(DESTDIR)/etc/xsypher
	install -m 0644 config/rules.yaml $(DESTDIR)/etc/xsypher/rules.yaml
	install -d $(DESTDIR)/usr/lib/systemd/system
	install -m 0644 deploy/xsypher-collector.service $(DESTDIR)/usr/lib/systemd/system/
	install -m 0644 deploy/xsypher-engine.service $(DESTDIR)/usr/lib/systemd/system/
	@echo "installed collector to $(DESTDIR)$(PREFIX)/bin/xsypher-collector"
	@echo "installed engine package to $(DESTDIR)$(PREFIX)/lib/xsypher/engine"
	@echo "installed rules to $(DESTDIR)/etc/xsypher/rules.yaml"
	@echo "installed systemd units to $(DESTDIR)/usr/lib/systemd/system"

check-deps:
	@for tool in $(CLANG) $(CXX) $(BPFTOOL); do \
		if ! command -v $$tool >/dev/null 2>&1; then \
			echo "missing build dependency: $$tool"; exit 1; \
		fi; \
	done
	@echo "toolchain: $(CLANG) / $(CXX) / $(BPFTOOL)"
