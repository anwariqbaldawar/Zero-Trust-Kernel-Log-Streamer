"""Native transport and map ABI regressions; no kernel privileges required."""
import ctypes
from pathlib import Path
import shutil
import socket
import subprocess

import pytest

from engine.abi import EgressKey

ROOT = Path(__file__).resolve().parents[1]


def test_map_abi_and_imds_ipv6(tmp_path):
    cc = shutil.which("cc")
    if not cc:
        pytest.skip("C compiler unavailable")
    source = tmp_path / "abi.c"
    source.write_text('''
#include <stdio.h>
#include "xsypher_abi.h"
int main(void) {
    unsigned char addr[16] = XSYPHER_IMDS_IPV6_RAW;
    printf("%zu %zu\\n", sizeof(struct egress_key_t),
           offsetof(struct egress_key_t, address));
    return fwrite(addr, 1, 16, stdout) == 16 ? 0 : 1;
}
''')
    binary = tmp_path / "abi"
    subprocess.run([cc, "-Wall", "-Wextra", "-Werror", "-Iinclude", str(source),
                    "-o", str(binary)], cwd=ROOT, check=True)
    layout, address = subprocess.check_output([str(binary)]).split(b"\n", 1)
    assert layout == f"{ctypes.sizeof(EgressKey)} {EgressKey.address.offset}".encode()
    assert address == socket.inet_pton(socket.AF_INET6, "fd00:ec2::254")


def test_seqpacket_batch_preserves_frames(tmp_path):
    cxx = shutil.which("g++")
    if not cxx:
        pytest.skip("C++ compiler unavailable")
    binary = tmp_path / "uds-batch"
    subprocess.run([cxx, "-std=c++20", "-Wall", "-Wextra", "-Werror", "-Iinclude",
                    "-Isrc/collector", "tests/uds_batch.cpp",
                    "src/collector/uds_server.cpp", "-o", str(binary)],
                   cwd=ROOT, check=True)
    subprocess.run([str(binary)], check=True, timeout=10)
