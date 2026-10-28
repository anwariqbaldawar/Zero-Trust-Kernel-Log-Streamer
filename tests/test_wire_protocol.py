"""Wire protocol tests: binary layout, codecs and AF_UNIX/SOCK_SEQPACKET I/O.

These tests are the contract between three languages:

    include/xsypher_abi.h  <->  src/collector/*.cpp  <->  src/engine/abi.py

They assert exact structure sizes and field offsets, cross-check them against
the C header using the host compiler when one is available, and exercise a real
SOCK_SEQPACKET round trip against a mock collector.
"""

from __future__ import annotations

import asyncio
import ctypes
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from engine import abi  # noqa: E402
from engine.main import UdsTransport  # noqa: E402


# --------------------------------------------------------------------------- #
# Binary layout
# --------------------------------------------------------------------------- #

class TestStructLayout(unittest.TestCase):
    def test_kernel_event_size(self) -> None:
        self.assertEqual(ctypes.sizeof(abi.KernelEvent), 656)
        self.assertEqual(abi.KERNEL_EVENT_SIZE, 656)

    def test_wire_event_size(self) -> None:
        self.assertEqual(ctypes.sizeof(abi.WireEventMsg), 736)
        self.assertEqual(abi.WIRE_EVENT_SIZE, 736)

    def test_policy_cmd_size(self) -> None:
        self.assertEqual(ctypes.sizeof(abi.WirePolicyCmd), 32)
        self.assertEqual(abi.POLICY_CMD_SIZE, 32)

    def test_kernel_event_offsets(self) -> None:
        expected = {
            "timestamp_ns": 0,
            "cgroup_id": 8,
            "pid": 16,
            "tgid": 20,
            "ppid": 24,
            "uid": 28,
            "gid": 32,
            "mnt_ns_id": 36,
            "pid_ns_id": 40,
            "net_ns_id": 44,
            "event_type": 48,
            "retval": 52,
            "blocked_by_lsm": 56,
            "af_family": 57,
            "dport": 58,
            "sport": 60,
            "daddr_v4": 64,
            "saddr_v4": 68,
            "daddr_v6": 72,
            "open_flags": 88,
            "comm": 92,
            "parent_comm": 108,
            "filename": 124,
            "args": 380,
            "target_ino": 636,
            "target_dev": 640,
            "lineage_root_pid": 644,
            "lineage_flags": 648,
            "enforced_inline": 652,
        }
        for name, offset in expected.items():
            with self.subTest(field=name):
                self.assertEqual(getattr(abi.KernelEvent, name).offset, offset)

    def test_wire_event_offsets(self) -> None:
        self.assertEqual(abi.WireEventMsg.magic.offset, 0)
        self.assertEqual(abi.WireEventMsg.version.offset, 4)
        self.assertEqual(abi.WireEventMsg.msg_type.offset, 6)
        self.assertEqual(abi.WireEventMsg.seq_no.offset, 8)
        self.assertEqual(abi.WireEventMsg.container_id.offset, 16)
        self.assertEqual(abi.WireEventMsg.event.offset, 80)

    def test_policy_cmd_offsets(self) -> None:
        self.assertEqual(abi.WirePolicyCmd.magic.offset, 0)
        self.assertEqual(abi.WirePolicyCmd.version.offset, 4)
        self.assertEqual(abi.WirePolicyCmd.cmd_type.offset, 6)
        self.assertEqual(abi.WirePolicyCmd.target_cgroup_id.offset, 8)
        self.assertEqual(abi.WirePolicyCmd.target_pid.offset, 16)
        self.assertEqual(abi.WirePolicyCmd.target_ipv4.offset, 20)
        self.assertEqual(abi.WirePolicyCmd.enforcement_mode.offset, 24)
        self.assertEqual(abi.WirePolicyCmd.value.offset, 28)

    def test_constants_match_header(self) -> None:
        self.assertEqual(abi.XSYPHER_WIRE_MAGIC, 0x58535950)
        self.assertEqual(abi.XSYPHER_ABI_VERSION, 3)
        self.assertEqual(abi.MAX_COMM_LEN, 16)
        self.assertEqual(abi.MAX_PATH_LEN, 256)
        self.assertEqual(abi.MAX_ARGS_LEN, 256)
        self.assertEqual(abi.MAX_CONTAINER_ID_LEN, 64)
        self.assertEqual(abi.XSYPHER_RINGBUF_BYTES, 16 * 1024 * 1024)

    def test_imds_constant(self) -> None:
        # 169.254.169.254 as the raw u32 the kernel stores in sin_addr.s_addr.
        self.assertEqual(abi.IMDS_IPV4, "169.254.169.254")
        self.assertEqual(abi.IMDS_IPV4_RAW, 0xFEA9FEA9)
        self.assertEqual(abi.ipv4_to_raw("169.254.169.254"), abi.IMDS_IPV4_RAW)
        self.assertEqual(abi.ipv4_from_raw(abi.IMDS_IPV4_RAW), "169.254.169.254")

    def test_byte_order_helpers(self) -> None:
        # dport is stored in network byte order, so port 80 looks like 0x5000.
        # Port 80 is 0x0050 over the wire, and the raw u16 field the kernel
        # hands to us (network bytes in host order) therefore reads 0x5000.
        raw = struct.unpack("<H", struct.pack("!H", 80))[0]
        self.assertEqual(raw, 0x5000)
        self.assertEqual(struct.pack("<H", raw), b"\x00\x50")
        self.assertEqual(abi.port_from_raw(raw), 80)
        self.assertEqual(abi.port_from_raw(abi.port_from_raw(0)), 0)


class TestCrossLanguageLayout(unittest.TestCase):
    """Compile the C header and compare it against ctypes, when possible."""

    C_SOURCE = r"""
#include <stdio.h>
#include <stddef.h>
#include "xsypher_abi.h"

int main(void)
{
    printf("sizes %zu %zu %zu\n",
           sizeof(struct kernel_event_t),
           sizeof(struct wire_event_msg_t),
           sizeof(struct wire_policy_cmd_t));
    printf("offsets %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu\n",
           offsetof(struct kernel_event_t, event_type),
           offsetof(struct kernel_event_t, daddr_v4),
           offsetof(struct kernel_event_t, filename),
           offsetof(struct kernel_event_t, args),
           offsetof(struct kernel_event_t, target_ino),
           offsetof(struct kernel_event_t, target_dev),
           offsetof(struct kernel_event_t, lineage_root_pid),
           offsetof(struct kernel_event_t, lineage_flags),
           offsetof(struct kernel_event_t, enforced_inline),
           offsetof(struct wire_event_msg_t, container_id),
           offsetof(struct wire_event_msg_t, event),
           offsetof(struct wire_policy_cmd_t, target_ipv4),
           offsetof(struct wire_policy_cmd_t, enforcement_mode),
           offsetof(struct wire_policy_cmd_t, value));
    printf("constants %u %u %u\n",
           XSYPHER_WIRE_MAGIC, XSYPHER_ABI_VERSION, XSYPHER_IMDS_IPV4_RAW);
    return 0;
}
"""

    def test_c_header_matches_python(self) -> None:
        compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if compiler is None:
            self.skipTest("no C compiler available on this host")

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "layout_check.c"
            binary = Path(tmp) / "layout_check"
            source.write_text(self.C_SOURCE)
            compile_result = subprocess.run(
                [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                 f"-I{REPO_ROOT / 'include'}", str(source), "-o", str(binary)],
                capture_output=True, text=True, check=False,
            )
            if compile_result.returncode != 0:
                self.fail(f"C header failed to compile:\n{compile_result.stderr}")
            run = subprocess.run([str(binary)], capture_output=True, text=True, check=True)

        lines = dict(
            line.split(" ", 1) for line in run.stdout.strip().splitlines()
        )
        sizes = [int(value) for value in lines["sizes"].split()]
        self.assertEqual(sizes, [ctypes.sizeof(abi.KernelEvent),
                                 ctypes.sizeof(abi.WireEventMsg),
                                 ctypes.sizeof(abi.WirePolicyCmd)])

        offsets = [int(value) for value in lines["offsets"].split()]
        self.assertEqual(
            offsets,
            [
                abi.KernelEvent.event_type.offset,
                abi.KernelEvent.daddr_v4.offset,
                abi.KernelEvent.filename.offset,
                abi.KernelEvent.args.offset,
                abi.KernelEvent.target_ino.offset,
                abi.KernelEvent.target_dev.offset,
                abi.KernelEvent.lineage_root_pid.offset,
                abi.KernelEvent.lineage_flags.offset,
                abi.KernelEvent.enforced_inline.offset,
                abi.WireEventMsg.container_id.offset,
                abi.WireEventMsg.event.offset,
                abi.WirePolicyCmd.target_ipv4.offset,
                abi.WirePolicyCmd.enforcement_mode.offset,
                abi.WirePolicyCmd.value.offset,
            ],
        )

        magic, version, imds = [int(value) for value in lines["constants"].split()]
        self.assertEqual(magic, abi.XSYPHER_WIRE_MAGIC)
        self.assertEqual(version, abi.XSYPHER_ABI_VERSION)
        self.assertEqual(imds, abi.IMDS_IPV4_RAW)


# --------------------------------------------------------------------------- #
# Codecs
# --------------------------------------------------------------------------- #

class TestWireCodec(unittest.TestCase):
    def make_event(self, **overrides) -> abi.Event:
        base = dict(
            timestamp_ns=1_700_000_000_000_000_000,
            cgroup_id=0xDEADBEEF,
            pid=4242,
            tgid=4242,
            ppid=1,
            uid=1000,
            gid=1000,
            mnt_ns_id=4026531840,
            pid_ns_id=4026531836,
            net_ns_id=4026531992,
            event_type=abi.EventType.CONNECT,
            af_family=2,
            dport=443,
            sport=51234,
            daddr_v4="169.254.169.254",
            saddr_v4="10.1.2.3",
            comm="curl",
            parent_comm="sh",
            filename="/usr/bin/curl",
            args="http://169.254.169.254/latest/meta-data/",
        )
        base.update(overrides)
        return abi.Event(**base)

    def test_round_trip(self) -> None:
        event = self.make_event()
        frame = abi.encode_wire_frame(event, seq_no=7, container_id="c" * 64)
        self.assertEqual(len(frame), 736)
        decoded = abi.decode_wire_frame(frame)

        self.assertTrue(decoded.valid)
        self.assertEqual(decoded.seq_no, 7)
        self.assertEqual(decoded.container_id, "c" * 64)
        self.assertEqual(decoded.event.pid, 4242)
        self.assertEqual(decoded.event.comm, "curl")
        self.assertEqual(decoded.event.parent_comm, "sh")
        self.assertEqual(decoded.event.filename, "/usr/bin/curl")
        self.assertEqual(decoded.event.dport, 443)
        self.assertEqual(decoded.event.sport, 51234)
        self.assertEqual(decoded.event.daddr_v4, "169.254.169.254")
        self.assertEqual(decoded.event.saddr_v4, "10.1.2.3")
        self.assertEqual(decoded.event.event_type, abi.EventType.CONNECT)
        self.assertEqual(decoded.event.mnt_ns_id, 4026531840)
        self.assertEqual(decoded.event.args, event.args)

    def test_ipv6_round_trip(self) -> None:
        event = self.make_event(af_family=10, daddr_v6="fd00:ec2::254", daddr_v4="")
        decoded = abi.decode_wire_frame(abi.encode_wire_frame(event))
        self.assertEqual(decoded.event.daddr_v6, "fd00:ec2::254")
        self.assertEqual(decoded.event.daddr_v4, "")

    def test_enforced_inline_event_round_trip(self) -> None:
        event = self.make_event(
            event_type=abi.EventType.ENFORCED_INLINE,
            blocked_by_lsm=1,
            enforced_inline=1,
            open_flags=abi.BlockReason.RESTRICTED_INODE,
            target_ino=0x12345678,
            target_dev=0x80,
            lineage_root_pid=4242,
            lineage_flags=abi.LINEAGE_FLAG_AI_RUNTIME | abi.LINEAGE_FLAG_QUARANTINE,
        )
        decoded = abi.decode_wire_frame(abi.encode_wire_frame(event))
        self.assertEqual(decoded.event.event_type, abi.EventType.ENFORCED_INLINE)
        self.assertEqual(decoded.event.enforced_inline, 1)
        self.assertEqual(decoded.event.open_flags, abi.BlockReason.RESTRICTED_INODE)
        self.assertEqual(decoded.event.target_ino, 0x12345678)
        self.assertEqual(decoded.event.target_dev, 0x80)
        self.assertEqual(decoded.event.lineage_root_pid, 4242)
        self.assertEqual(
            decoded.event.lineage_flags,
            abi.LINEAGE_FLAG_AI_RUNTIME | abi.LINEAGE_FLAG_QUARANTINE,
        )

    def test_control_plane_commands_round_trip(self) -> None:
        commands = [
            abi.PolicyCommand.set_heartbeat(1_700_000_000_000_000_000),
            abi.PolicyCommand.set_fail_closed(True),
            abi.PolicyCommand.set_shutdown_token(0xC0FFEE),
            abi.PolicyCommand.protect_pid(4242, token=0x1234),
            abi.PolicyCommand.unprotect_pid(4242),
            abi.PolicyCommand.register_inode(0x12345678, 0x80),
        ]
        for command in commands:
            with self.subTest(command=command.name):
                payload = command.to_bytes()
                self.assertEqual(len(payload), abi.POLICY_CMD_SIZE)
                decoded = abi.PolicyCommand.from_bytes(payload)
                self.assertEqual(decoded.cmd_type, command.cmd_type)
                self.assertEqual(decoded.target_pid, command.target_pid)
                self.assertEqual(decoded.target_cgroup_id, command.target_cgroup_id)
                self.assertEqual(decoded.value, command.value)

    def test_long_strings_are_truncated_not_corrupted(self) -> None:
        event = self.make_event(filename="/" + "a" * 400, args="x" * 400)
        decoded = abi.decode_wire_frame(abi.encode_wire_frame(event))
        self.assertEqual(len(decoded.event.filename), abi.MAX_PATH_LEN - 1)
        self.assertTrue(decoded.event.filename.startswith("/aaaa"))
        self.assertEqual(len(decoded.event.args), abi.MAX_ARGS_LEN - 1)

    def test_wrong_size_rejected(self) -> None:
        with self.assertRaises(ValueError):
            abi.decode_wire_frame(b"\x00" * 10)
        with self.assertRaises(ValueError):
            abi.decode_wire_frame(b"\x00" * 800)

    def test_bad_magic_rejected(self) -> None:
        frame = bytearray(abi.encode_wire_frame(self.make_event()))
        frame[0:4] = struct.pack("<I", 0xDEADBEEF)
        with self.assertRaises(ValueError):
            abi.decode_wire_frame(bytes(frame))

    def test_bad_version_rejected(self) -> None:
        frame = bytearray(abi.encode_wire_frame(self.make_event()))
        frame[4:6] = struct.pack("<H", 99)
        with self.assertRaises(ValueError):
            abi.decode_wire_frame(bytes(frame))

    def test_empty_container_defaults_to_host(self) -> None:
        event = self.make_event()
        event.container_id = ""
        decoded = abi.decode_wire_frame(abi.encode_wire_frame(event))
        self.assertEqual(decoded.container_id, "host")

    def test_policy_command_round_trip(self) -> None:
        commands = [
            abi.PolicyCommand.quarantine_pid(1234),
            abi.PolicyCommand.unquarantine_pid(1234),
            abi.PolicyCommand.quarantine_cgroup(0x1234_5678_9ABC),
            abi.PolicyCommand.unquarantine_cgroup(0x1234_5678_9ABC),
            abi.PolicyCommand.block_ipv4("203.0.113.9"),
            abi.PolicyCommand.unblock_ipv4("203.0.113.9"),
            abi.PolicyCommand.set_enforcement_mode(1),
        ]
        for command in commands:
            with self.subTest(command=command.name):
                payload = command.to_bytes()
                self.assertEqual(len(payload), abi.POLICY_CMD_SIZE)
                decoded = abi.PolicyCommand.from_bytes(payload)
                self.assertEqual(decoded.cmd_type, command.cmd_type)
                self.assertEqual(decoded.target_pid, command.target_pid)
                self.assertEqual(decoded.target_cgroup_id, command.target_cgroup_id)
                self.assertEqual(decoded.target_ipv4, command.target_ipv4)
                self.assertEqual(decoded.enforcement_mode, command.enforcement_mode)

    def test_policy_command_wire_layout(self) -> None:
        payload = abi.PolicyCommand.block_ipv4("169.254.169.254").to_bytes()
        magic, version, cmd_type = struct.unpack_from("<IHH", payload, 0)
        (target_ipv4,) = struct.unpack_from("<I", payload, 20)
        self.assertEqual(magic, abi.XSYPHER_WIRE_MAGIC)
        self.assertEqual(version, 3)
        self.assertEqual(cmd_type, abi.CmdType.BLOCK_IPV4)
        self.assertEqual(target_ipv4, 0xFEA9FEA9)

    def test_policy_command_rejects_bad_input(self) -> None:
        with self.assertRaises(ValueError):
            abi.PolicyCommand.from_bytes(b"\x00" * 8)
        bad = bytearray(abi.PolicyCommand.quarantine_pid(1).to_bytes())
        bad[0:4] = b"\x00\x00\x00\x00"
        with self.assertRaises(ValueError):
            abi.PolicyCommand.from_bytes(bytes(bad))

    def test_describe(self) -> None:
        self.assertIn("pid=99", abi.PolicyCommand.quarantine_pid(99).describe())
        self.assertIn("169.254.169.254",
                      abi.PolicyCommand.block_ipv4("169.254.169.254").describe())


# --------------------------------------------------------------------------- #
# AF_UNIX / SOCK_SEQPACKET transport
# --------------------------------------------------------------------------- #

class MockCollector:
    """Minimal stand-in for the C++ collector, used by the transport tests."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.received: list[abi.PolicyCommand] = []
        self.error: BaseException | None = None
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self._server.bind(path)
        self._server.listen(4)
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> "MockCollector":
        self._thread.start()
        return self

    def _run(self) -> None:
        try:
            conn, _ = self._server.accept()
            with conn:
                conn.settimeout(5.0)
                for frame in self.frames:
                    conn.send(frame)
                deadline = time.monotonic() + 5.0
                while len(self.received) < self.expected_commands and time.monotonic() < deadline:
                    data = conn.recv(64)
                    if not data:
                        break
                    self.received.append(abi.PolicyCommand.from_bytes(data))
        except BaseException as exc:  # pragma: no cover - surfaced in the test
            self.error = exc
        finally:
            self._server.close()

    def join(self, timeout: float = 10.0) -> None:
        self._thread.join(timeout)

    frames: tuple[bytes, ...] = ()
    expected_commands: int = 1


class TestUdsSeqpacket(unittest.IsolatedAsyncioTestCase):
    async def test_engine_transport_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "stream.sock")
            event = abi.Event(pid=77, tgid=77, comm="sh", event_type=abi.EventType.EXECVE,
                              filename="/bin/sh", container_id="deadbeef")
            collector = MockCollector(path)
            collector.frames = (
                abi.encode_wire_frame(event, seq_no=1),
                abi.encode_wire_frame(event, seq_no=2),
            )
            collector.expected_commands = 1
            collector.start()

            received: list[bytes] = []
            transport = UdsTransport(path, on_frame=received.append)
            connected = await transport.connect(attempts=20, retry_interval=0.05)
            self.assertTrue(connected)

            deadline = time.monotonic() + 5.0
            while len(received) < 2 and time.monotonic() < deadline:
                await asyncio.sleep(0.01)
            self.assertEqual(len(received), 2)

            frame = abi.decode_wire_frame(received[0])
            self.assertEqual(frame.seq_no, 1)
            self.assertEqual(frame.event.comm, "sh")

            command = abi.PolicyCommand.quarantine_pid(77)
            self.assertTrue(transport.send(command.to_bytes()))

            collector.join()
            self.assertIsNone(collector.error)
            self.assertEqual(len(collector.received), 1)
            self.assertEqual(collector.received[0].cmd_type, abi.CmdType.QUARANTINE_PID)
            self.assertEqual(collector.received[0].target_pid, 77)

            transport.close()

    async def test_transport_reports_disconnected_when_socket_missing(self) -> None:
        transport = UdsTransport("/nonexistent/xsypher-test.sock")
        connected = await transport.connect(attempts=2, retry_interval=0.01)
        self.assertFalse(connected)
        self.assertFalse(transport.connected)
        self.assertFalse(transport.send(b"\x00" * 32))
        transport.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
