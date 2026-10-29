"""Byte-exact Python mirror of ``include/xsypher_abi.h``.

Every structure below is laid out with ``_pack_ = 1`` plus *explicit* padding
fields, exactly like the C header does, so ctypes and clang/g++ agree on every
offset and on total size.  Import-time assertions guarantee that a careless
edit of either side fails loudly instead of silently corrupting telemetry.

Wire conventions
----------------
* integers are little-endian (x86_64 / aarch64)
* ``daddr_v4`` / ``saddr_v4`` / ``target_ipv4`` hold **raw network byte order**
  bytes, i.e. exactly the ``struct in_addr.s_addr`` the kernel produced.  On a
  little-endian host this means ``169.254.169.254`` shows up as ``0xFEA9FEA9``.
  Use :func:`ipv4_from_raw` / :func:`ipv4_to_raw` instead of hand-rolling that.
* ``dport`` / ``sport`` are also raw network byte order.
* strings are NUL terminated and NUL padded.
"""

from __future__ import annotations

import ctypes
import socket
import struct
import sys
from dataclasses import dataclass, field
from typing import Final

# --------------------------------------------------------------------------- #
# Constants (mirrors include/xsypher_abi.h)
# --------------------------------------------------------------------------- #

XSYPHER_WIRE_MAGIC: Final[int] = 0x58535950  # "XSYP"
XSYPHER_ABI_VERSION: Final[int] = 3

MAX_COMM_LEN: Final[int] = 16
MAX_PATH_LEN: Final[int] = 256
MAX_ARGS_LEN: Final[int] = 256
MAX_CONTAINER_ID_LEN: Final[int] = 64
XSYPHER_PATH_BUF_LEN: Final[int] = 512

XSYPHER_RINGBUF_BYTES: Final[int] = 16 * 1024 * 1024
XSYPHER_MAX_ARGV_POINTERS: Final[int] = 4

MSG_TELEMETRY_EVENT: Final[int] = 1
MSG_HEARTBEAT: Final[int] = 2

ENFORCEMENT_AUDIT_ONLY: Final[int] = 0
ENFORCEMENT_INLINE_BLOCK: Final[int] = 1

QUARANTINE_OBSERVE: Final[int] = 0
QUARANTINE_BLOCK: Final[int] = 1

# Lineage flag bits (mirrors LINEAGE_FLAG_* in include/xsypher_abi.h).
LINEAGE_FLAG_AI_RUNTIME: Final[int] = 0x1
LINEAGE_FLAG_QUARANTINE: Final[int] = 0x2
LINEAGE_FLAG_FAIL_CLOSED: Final[int] = 0x4

# LSM block reasons (mirrors enum xsypher_block_reason).
class BlockReason:
    NONE = 0
    QUARANTINE_EXEC = 1
    IMDS = 2
    BLOCKED_IP = 3
    CREDENTIAL_READ = 4
    WRITE_DENIED = 5
    RESTRICTED_SHELL = 6
    RESTRICTED_INODE = 7
    IMDS_IPV6 = 8
    FAIL_CLOSED = 9
    TAMPER_KILL = 10
    TAMPER_BPF = 11
    PATH_EVASION = 12

    NAMES = {
        NONE: "none",
        QUARANTINE_EXEC: "quarantine_exec",
        IMDS: "imds",
        BLOCKED_IP: "blocked_ip",
        CREDENTIAL_READ: "credential_read",
        WRITE_DENIED: "write_denied",
        RESTRICTED_SHELL: "restricted_shell",
        RESTRICTED_INODE: "restricted_inode",
        IMDS_IPV6: "imds_ipv6",
        FAIL_CLOSED: "fail_closed",
        TAMPER_KILL: "tamper_kill",
        TAMPER_BPF: "tamper_bpf",
        PATH_EVASION: "path_evasion",
    }

    @classmethod
    def name(cls, value: int) -> str:
        return cls.NAMES.get(value, f"reason_{value}")

# Raw network-order constants -------------------------------------------------
IMDS_IPV4: Final[str] = "169.254.169.254"
IMDS_IPV4_BE: Final[int] = 0xA9FEA9FE  # big-endian logical value
#: raw u32 as stored in kernel memory / on the wire on little-endian hosts
IMDS_IPV4_RAW: Final[int] = struct.unpack("<I", socket.inet_aton(IMDS_IPV4))[0]

#: AWS IPv6 IMDS address fd00:ec2::254 as a raw 16-byte network-order array.
IMDS_IPV6: Final[str] = "fd00:ec2::254"
IMDS_IPV6_RAW: Final[bytes] = bytes(
    [0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0xEC, 0x02, 0x00, 0xFE]
)


class EventType:
    """Mirror of ``enum xsypher_event_type``."""

    UNKNOWN = 0
    EXECVE = 1
    CONNECT = 2
    OPENAT = 3
    MEMFD_CREATE = 4
    PROCESS_EXIT = 5
    LSM_BLOCK = 6
    ENFORCED_INLINE = 7

    NAMES = {
        UNKNOWN: "unknown",
        EXECVE: "execve",
        CONNECT: "connect",
        OPENAT: "openat",
        MEMFD_CREATE: "memfd_create",
        PROCESS_EXIT: "process_exit",
        LSM_BLOCK: "lsm_block",
        ENFORCED_INLINE: "enforced_inline",
    }

    @classmethod
    def name(cls, value: int) -> str:
        return cls.NAMES.get(value, f"event_{value}")


class CmdType:
    """Mirror of ``enum xsypher_cmd_type``."""

    QUARANTINE_PID = 10
    UNQUARANTINE_PID = 11
    QUARANTINE_CGROUP = 12
    UNQUARANTINE_CGROUP = 13
    BLOCK_IPV4 = 14
    UNBLOCK_IPV4 = 15
    SET_ENFORCEMENT_MODE = 16
    SET_HEARTBEAT = 17
    SET_FAIL_CLOSED = 18
    SET_SHUTDOWN_TOKEN = 19
    PROTECT_PID = 20
    UNPROTECT_PID = 21
    REGISTER_INODE = 22

    NAMES = {
        QUARANTINE_PID: "quarantine_pid",
        UNQUARANTINE_PID: "unquarantine_pid",
        QUARANTINE_CGROUP: "quarantine_cgroup",
        UNQUARANTINE_CGROUP: "unquarantine_cgroup",
        BLOCK_IPV4: "block_ipv4",
        UNBLOCK_IPV4: "unblock_ipv4",
        SET_ENFORCEMENT_MODE: "set_enforcement_mode",
        SET_HEARTBEAT: "set_heartbeat",
        SET_FAIL_CLOSED: "set_fail_closed",
        SET_SHUTDOWN_TOKEN: "set_shutdown_token",
        PROTECT_PID: "protect_pid",
        UNPROTECT_PID: "unprotect_pid",
        REGISTER_INODE: "register_inode",
    }

    @classmethod
    def name(cls, value: int) -> str:
        return cls.NAMES.get(value, f"cmd_{value}")


# --------------------------------------------------------------------------- #
# Structures
# --------------------------------------------------------------------------- #

_U8 = ctypes.c_uint8
_U16 = ctypes.c_uint16
_U32 = ctypes.c_uint32
_U64 = ctypes.c_uint64
_I32 = ctypes.c_int32


class KernelEvent(ctypes.LittleEndianStructure):
    """``struct kernel_event_t`` — 656 bytes."""

    if sys.version_info >= (3, 14):
        _layout_ = "ms"
    _pack_ = 1
    _fields_ = [
        ("timestamp_ns", _U64),          # 0
        ("cgroup_id", _U64),             # 8
        ("pid", _U32),                   # 16
        ("tgid", _U32),                  # 20
        ("ppid", _U32),                  # 24
        ("uid", _U32),                   # 28
        ("gid", _U32),                   # 32
        ("mnt_ns_id", _U32),             # 36
        ("pid_ns_id", _U32),             # 40
        ("net_ns_id", _U32),             # 44
        ("event_type", _U32),            # 48
        ("retval", _I32),                # 52
        ("blocked_by_lsm", _U8),         # 56
        ("af_family", _U8),              # 57
        ("dport", _U16),                 # 58 (network byte order)
        ("sport", _U16),                 # 60 (network byte order)
        ("reserved0", _U8 * 2),          # 62 explicit padding
        ("daddr_v4", _U32),              # 64 raw network byte order
        ("saddr_v4", _U32),              # 68 raw network byte order
        ("daddr_v6", _U8 * 16),          # 72
        ("open_flags", _U32),            # 88
        ("comm", ctypes.c_char * MAX_COMM_LEN),              # 92
        ("parent_comm", ctypes.c_char * MAX_COMM_LEN),       # 108
        ("filename", ctypes.c_char * MAX_PATH_LEN),          # 124
        ("args", ctypes.c_char * MAX_ARGS_LEN),              # 380
        ("target_ino", _U32),            # 636
        ("target_dev", _U32),            # 640
        ("lineage_root_pid", _U32),      # 644
        ("lineage_flags", _U32),         # 648
        ("enforced_inline", _U8),        # 652
        ("reserved2", _U8),              # 653
        ("reserved3", _U16),             # 654
    ]


class WireEventMsg(ctypes.LittleEndianStructure):
    """``struct wire_event_msg_t`` — 736 bytes."""

    if sys.version_info >= (3, 14):
        _layout_ = "ms"
    _pack_ = 1
    _fields_ = [
        ("magic", _U32),                 # 0
        ("version", _U16),               # 4
        ("msg_type", _U16),              # 6
        ("seq_no", _U64),                # 8
        ("container_id", ctypes.c_char * MAX_CONTAINER_ID_LEN),  # 16
        ("event", KernelEvent),          # 80
    ]


class WirePolicyCmd(ctypes.LittleEndianStructure):
    """``struct wire_policy_cmd_t`` — 32 bytes."""

    if sys.version_info >= (3, 14):
        _layout_ = "ms"
    _pack_ = 1
    _fields_ = [
        ("magic", _U32),                 # 0
        ("version", _U16),               # 4
        ("cmd_type", _U16),              # 6
        ("target_cgroup_id", _U64),      # 8
        ("target_pid", _U32),            # 16
        ("target_ipv4", _U32),           # 20 raw network byte order
        ("enforcement_mode", _U32),      # 24
        ("value", _U32),                 # 28
    ]


KERNEL_EVENT_SIZE: Final[int] = 656
WIRE_EVENT_SIZE: Final[int] = 736
POLICY_CMD_SIZE: Final[int] = 32

# Hard guarantees that the C header and this module never drift apart.
assert ctypes.sizeof(KernelEvent) == KERNEL_EVENT_SIZE, (
    f"KernelEvent size {ctypes.sizeof(KernelEvent)} != {KERNEL_EVENT_SIZE}"
)
assert ctypes.sizeof(WireEventMsg) == WIRE_EVENT_SIZE, (
    f"WireEventMsg size {ctypes.sizeof(WireEventMsg)} != {WIRE_EVENT_SIZE}"
)
assert ctypes.sizeof(WirePolicyCmd) == POLICY_CMD_SIZE, (
    f"WirePolicyCmd size {ctypes.sizeof(WirePolicyCmd)} != {POLICY_CMD_SIZE}"
)

# Field-offset guarantees (mirrors the XSYPHER_STATIC_ASSERT block in C).
_OFFSETS = {
    (KernelEvent, "timestamp_ns"): 0,
    (KernelEvent, "cgroup_id"): 8,
    (KernelEvent, "pid"): 16,
    (KernelEvent, "event_type"): 48,
    (KernelEvent, "retval"): 52,
    (KernelEvent, "blocked_by_lsm"): 56,
    (KernelEvent, "af_family"): 57,
    (KernelEvent, "dport"): 58,
    (KernelEvent, "sport"): 60,
    (KernelEvent, "daddr_v4"): 64,
    (KernelEvent, "saddr_v4"): 68,
    (KernelEvent, "daddr_v6"): 72,
    (KernelEvent, "open_flags"): 88,
    (KernelEvent, "comm"): 92,
    (KernelEvent, "parent_comm"): 108,
    (KernelEvent, "filename"): 124,
    (KernelEvent, "args"): 380,
    (KernelEvent, "target_ino"): 636,
    (KernelEvent, "target_dev"): 640,
    (KernelEvent, "lineage_root_pid"): 644,
    (KernelEvent, "lineage_flags"): 648,
    (KernelEvent, "enforced_inline"): 652,
    (WireEventMsg, "seq_no"): 8,
    (WireEventMsg, "container_id"): 16,
    (WireEventMsg, "event"): 80,
    (WirePolicyCmd, "target_cgroup_id"): 8,
    (WirePolicyCmd, "target_pid"): 16,
    (WirePolicyCmd, "target_ipv4"): 20,
    (WirePolicyCmd, "enforcement_mode"): 24,
}
for (_struct, _name), _expected in _OFFSETS.items():
    _actual = getattr(_struct, _name).offset
    assert _actual == _expected, (
        f"{_struct.__name__}.{_name} offset {_actual} != {_expected}"
    )


# --------------------------------------------------------------------------- #
# Byte-order / string helpers
# --------------------------------------------------------------------------- #

def ipv4_from_raw(raw: int) -> str:
    """Convert a raw network-order u32 field into dotted-quad text."""
    return socket.inet_ntoa(struct.pack("<I", raw & 0xFFFFFFFF))


def ipv4_to_raw(text: str) -> int:
    """Convert dotted-quad text into the raw network-order u32 field value."""
    return struct.unpack("<I", socket.inet_aton(text))[0]


def port_from_raw(raw: int) -> int:
    """Convert a raw network-order u16 port into host order."""
    return struct.unpack("!H", struct.pack("<H", raw & 0xFFFF))[0]


def _cstr(raw: bytes) -> str:
    """Decode a fixed-size NUL padded C string, dropping garbage after NUL."""
    nul = raw.find(b"\0")
    if nul >= 0:
        raw = raw[:nul]
    return raw.decode("utf-8", errors="replace")


def _fixed_bytes(text: str, length: int) -> bytes:
    """Encode ``text`` into a fixed-size NUL padded field."""
    raw = text.encode("utf-8", errors="replace")[: length - 1]
    return raw + b"\0" * (length - len(raw))


def _id_bytes(text: str, length: int) -> bytes:
    """Encode a container identifier into its fixed-width wire field.

    Unlike the other strings this field is *not* required to be NUL terminated:
    Docker/containerd/CRI-O identifiers are exactly 64 hex characters, which
    fills MAX_CONTAINER_ID_LEN completely.  Shorter values ("host") are NUL
    padded, and the decoder accepts both shapes.
    """
    raw = text.encode("utf-8", errors="replace")[:length]
    return raw + b"\0" * (length - len(raw))


def _comm_bytes(text: str) -> bytes:
    """Encode a 16-byte comm field (kernel comm is NUL terminated)."""
    return text.encode("utf-8", errors="replace")[: MAX_COMM_LEN - 1].ljust(
        MAX_COMM_LEN, b"\0"
    )


# --------------------------------------------------------------------------- #
# Python-facing event object
# --------------------------------------------------------------------------- #

@dataclass(slots=True)
class Event:
    """Ergonomic, immutable-ish view over ``struct kernel_event_t``.

    Constructed from the raw ctypes structure (zero-copy field access) or built
    synthetically by the simulator / tests.
    """

    timestamp_ns: int = 0
    cgroup_id: int = 0
    pid: int = 0
    tgid: int = 0
    ppid: int = 0
    uid: int = 0
    gid: int = 0
    mnt_ns_id: int = 0
    pid_ns_id: int = 0
    net_ns_id: int = 0
    event_type: int = EventType.UNKNOWN
    retval: int = 0
    blocked_by_lsm: int = 0
    af_family: int = 0
    dport: int = 0          # host order after decoding
    sport: int = 0          # host order after decoding
    daddr_v4: str = ""
    saddr_v4: str = ""
    daddr_v6: str = ""
    open_flags: int = 0
    comm: str = ""
    parent_comm: str = ""
    filename: str = ""
    args: str = ""
    target_ino: int = 0
    target_dev: int = 0
    lineage_root_pid: int = 0
    lineage_flags: int = 0
    enforced_inline: int = 0

    # Enrichment added by the C++ collector / Python engine.
    seq_no: int = 0
    container_id: str = "host"
    received_ns: int = 0
    raw: bytes = field(default=b"", repr=False)

    # -- derived helpers -------------------------------------------------- #
    @property
    def event_name(self) -> str:
        return EventType.name(self.event_type)

    @property
    def argv(self) -> list[str]:
        return [tok for tok in self.args.split(" ") if tok]

    @property
    def exe_basename(self) -> str:
        return self.filename.rsplit("/", 1)[-1] if self.filename else self.comm

    @property
    def is_container(self) -> bool:
        return self.container_id not in ("", "host")

    @property
    def is_network(self) -> bool:
        return self.event_type == EventType.CONNECT

    def text_blob(self) -> str:
        """Lower-cased blob of all attacker-controllable text, for matching."""
        return f"{self.filename} {self.args} {self.comm}".lower()

    def to_struct(self) -> KernelEvent:
        """Build a ctypes kernel event from this dataclass."""
        ev = KernelEvent()
        ev.timestamp_ns = self.timestamp_ns
        ev.cgroup_id = self.cgroup_id
        ev.pid = self.pid
        ev.tgid = self.tgid
        ev.ppid = self.ppid
        ev.uid = self.uid
        ev.gid = self.gid
        ev.mnt_ns_id = self.mnt_ns_id
        ev.pid_ns_id = self.pid_ns_id
        ev.net_ns_id = self.net_ns_id
        ev.event_type = self.event_type
        ev.retval = self.retval
        ev.blocked_by_lsm = 1 if self.blocked_by_lsm else 0
        ev.af_family = self.af_family
        ev.dport = struct.unpack("<H", struct.pack("!H", self.dport & 0xFFFF))[0]
        ev.sport = struct.unpack("<H", struct.pack("!H", self.sport & 0xFFFF))[0]
        ev.daddr_v4 = ipv4_to_raw(self.daddr_v4) if self.daddr_v4 else 0
        ev.saddr_v4 = ipv4_to_raw(self.saddr_v4) if self.saddr_v4 else 0
        if self.daddr_v6:
            try:
                packed = socket.inet_pton(socket.AF_INET6, self.daddr_v6)
            except OSError:
                packed = b""
            for index, byte in enumerate(packed[:16]):
                ev.daddr_v6[index] = byte
        ev.open_flags = self.open_flags
        ev.comm = _comm_bytes(self.comm)
        ev.parent_comm = _comm_bytes(self.parent_comm)
        ev.filename = _fixed_bytes(self.filename, MAX_PATH_LEN)
        ev.args = _fixed_bytes(self.args, MAX_ARGS_LEN)
        ev.target_ino = self.target_ino & 0xFFFFFFFF
        ev.target_dev = self.target_dev & 0xFFFFFFFF
        ev.lineage_root_pid = self.lineage_root_pid & 0xFFFFFFFF
        ev.lineage_flags = self.lineage_flags & 0xFFFFFFFF
        ev.enforced_inline = 1 if self.enforced_inline else 0
        return ev

    @classmethod
    def from_struct(cls, ev: KernelEvent) -> "Event":
        """Decode a ctypes kernel event (zero-copy field reads)."""
        daddr6 = bytes(ev.daddr_v6)
        daddr6_text = ""
        if any(daddr6):
            try:
                daddr6_text = socket.inet_ntop(socket.AF_INET6, daddr6)
            except OSError:
                daddr6_text = ""
        daddr4 = ev.daddr_v4
        saddr4 = ev.saddr_v4
        return cls(
            timestamp_ns=ev.timestamp_ns,
            cgroup_id=ev.cgroup_id,
            pid=ev.pid,
            tgid=ev.tgid,
            ppid=ev.ppid,
            uid=ev.uid,
            gid=ev.gid,
            mnt_ns_id=ev.mnt_ns_id,
            pid_ns_id=ev.pid_ns_id,
            net_ns_id=ev.net_ns_id,
            event_type=ev.event_type,
            retval=ev.retval,
            blocked_by_lsm=ev.blocked_by_lsm,
            af_family=ev.af_family,
            dport=port_from_raw(ev.dport),
            sport=port_from_raw(ev.sport),
            daddr_v4=ipv4_from_raw(daddr4) if daddr4 else "",
            saddr_v4=ipv4_from_raw(saddr4) if saddr4 else "",
            daddr_v6=daddr6_text,
            open_flags=ev.open_flags,
            comm=_cstr(ev.comm),
            parent_comm=_cstr(ev.parent_comm),
            filename=_cstr(ev.filename),
            args=_cstr(ev.args),
            target_ino=ev.target_ino,
            target_dev=ev.target_dev,
            lineage_root_pid=ev.lineage_root_pid,
            lineage_flags=ev.lineage_flags,
            enforced_inline=ev.enforced_inline,
        )


# --------------------------------------------------------------------------- #
# Wire frame codecs
# --------------------------------------------------------------------------- #

@dataclass(slots=True)
class WireFrame:
    """Decoded ``struct wire_event_msg_t``."""

    magic: int
    version: int
    msg_type: int
    seq_no: int
    container_id: str
    event: Event

    @property
    def valid(self) -> bool:
        return self.magic == XSYPHER_WIRE_MAGIC and self.version == XSYPHER_ABI_VERSION


def decode_wire_frame(data: bytes, *, strict: bool = True) -> WireFrame:
    """Decode one ``SOCK_SEQPACKET`` datagram into a :class:`WireFrame`.

    Raises ``ValueError`` on short, oversized or malformed frames when
    ``strict`` is true; returns a frame with ``magic=0`` semantics otherwise.
    """
    if len(data) != WIRE_EVENT_SIZE:
        if strict:
            raise ValueError(
                f"wire frame must be exactly {WIRE_EVENT_SIZE} bytes, got {len(data)}"
            )
        if len(data) > WIRE_EVENT_SIZE:
            data = data[:WIRE_EVENT_SIZE]
        else:
            data = data + b"\0" * (WIRE_EVENT_SIZE - len(data))

    msg = WireEventMsg.from_buffer_copy(data)
    if strict and msg.magic != XSYPHER_WIRE_MAGIC:
        raise ValueError(f"bad wire magic 0x{msg.magic:08x}")
    if strict and msg.version != XSYPHER_ABI_VERSION:
        raise ValueError(f"unsupported ABI version {msg.version}")

    event = Event.from_struct(msg.event)
    event.seq_no = msg.seq_no
    event.container_id = _cstr(msg.container_id) or "host"
    event.raw = data
    return WireFrame(
        magic=msg.magic,
        version=msg.version,
        msg_type=msg.msg_type,
        seq_no=msg.seq_no,
        container_id=event.container_id,
        event=event,
    )


def encode_wire_frame(event: Event, *, seq_no: int = 0,
                      container_id: str | None = None) -> bytes:
    """Encode an :class:`Event` into a complete 736-byte wire frame."""
    msg = WireEventMsg()
    msg.magic = XSYPHER_WIRE_MAGIC
    msg.version = XSYPHER_ABI_VERSION
    msg.msg_type = MSG_TELEMETRY_EVENT
    msg.seq_no = seq_no
    msg.container_id = _id_bytes(
        container_id if container_id is not None else event.container_id,
        MAX_CONTAINER_ID_LEN,
    )
    msg.event = event.to_struct()
    return bytes(memoryview(msg))


@dataclass(slots=True)
class PolicyCommand:
    """Typed ``struct wire_policy_cmd_t``."""

    cmd_type: int
    target_cgroup_id: int = 0
    target_pid: int = 0
    target_ipv4: int = 0        # raw network byte order
    enforcement_mode: int = 0
    value: int = 0              # general 32-bit payload (was reserved0)

    def to_bytes(self) -> bytes:
        """Serialise into a 32-byte control datagram."""
        cmd = WirePolicyCmd()
        cmd.magic = XSYPHER_WIRE_MAGIC
        cmd.version = XSYPHER_ABI_VERSION
        cmd.cmd_type = self.cmd_type
        cmd.target_cgroup_id = self.target_cgroup_id
        cmd.target_pid = self.target_pid
        cmd.target_ipv4 = self.target_ipv4
        cmd.enforcement_mode = self.enforcement_mode
        cmd.value = self.value
        return bytes(memoryview(cmd))

    @classmethod
    def from_bytes(cls, data: bytes) -> "PolicyCommand":
        """Parse a 32-byte control datagram."""
        if len(data) != POLICY_CMD_SIZE:
            raise ValueError(
                f"policy command must be {POLICY_CMD_SIZE} bytes, got {len(data)}"
            )
        cmd = WirePolicyCmd.from_buffer_copy(data)
        if cmd.magic != XSYPHER_WIRE_MAGIC:
            raise ValueError(f"bad command magic 0x{cmd.magic:08x}")
        if cmd.version != XSYPHER_ABI_VERSION:
            raise ValueError(f"unsupported ABI version {cmd.version}")
        return cls(
            cmd_type=cmd.cmd_type,
            target_cgroup_id=cmd.target_cgroup_id,
            target_pid=cmd.target_pid,
            target_ipv4=cmd.target_ipv4,
            enforcement_mode=cmd.enforcement_mode,
            value=cmd.value,
        )

    @classmethod
    def quarantine_pid(cls, pid: int) -> "PolicyCommand":
        return cls(CmdType.QUARANTINE_PID, target_pid=pid)

    @classmethod
    def unquarantine_pid(cls, pid: int) -> "PolicyCommand":
        return cls(CmdType.UNQUARANTINE_PID, target_pid=pid)

    @classmethod
    def quarantine_cgroup(cls, cgroup_id: int) -> "PolicyCommand":
        return cls(CmdType.QUARANTINE_CGROUP, target_cgroup_id=cgroup_id)

    @classmethod
    def unquarantine_cgroup(cls, cgroup_id: int) -> "PolicyCommand":
        return cls(CmdType.UNQUARANTINE_CGROUP, target_cgroup_id=cgroup_id)

    @classmethod
    def block_ipv4(cls, address: str) -> "PolicyCommand":
        return cls(CmdType.BLOCK_IPV4, target_ipv4=ipv4_to_raw(address))

    @classmethod
    def unblock_ipv4(cls, address: str) -> "PolicyCommand":
        return cls(CmdType.UNBLOCK_IPV4, target_ipv4=ipv4_to_raw(address))

    @classmethod
    def set_enforcement_mode(cls, mode: int) -> "PolicyCommand":
        return cls(CmdType.SET_ENFORCEMENT_MODE, enforcement_mode=mode)

    @classmethod
    def set_heartbeat(cls, heartbeat_ns: int) -> "PolicyCommand":
        return cls(CmdType.SET_HEARTBEAT, target_cgroup_id=heartbeat_ns)

    @classmethod
    def set_fail_closed(cls, enabled: bool) -> "PolicyCommand":
        return cls(CmdType.SET_FAIL_CLOSED, value=1 if enabled else 0)

    @classmethod
    def set_shutdown_token(cls, token: int) -> "PolicyCommand":
        return cls(CmdType.SET_SHUTDOWN_TOKEN, value=token)

    @classmethod
    def protect_pid(cls, pid: int, token: int = 0) -> "PolicyCommand":
        return cls(CmdType.PROTECT_PID, target_pid=pid, value=token)

    @classmethod
    def unprotect_pid(cls, pid: int) -> "PolicyCommand":
        return cls(CmdType.UNPROTECT_PID, target_pid=pid)

    @classmethod
    def register_inode(cls, ino: int, dev: int) -> "PolicyCommand":
        return cls(CmdType.REGISTER_INODE, target_cgroup_id=ino,
                   target_pid=dev)

    @property
    def name(self) -> str:
        return CmdType.name(self.cmd_type)

    def describe(self) -> str:
        """Human readable one-liner for the TUI / JSONL audit log."""
        if self.cmd_type in (CmdType.QUARANTINE_PID, CmdType.UNQUARANTINE_PID):
            return f"{self.name}(pid={self.target_pid})"
        if self.cmd_type in (CmdType.QUARANTINE_CGROUP,
                             CmdType.UNQUARANTINE_CGROUP):
            return f"{self.name}(cgroup={self.target_cgroup_id})"
        if self.cmd_type in (CmdType.BLOCK_IPV4, CmdType.UNBLOCK_IPV4):
            return f"{self.name}(ip={ipv4_from_raw(self.target_ipv4)})"
        if self.cmd_type == CmdType.SET_HEARTBEAT:
            return f"{self.name}(ns={self.target_cgroup_id})"
        if self.cmd_type == CmdType.SET_FAIL_CLOSED:
            return f"{self.name}(enabled={bool(self.value)})"
        if self.cmd_type == CmdType.SET_SHUTDOWN_TOKEN:
            return f"{self.name}(token={self.value})"
        if self.cmd_type in (CmdType.PROTECT_PID, CmdType.UNPROTECT_PID):
            return f"{self.name}(pid={self.target_pid})"
        if self.cmd_type == CmdType.REGISTER_INODE:
            return f"{self.name}(ino={self.target_cgroup_id},dev={self.target_pid})"
        return f"{self.name}(mode={self.enforcement_mode})"


# Storage-layout report used by the verification script and README table.
def layout_report() -> list[tuple[str, int, list[tuple[str, int]]]]:
    """Return ``[(struct_name, size, [(field, offset), ...]), ...]``."""
    report = []
    for struct in (KernelEvent, WireEventMsg, WirePolicyCmd):
        fields = [
            (name, getattr(struct, name).offset)
            for name, _ctype in struct._fields_  # noqa: SLF001 - ctypes API
        ]
        report.append((struct.__name__, ctypes.sizeof(struct), fields))
    return report


__all__ = [
    "BlockReason",
    "CmdType",
    "Event",
    "EventType",
    "IMDS_IPV4",
    "IMDS_IPV4_BE",
    "IMDS_IPV4_RAW",
    "IMDS_IPV6",
    "IMDS_IPV6_RAW",
    "KERNEL_EVENT_SIZE",
    "KernelEvent",
    "LINEAGE_FLAG_AI_RUNTIME",
    "LINEAGE_FLAG_FAIL_CLOSED",
    "LINEAGE_FLAG_QUARANTINE",
    "MAX_ARGS_LEN",
    "MAX_COMM_LEN",
    "MAX_CONTAINER_ID_LEN",
    "MAX_PATH_LEN",
    "MSG_TELEMETRY_EVENT",
    "POLICY_CMD_SIZE",
    "PolicyCommand",
    "WIRE_EVENT_SIZE",
    "WireEventMsg",
    "WireFrame",
    "WirePolicyCmd",
    "XSYPHER_ABI_VERSION",
    "XSYPHER_PATH_BUF_LEN",
    "XSYPHER_RINGBUF_BYTES",
    "XSYPHER_WIRE_MAGIC",
    "decode_wire_frame",
    "encode_wire_frame",
    "ipv4_from_raw",
    "ipv4_to_raw",
    "layout_report",
    "port_from_raw",
]


class EgressKey(ctypes.Structure):
    """Native map key; addresses/port are raw network-order bytes."""
    _fields_ = [
        ("cgroup_id", ctypes.c_uint64),
        ("executable_ino", ctypes.c_uint64),
        ("executable_dev", ctypes.c_uint32),
        ("family", ctypes.c_uint16),
        ("port", ctypes.c_uint16),
        ("address", ctypes.c_uint8 * 16),
    ]


assert ctypes.sizeof(EgressKey) == 40
assert EgressKey.address.offset == 24
