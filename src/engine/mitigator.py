"""xSypher-Stream - active response and tamper-evident audit trail.

Responsibilities
----------------
1. Translate a :class:`~engine.rule_engine.RuleMatch` into concrete kernel
   policy commands (:class:`~engine.abi.PolicyCommand`) and push them down to
   the C++ collector, which applies them to the eBPF maps.
2. Optionally deliver an immediate user-space ``SIGKILL`` (defence in depth for
   kernels without BPF-LSM).
3. Append a structured JSONL audit record for every alert, where each record
   commits to the hash of the previous one (SHA-256 chain).  Editing or
   deleting a line invalidates every subsequent hash, so the log is
   tamper-evident without external infrastructure.

The chain is::

    hash_n = SHA256(hex(hash_{n-1}) || canonical_json(record_n without "hash"/"alert_id"))

with ``hash_0 = "0" * 64`` (genesis).
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import signal
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Sequence

from .abi import (
    IMDS_IPV4,
    CmdType,
    Event,
    PolicyCommand,
    ipv4_to_raw,
)
from .rule_engine import RuleMatch

GENESIS_HASH = "0" * 64
ALERT_SCHEMA = "xsypher.alert.v2"

#: Signature of the sink that ships policy commands to the collector.  It may be
#: a plain callable or a coroutine function; both are supported.
CommandSink = Callable[[PolicyCommand], Any]


def _canonical(record: dict[str, Any]) -> str:
    """Deterministic JSON encoding used for hashing."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _iso_timestamp(timestamp_ns: int) -> str:
    seconds, nanos = divmod(timestamp_ns, 1_000_000_000)
    stamp = datetime.fromtimestamp(seconds, tz=timezone.utc)
    return f"{stamp.strftime('%Y-%m-%dT%H:%M:%S')}.{nanos:09d}Z"


class AlertLog:
    """Append-only, SHA-256 hash-chained JSONL audit log."""

    def __init__(self, path: str, *, fsync: bool = False) -> None:
        self.path = path
        self.fsync = fsync
        self._last_hash = GENESIS_HASH
        self._sequence = 0
        self._handle = None
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._load_tail()

    # -- chain state ------------------------------------------------------- #
    def _load_tail(self) -> None:
        """Resume the chain from the last valid record of an existing log."""
        if not os.path.exists(self.path) or os.path.getsize(self.path) == 0:
            return
        last_line = ""
        with open(self.path, "r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last_line = line
        if not last_line:
            return
        try:
            record = json.loads(last_line)
        except json.JSONDecodeError:
            return
        digest = record.get("hash")
        if isinstance(digest, str) and len(digest) == 64:
            self._last_hash = digest
        sequence = record.get("sequence")
        if isinstance(sequence, int):
            self._sequence = sequence + 1

    @property
    def last_hash(self) -> str:
        return self._last_hash

    @property
    def sequence(self) -> int:
        return self._sequence

    # -- writing ----------------------------------------------------------- #
    #: Fields excluded from the committed payload: ``hash`` is the digest itself
    #: and ``alert_id`` is derived from it (so it cannot be part of its input).
    _UNCOMMITTED_FIELDS = ("hash", "prev_hash", "alert_id")

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        """Hash-chain and persist one record; returns it with hash fields set."""
        payload = {key: value for key, value in record.items()
                   if key not in self._UNCOMMITTED_FIELDS}
        payload["prev_hash"] = self._last_hash
        payload["sequence"] = self._sequence
        digest = hashlib.sha256(
            (self._last_hash + _canonical(payload)).encode("utf-8")
        ).hexdigest()
        payload["hash"] = digest
        payload["alert_id"] = digest[:16]

        line = _canonical(payload) + "\n"
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
            if self.fsync:
                os.fsync(handle.fileno())

        self._last_hash = digest
        self._sequence += 1
        return payload

    # -- verification ------------------------------------------------------ #
    @staticmethod
    def verify(path: str) -> tuple[bool, int, str | None]:
        """Verify the whole chain.  Returns ``(ok, records, error)``."""
        if not os.path.exists(path):
            return True, 0, None

        previous = GENESIS_HASH
        count = 0
        with open(path, "r", encoding="utf-8") as handle:
            for lineno, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    return False, count, f"line {lineno}: invalid JSON ({exc})"
                stored = record.pop("hash", None)
                if stored is None:
                    return False, count, f"line {lineno}: missing 'hash'"
                record.pop("alert_id", None)
                if record.get("prev_hash") != previous:
                    return False, count, (
                        f"line {lineno}: prev_hash mismatch "
                        f"(expected {previous[:16]}..., got {str(record.get('prev_hash'))[:16]}...)"
                    )
                expected = hashlib.sha256(
                    (previous + _canonical(record)).encode("utf-8")
                ).hexdigest()
                if expected != stored:
                    return False, count, f"line {lineno}: hash mismatch (record was modified)"
                previous = stored
                count += 1
        return True, count, None


@dataclass(slots=True)
class MitigationResult:
    """Outcome of handling one rule match."""

    match: RuleMatch
    record: dict[str, Any] = field(default_factory=dict)
    commands: list[PolicyCommand] = field(default_factory=list)
    killed: bool = False
    kill_error: str | None = None
    enforced: bool = True

    @property
    def alert_id(self) -> str:
        return str(self.record.get("alert_id", ""))

    def action_names(self) -> list[str]:
        return [command.name for command in self.commands]


class Mitigator:
    """Executes rule actions and writes the audit trail."""

    def __init__(
        self,
        alert_log: AlertLog,
        *,
        command_sink: CommandSink | None = None,
        active_kill: bool = False,
        enforce: bool = True,
        allow_kill_pid_below: int = 2,
        clock: Callable[[], int] = time.time_ns,
        log: Callable[[str], None] | None = None,
    ) -> None:
        self.alert_log = alert_log
        self._sink = command_sink
        self.active_kill = active_kill
        self.enforce = enforce
        self._min_kill_pid = int(allow_kill_pid_below)
        self._clock = clock
        self._log = log or (lambda _message: None)
        # Deduplication: never re-send the same kernel state transition.
        self._quarantined_pids: set[int] = set()
        self._quarantined_cgroups: set[int] = set()
        self._blocked_ips: set[int] = set()
        self.commands_sent = 0
        self.alerts_written = 0
        self.kills_delivered = 0
        self.kills_failed = 0
        self.suppressed_commands = 0

    # -- public API -------------------------------------------------------- #
    def set_sink(self, sink: CommandSink | None) -> None:
        self._sink = sink

    async def handle(self, match: RuleMatch, lineage=None) -> MitigationResult:
        """Apply every action of ``match`` and persist the audit record."""
        event = match.event
        pid = event.tgid or event.pid
        result = MitigationResult(match=match, enforced=self.enforce)
        actions_taken: list[dict[str, Any]] = []

        for action in match.actions:
            command = self._command_for(action, event, pid)
            if command is None:
                continue

            if self.enforce and not match.monitored:
                delivered = await self._dispatch(command)
                result.commands.append(command)
                actions_taken.append(
                    {
                        "action": action,
                        "command": command.name,
                        "target": self._target_of(command),
                        "delivered": delivered,
                    }
                )
            else:
                self.suppressed_commands += 1
                actions_taken.append(
                    {
                        "action": action,
                        "command": command.name,
                        "target": self._target_of(command),
                        "delivered": False,
                        "detail": "audit-only mode",
                    }
                )

        if self.active_kill and not match.monitored:
            killed, error = self._kill(pid)
            result.killed = killed
            result.kill_error = error
            actions_taken.append(
                {
                    "action": "kill",
                    "command": "sigkill",
                    "target": pid,
                    "delivered": killed,
                    "detail": error or "SIGKILL delivered to user space",
                }
            )

        record = self._build_record(match, actions_taken, result)
        result.record = self.alert_log.append(record)
        self.alerts_written += 1
        self._log(
            f"alert {result.record['alert_id']} {match.rule_id} "
            f"severity={match.severity} pid={pid} actions={len(actions_taken)}"
        )
        return result

    # -- internals --------------------------------------------------------- #
    @staticmethod
    def _target_of(command: PolicyCommand) -> Any:
        if command.cmd_type in (CmdType.QUARANTINE_PID, CmdType.UNQUARANTINE_PID):
            return command.target_pid
        if command.cmd_type in (CmdType.QUARANTINE_CGROUP, CmdType.UNQUARANTINE_CGROUP):
            return command.target_cgroup_id
        if command.cmd_type in (CmdType.BLOCK_IPV4, CmdType.UNBLOCK_IPV4):
            from .abi import ipv4_from_raw  # local import keeps the hot path lean

            return ipv4_from_raw(command.target_ipv4)
        return command.enforcement_mode

    def _command_for(self, action: str, event: Event, pid: int) -> PolicyCommand | None:
        if action == "quarantine_pid":
            if pid in self._quarantined_pids:
                return None
            self._quarantined_pids.add(pid)
            return PolicyCommand.quarantine_pid(pid)

        if action == "quarantine_cgroup":
            if event.cgroup_id == 0 or event.cgroup_id in self._quarantined_cgroups:
                return None
            self._quarantined_cgroups.add(event.cgroup_id)
            return PolicyCommand.quarantine_cgroup(event.cgroup_id)

        if action in ("block_ipv4", "block_imds"):
            address = event.daddr_v4 if action == "block_ipv4" and event.daddr_v4 else IMDS_IPV4
            if not address:
                return None
            try:
                raw = ipv4_to_raw(address)
            except OSError:
                return None
            if raw in self._blocked_ips:
                return None
            self._blocked_ips.add(raw)
            return PolicyCommand.block_ipv4(address)

        # "kill" is executed in user space, never as a kernel map command.
        return None

    async def _dispatch(self, command: PolicyCommand) -> bool:
        if self._sink is None:
            return False
        try:
            outcome = self._sink(command)
            if inspect.isawaitable(outcome):
                await outcome  # type: ignore[func-returns-value]
            self.commands_sent += 1
            return True
        except (BrokenPipeError, ConnectionError, OSError) as exc:
            self._log(f"command {command.describe()} failed: {exc}")
            return False

    def _kill(self, pid: int) -> tuple[bool, str | None]:
        if pid <= self._min_kill_pid:
            self.kills_failed += 1
            return False, f"refusing to kill pid {pid} (below {self._min_kill_pid})"
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            self.kills_failed += 1
            return False, f"pid {pid} already gone"
        except PermissionError as exc:
            self.kills_failed += 1
            return False, f"permission denied killing pid {pid}: {exc}"
        except OSError as exc:
            self.kills_failed += 1
            return False, f"failed to kill pid {pid}: {exc}"
        self.kills_delivered += 1
        return True, None

    def _build_record(
        self,
        match: RuleMatch,
        actions_taken: Sequence[dict[str, Any]],
        result: MitigationResult,
    ) -> dict[str, Any]:
        event = match.event
        timestamp_ns = int(self._clock())
        return {
            "schema": ALERT_SCHEMA,
            "timestamp": _iso_timestamp(timestamp_ns),
            "timestamp_ns": timestamp_ns,
            "event_timestamp_ns": int(event.timestamp_ns),
            "rule": match.rule_id,
            "title": match.title,
            "severity": match.severity,
            "severity_level": match.level,
            "reason": match.reason,
            "tags": list(match.tags),
            "declared_actions": list(match.actions),
            "monitored": match.monitored,
            "enforced": result.enforced,
            "subject": {
                "pid": event.pid,
                "tgid": event.tgid,
                "comm": event.comm,
                "parent_comm": event.parent_comm,
                "uid": event.uid,
                "gid": event.gid,
                "cgroup_id": event.cgroup_id,
                "container_id": event.container_id,
                "mnt_ns_id": event.mnt_ns_id,
                "pid_ns_id": event.pid_ns_id,
                "net_ns_id": event.net_ns_id,
            },
            "event": {
                "type": event.event_name,
                "filename": event.filename,
                "args": event.args,
                "daddr_v4": event.daddr_v4,
                "daddr_v6": event.daddr_v6,
                "dport": event.dport,
                "open_flags": event.open_flags,
                "blocked_by_lsm": bool(event.blocked_by_lsm),
                "seq_no": event.seq_no,
            },
            "ancestry": list(match.ancestry),
            "mitigations": list(actions_taken),
            "killed": result.killed,
        }

    # -- bookkeeping ------------------------------------------------------- #
    @property
    def stats(self) -> dict[str, int]:
        return {
            "alerts": self.alerts_written,
            "commands_sent": self.commands_sent,
            "suppressed_commands": self.suppressed_commands,
            "kills_delivered": self.kills_delivered,
            "kills_failed": self.kills_failed,
            "quarantined_pids": len(self._quarantined_pids),
            "quarantined_cgroups": len(self._quarantined_cgroups),
            "blocked_ips": len(self._blocked_ips),
        }

    def release_all(self) -> list[PolicyCommand]:
        """Build the inverse commands for every enforced action."""
        commands: list[PolicyCommand] = []
        for pid in sorted(self._quarantined_pids):
            commands.append(PolicyCommand.unquarantine_pid(pid))
        for cgroup_id in sorted(self._quarantined_cgroups):
            commands.append(PolicyCommand.unquarantine_cgroup(cgroup_id))
        for raw in sorted(self._blocked_ips):
            from .abi import ipv4_from_raw  # local import

            commands.append(PolicyCommand.unblock_ipv4(ipv4_from_raw(raw)))
        self._quarantined_pids.clear()
        self._quarantined_cgroups.clear()
        self._blocked_ips.clear()
        return commands

    async def release_all_async(self) -> int:
        """Send the inverse commands; returns how many were delivered."""
        delivered = 0
        for command in self.release_all():
            if await self._dispatch(command):
                delivered += 1
        return delivered


async def collect_commands(sink: list[PolicyCommand]) -> CommandSink:
    """Test helper: a sink that simply records the commands it receives."""

    def _record(command: PolicyCommand) -> None:
        sink.append(command)

    return _record


def summarize_commands(commands: Iterable[PolicyCommand]) -> list[str]:
    """Render commands for logging."""
    return [command.describe() for command in commands]


__all__ = [
    "ALERT_SCHEMA",
    "AlertLog",
    "CommandSink",
    "GENESIS_HASH",
    "MitigationResult",
    "Mitigator",
    "collect_commands",
    "summarize_commands",
]
