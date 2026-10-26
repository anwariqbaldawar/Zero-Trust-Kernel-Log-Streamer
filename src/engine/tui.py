"""xSypher-Stream - ANSI live terminal monitor.

The TUI is intentionally line oriented (no curses, no alternate screen) so the
exact same output can be piped into a log aggregator.  Colour is enabled only
when the destination is a TTY and ``NO_COLOR`` is not set, matching the
convention used by most Unix tooling.
"""

from __future__ import annotations

import os
import shutil
import sys
from datetime import datetime, timezone
from typing import Any, Iterable, TextIO

from .abi import Event, EventType
from .rule_engine import RuleMatch

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

FG_RED = "\033[31m"
FG_GREEN = "\033[32m"
FG_YELLOW = "\033[33m"
FG_BLUE = "\033[34m"
FG_MAGENTA = "\033[35m"
FG_CYAN = "\033[36m"
FG_WHITE = "\033[37m"
BG_RED = "\033[41m"

SEVERITY_COLORS = {
    "critical": FG_RED + BOLD,
    "high": FG_RED,
    "medium": FG_YELLOW,
    "low": FG_CYAN,
    "info": FG_BLUE,
}

EVENT_COLORS = {
    EventType.EXECVE: FG_GREEN,
    EventType.CONNECT: FG_CYAN,
    EventType.OPENAT: FG_YELLOW,
    EventType.MEMFD_CREATE: FG_MAGENTA,
    EventType.PROCESS_EXIT: DIM + FG_WHITE,
    EventType.LSM_BLOCK: FG_RED + BOLD,
}

EVENT_LABELS = {
    EventType.EXECVE: "EXEC",
    EventType.CONNECT: "CONN",
    EventType.OPENAT: "OPEN",
    EventType.MEMFD_CREATE: "MEMFD",
    EventType.PROCESS_EXIT: "EXIT",
    EventType.LSM_BLOCK: "LSM!",
}


def _now_text() -> str:
    return datetime.now(tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]


def _short_container(container_id: str) -> str:
    if not container_id or container_id == "host":
        return "host"
    return container_id[:12]


class Tui:
    """Renders telemetry, alerts and status lines."""

    def __init__(
        self,
        stream: TextIO | None = None,
        *,
        color: bool | None = None,
        verbose: bool = False,
        show_ancestry: bool = True,
        width: int | None = None,
        show_events: bool = True,
    ) -> None:
        self.stream = stream if stream is not None else sys.stdout
        if color is None:
            color = self._auto_color(self.stream)
        self.color = color
        self.verbose = verbose
        self.show_ancestry = show_ancestry
        self.show_events = show_events
        self._width = width or self._detect_width()
        self._alerts = 0
        self._events = 0

    # -- setup ------------------------------------------------------------- #
    @staticmethod
    def _auto_color(stream: TextIO) -> bool:
        if os.environ.get("NO_COLOR"):
            return False
        try:
            return bool(stream.isatty())
        except (AttributeError, ValueError):
            return False

    def _detect_width(self) -> int:
        try:
            return max(60, shutil.get_terminal_size((120, 24)).columns)
        except OSError:
            return 120

    def paint(self, text: str, color: str) -> str:
        return f"{color}{text}{RESET}" if self.color else text

    def _write(self, line: str) -> None:
        if self._width and len(line) > self._width + 32:
            line = line[: self._width + 29] + "..."
        try:
            self.stream.write(line + "\n")
            self.stream.flush()
        except (BrokenPipeError, ValueError):
            # Terminal went away (e.g. `| head`): stop writing but keep working.
            self.show_events = False

    # -- output ------------------------------------------------------------ #
    def banner(self, *, socket_path: str, rules: int, enforcing: bool,
               active_kill: bool, metrics_url: str, collector_connected: bool) -> None:
        title = self.paint("xSypher-Stream", BOLD + FG_MAGENTA)
        subtitle = self.paint("zero-trust kernel telemetry & inline LSM enforcement", DIM)
        mode = self.paint("INLINE_BLOCK" if enforcing else "AUDIT_ONLY",
                          BG_RED + BOLD if enforcing else FG_CYAN)
        self._write("")
        self._write(f"  {title}  {subtitle}")
        self._write(
            f"  mode={mode} rules={rules} kill={'on' if active_kill else 'off'} "
            f"collector={'connected' if collector_connected else 'pending'} "
            f"socket={socket_path}"
        )
        self._write(f"  metrics={metrics_url}   (Ctrl-C to stop)")
        self._write(self.paint("  " + "-" * min(110, self._width - 4), DIM))

    def event_line(self, event: Event, matches: Iterable[RuleMatch] = ()) -> None:
        """Render one telemetry line (suppressed in quiet mode)."""
        if not self.show_events and not self.verbose:
            return

        match_list = list(matches)
        if not self.verbose and not match_list and self._is_noise(event):
            return

        self._events += 1
        stamp = self.paint(_now_text(), DIM)
        label = EVENT_LABELS.get(event.event_type, f"EV{event.event_type}")
        label_text = self.paint(f"{label:<5}", EVENT_COLORS.get(event.event_type, FG_WHITE))

        detail = self._describe_event(event)
        alert = ""
        if match_list:
            worst = max(match_list, key=lambda m: m.level)
            alert = "  " + self.paint(f"! {worst.rule_id}", SEVERITY_COLORS.get(worst.severity, FG_RED))

        self._write(
            f"{stamp} {label_text} pid={event.pid:<7} tgid={event.tgid:<7} "
            f"cont={self.paint(_short_container(event.container_id), FG_BLUE)} {detail}{alert}"
        )

    @staticmethod
    def _is_noise(event: Event) -> bool:
        return event.event_type == EventType.PROCESS_EXIT

    def _describe_event(self, event: Event) -> str:
        name = self.paint(event.comm or "?", BOLD)
        if event.event_type == EventType.CONNECT:
            peer = event.daddr_v4 or event.daddr_v6 or "?"
            return f"{name:<16} -> {peer}:{event.dport} (af={event.af_family})"
        if event.event_type == EventType.OPENAT:
            flags = []
            if event.open_flags & 0o1:
                flags.append("W")
            if event.open_flags & 0o2:
                flags.append("RW")
            if event.open_flags & 0o100:
                flags.append("CREAT")
            suffix = f" [{','.join(flags)}]" if flags else ""
            return f"{name:<16} {event.filename}{suffix}"
        if event.event_type == EventType.MEMFD_CREATE:
            return f"{name:<16} memfd:{event.filename or '?'}"
        if event.event_type == EventType.LSM_BLOCK:
            return f"{name:<16} DENIED {event.filename or '?'} (ret={event.retval})"
        text = f"{name:<16} {event.filename or ''}"
        if event.args:
            text += f" {event.args}"
        return text

    def alert(self, result: Any, *, show_ancestry: bool | None = None) -> None:
        """Render a full alert block from a MitigationResult."""
        match: RuleMatch = result.match
        event = match.event
        self._alerts += 1

        color = SEVERITY_COLORS.get(match.severity, FG_RED)
        header = f"{match.severity.upper():<8} {match.rule_id}"
        alert_id = getattr(result, "alert_id", "")

        self._write("")
        self._write("  " + self.paint(f"╔═ ALERT {alert_id} ", color) + self.paint("═" * 20, DIM))
        self._write("  " + self.paint(f"║ {header}", color))
        self._write(f"  ║ {self.paint(match.title, BOLD)}")
        if match.description:
            self._write(f"  ║ {self.paint(match.description, DIM)}")
        self._write(f"  ║ subject : {event.comm or '?'} pid={event.pid} tgid={event.tgid} "
                    f"uid={event.uid} container={_short_container(event.container_id)}")
        if event.filename:
            location = event.filename
            if event.args:
                location += f" {event.args}"
            self._write(f"  ║ observed: {location}")
        if event.event_type == EventType.CONNECT:
            self._write(f"  ║ network : {event.daddr_v4 or event.daddr_v6}:{event.dport}")
        self._write(f"  ║ reason  : {match.reason}")

        show_chain = self.show_ancestry if show_ancestry is None else show_ancestry
        if show_chain and match.ancestry:
            chain = " -> ".join(reversed(list(match.ancestry)))
            self._write(f"  ║ lineage : {chain} -> {event.comm or '?'}[{event.pid}]")

        actions = result.action_names() if hasattr(result, "action_names") else []
        detail = []
        for entry in result.record.get("mitigations", []):
            marker = "ok" if entry.get("delivered") else "skipped"
            detail.append(f"{entry.get('command')}({entry.get('target')})={marker}")
        if actions:
            self._write(f"  ║ actions : {', '.join(detail) or ', '.join(actions)}")
        elif detail:
            self._write(f"  ║ actions : {', '.join(detail)}")
        if getattr(result, "killed", False):
            self._write(f"  ║ kill    : SIGKILL delivered to pid {event.tgid or event.pid}")
        elif getattr(result, "kill_error", None):
            self._write(f"  ║ kill    : {result.kill_error}")
        self._write("  " + self.paint("╚" + "═" * 40, DIM))
        self._write("")

    def status(self, payload: dict[str, Any]) -> None:
        """Render a compact status line (events/s, alerts, tracked processes)."""
        parts = [f"{key}={value}" for key, value in payload.items()]
        self._write(self.paint("  [status] " + "  ".join(parts), DIM))

    def info(self, message: str) -> None:
        self._write(self.paint(f"  [..] {message}", FG_CYAN))

    def warn(self, message: str) -> None:
        self._write(self.paint(f"  [!!] {message}", FG_YELLOW))

    def error(self, message: str) -> None:
        self._write(self.paint(f"  [xx] {message}", FG_RED + BOLD))

    def good(self, message: str) -> None:
        self._write(self.paint(f"  [ok] {message}", FG_GREEN))

    @property
    def counters(self) -> dict[str, int]:
        return {"events": self._events, "alerts": self._alerts}


__all__ = ["SEVERITY_COLORS", "Tui"]
