"""xSypher-Stream - zero-dependency Prometheus exporter.

A tiny :mod:`asyncio` HTTP/1.1 server exposing ``/metrics`` in the Prometheus
text exposition format, plus ``/healthz`` for liveness probes.  No third party
packages are used, so the engine can ship into a distroless container with only
the Python standard library.
"""

from __future__ import annotations

import asyncio
import math
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

MAX_REQUESTS_BEFORE_CLOSE = 1000
REQUEST_TIMEOUT_SECONDS = 5.0


def _escape_label(value: str) -> str:
    """Escape a label value per the Prometheus exposition format."""
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _format_value(value: float) -> str:
    if isinstance(value, int) or (isinstance(value, float) and value.is_integer()):
        return str(int(value))
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "+Inf" if value > 0 else "-Inf"
    return repr(float(value))


def _label_key(labels: Mapping[str, Any] | None) -> tuple[tuple[str, str], ...]:
    if not labels:
        return ()
    return tuple(sorted((str(k), str(v)) for k, v in labels.items()))


@dataclass(slots=True)
class _Family:
    name: str
    type: str
    help: str
    samples: dict[tuple[tuple[str, str], ...], float] = field(default_factory=dict)
    sums: dict[tuple[tuple[str, str], ...], float] = field(default_factory=dict)
    counts: dict[tuple[tuple[str, str], ...], float] = field(default_factory=dict)


class MetricsRegistry:
    """In-process metric store with Prometheus text rendering."""

    def __init__(self) -> None:
        self._families: dict[str, _Family] = {}
        self._order: list[str] = []
        self.started_at = time.time()

    # -- registration ------------------------------------------------------ #
    def _declare(self, name: str, metric_type: str, help_text: str) -> _Family:
        family = self._families.get(name)
        if family is None:
            family = _Family(name=name, type=metric_type, help=help_text)
            self._families[name] = family
            self._order.append(name)
        return family

    def counter(self, name: str, help_text: str) -> None:
        self._declare(name, "counter", help_text)

    def gauge(self, name: str, help_text: str) -> None:
        self._declare(name, "gauge", help_text)

    def summary(self, name: str, help_text: str) -> None:
        self._declare(name, "summary", help_text)

    # -- mutation ---------------------------------------------------------- #
    def inc(self, name: str, labels: Mapping[str, Any] | None = None, value: float = 1) -> None:
        family = self._families.get(name)
        if family is None:
            family = self._declare(name, "counter", name)
        key = _label_key(labels)
        family.samples[key] = family.samples.get(key, 0.0) + value

    def set(self, name: str, value: float, labels: Mapping[str, Any] | None = None) -> None:
        family = self._families.get(name)
        if family is None:
            family = self._declare(name, "gauge", name)
        family.samples[_label_key(labels)] = float(value)

    def observe(self, name: str, value: float, labels: Mapping[str, Any] | None = None) -> None:
        """Record an observation into a summary (``_sum`` / ``_count``)."""
        family = self._families.get(name)
        if family is None:
            family = self._declare(name, "summary", name)
        key = _label_key(labels)
        family.sums[key] = family.sums.get(key, 0.0) + float(value)
        family.counts[key] = family.counts.get(key, 0.0) + 1.0

    def get(self, name: str, labels: Mapping[str, Any] | None = None) -> float:
        family = self._families.get(name)
        if family is None:
            return 0.0
        return family.samples.get(_label_key(labels), 0.0)

    # -- rendering --------------------------------------------------------- #
    def render(self) -> str:
        """Render every registered metric family in Prometheus text format."""
        lines: list[str] = []
        for name in self._order:
            family = self._families[name]
            lines.append(f"# HELP {name} {family.help}")
            lines.append(f"# TYPE {name} {family.type}")

            for key, value in sorted(family.samples.items()):
                lines.append(f"{name}{self._labels(key)} {_format_value(value)}")

            if family.type == "summary":
                for key, value in sorted(family.sums.items()):
                    lines.append(f"{name}_sum{self._labels(key)} {_format_value(value)}")
                for key, value in sorted(family.counts.items()):
                    lines.append(f"{name}_count{self._labels(key)} {_format_value(value)}")

        lines.append("# HELP xsypher_engine_uptime_seconds Seconds since engine start")
        lines.append("# TYPE xsypher_engine_uptime_seconds gauge")
        lines.append(
            f"xsypher_engine_uptime_seconds {_format_value(time.time() - self.started_at)}"
        )
        return "\n".join(lines) + "\n"

    @staticmethod
    def _labels(key: Iterable[tuple[str, str]]) -> str:
        pairs = list(key)
        if not pairs:
            return ""
        body = ",".join(f'{name}="{_escape_label(value)}"' for name, value in pairs)
        return "{" + body + "}"

    def snapshot(self) -> dict[str, float]:
        """Flat ``{series: value}`` view used by tests and the TUI."""
        result: dict[str, float] = {}
        for name in self._order:
            family = self._families[name]
            for key, value in family.samples.items():
                result[f"{name}{self._labels(key)}"] = value
            for key, value in family.sums.items():
                result[f"{name}_sum{self._labels(key)}"] = value
            for key, value in family.counts.items():
                result[f"{name}_count{self._labels(key)}"] = value
        return result


class MetricsServer:
    """Minimal asyncio HTTP server for ``/metrics``."""

    def __init__(
        self,
        registry: MetricsRegistry,
        host: str = "0.0.0.0",
        port: int = 9109,
        *,
        extra_paths: Mapping[str, str] | None = None,
    ) -> None:
        self.registry = registry
        self.host = host
        self.port = int(port)
        self._server: asyncio.AbstractServer | None = None
        self._extra_paths = dict(extra_paths or {})
        self.requests_served = 0

    @property
    def bound_port(self) -> int:
        if self._server is None or not self._server.sockets:
            return self.port
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self) -> int:
        """Start listening; returns the effective port."""
        self._server = await asyncio.start_server(
            self._handle_client, host=self.host, port=self.port, reuse_address=True
        )
        return self.bound_port

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        try:
            await self._server.wait_closed()
        except (asyncio.CancelledError, RuntimeError):
            pass
        self._server = None

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            request = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=REQUEST_TIMEOUT_SECONDS
            )
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
            writer.close()
            return

        try:
            request_line = request.split(b"\r\n", 1)[0].decode("latin-1")
        except UnicodeDecodeError:
            request_line = ""
        parts = request_line.split(" ")
        method = parts[0] if parts else ""
        path = parts[1] if len(parts) > 1 else "/"
        # Strip a query string, if any.
        path = path.split("?", 1)[0]

        self.requests_served += 1
        status, body, content_type = self._route(method, path)
        payload = body.encode("utf-8")
        headers = (
            f"HTTP/1.1 {status}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(payload)}\r\n"
            "Connection: close\r\n"
            "Cache-Control: no-store\r\n"
            "\r\n"
        )
        try:
            writer.write(headers.encode("latin-1") + payload)
            await writer.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _route(self, method: str, path: str) -> tuple[str, str, str]:
        if method not in ("GET", "HEAD"):
            return "405 Method Not Allowed", "method not allowed\n", CONTENT_TYPE
        if path in ("/metrics", "/metrics/"):
            return "200 OK", self.registry.render(), CONTENT_TYPE
        if path in ("/healthz", "/health", "/"):
            return "200 OK", "ok\n", "text/plain; charset=utf-8"
        if path in self._extra_paths:
            return "200 OK", self._extra_paths[path], "text/plain; charset=utf-8"
        return "404 Not Found", "not found\n", "text/plain; charset=utf-8"


# --------------------------------------------------------------------------- #
# Standard metric families used by the engine
# --------------------------------------------------------------------------- #

def build_registry() -> MetricsRegistry:
    """Create and pre-declare every metric the engine emits."""
    registry = MetricsRegistry()
    registry.counter("xsypher_events_total", "Kernel telemetry events processed, by type")
    registry.counter("xsypher_alerts_total", "Rule alerts raised, by rule and severity")
    registry.counter("xsypher_mitigations_total", "Mitigations executed, by action")
    registry.gauge("xsypher_active_tracked_processes", "Processes currently tracked in the lineage graph")
    registry.gauge("xsypher_rule_cooldowns_active", "Active per-(rule, pid) cooldown entries")
    registry.gauge("xsypher_ringbuf_frames_dropped", "Wire frames dropped by the collector")
    registry.counter("xsypher_lsm_blocks_seen", "Inline LSM denials observed in telemetry")
    registry.counter("xsypher_enforced_inline_events_total",
                     "Synchronous in-kernel denials, by block reason")
    registry.gauge("xsypher_collector_status", "1 when the collector heartbeat is fresh, else 0")
    registry.gauge("xsypher_collector_heartbeat_age_seconds", "Age of the last collector heartbeat")
    registry.counter("xsypher_commands_sent_total", "Policy commands sent to the collector")
    registry.counter("xsypher_commands_failed_total", "Policy commands that failed to send")
    registry.summary("xsypher_rule_eval_seconds", "Time spent evaluating rules per event")
    registry.counter("xsypher_socket_reconnects_total", "Reconnects to the collector Unix socket")
    return registry


__all__ = [
    "CONTENT_TYPE",
    "MetricsRegistry",
    "MetricsServer",
    "build_registry",
]
