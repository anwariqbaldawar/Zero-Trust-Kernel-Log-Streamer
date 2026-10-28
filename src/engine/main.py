"""xSypher-Stream - Python orchestration, threat engine and observability.

The engine is the policy brain of the system:

    kernel (eBPF)  ->  C++ collector  --AF_UNIX/SEQPACKET-->  this process
                            ^                                   |
                            +---- wire_policy_cmd_t (32 B) -----+

Responsibilities
----------------
* decode binary telemetry frames (``wire_event_msg_t``, 736 bytes)
* maintain the process lineage graph
* evaluate the declarative YAML rule set
* push quarantine / IP-block commands back into the kernel maps
* export Prometheus metrics and a hash-chained JSONL audit log
* render the live ANSI monitor

Run it with::

    python3 -m engine.main --socket-path /run/xsypher/stream.sock --enforce-kernel

or, without root or eBPF, in synthetic mode::

    python3 -m engine.main --simulate
"""

from __future__ import annotations

import argparse
import asyncio
import os
import random
import signal
import socket
import sys
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Deque, Iterable

from .abi import (
    WIRE_EVENT_SIZE,
    BlockReason,
    Event,
    EventType,
    PolicyCommand,
    decode_wire_frame,
)
from .lineage import LineageGraph
from .metrics import MetricsRegistry, MetricsServer, build_registry
from .mitigator import AlertLog, Mitigator
from .rule_engine import RuleEngine, RuleMatch
from .tui import Tui

__version__ = "2.0.0"

DEFAULT_SOCKET_PATHS: tuple[str, ...] = (
    "/run/xsypher/stream.sock",
    "/tmp/xsypher-stream.sock",
)
DEFAULT_ALERT_LOG = "/var/log/xsypher-alerts.jsonl"
FALLBACK_ALERT_LOG = "/tmp/xsypher-alerts.jsonl"
DEFAULT_METRICS_PORT = 9109

REPO_ROOT = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

@dataclass
class EngineConfig:
    """Everything the engine needs, resolved from CLI/env/defaults."""

    socket_path: str = DEFAULT_SOCKET_PATHS[0]
    rules_path: str = ""
    alert_log_path: str = DEFAULT_ALERT_LOG
    metrics_host: str = "0.0.0.0"
    metrics_port: int = DEFAULT_METRICS_PORT
    enforce_kernel: bool = False
    active_kill: bool = False
    simulate: bool = False
    simulate_count: int = 0
    simulate_seed: int = 1337
    color: bool | None = None
    verbose: bool = False
    quiet: bool = False
    lineage_ttl: float = 5.0
    max_tracked: int = 200_000
    reconnect_interval: float = 1.0
    fsync_alerts: bool = False
    fail_closed: bool = False
    heartbeat_interval: float = 2.0
    collector_timeout: float = 10.0
    shutdown_token: int = 0


def default_rules_path() -> str:
    """Locate config/rules.yaml (env -> repo checkout -> /etc)."""
    env = os.environ.get("XSYPHER_RULES")
    if env:
        return env
    for candidate in (
        REPO_ROOT / "config" / "rules.yaml",
        Path.cwd() / "config" / "rules.yaml",
        Path("/etc/xsypher/rules.yaml"),
    ):
        if candidate.is_file():
            return str(candidate)
    return str(REPO_ROOT / "config" / "rules.yaml")


def _resolve_alert_log(configured: str, explicit: bool) -> tuple[str, str | None]:
    """Pick a writable alert log; returns ``(path, warning)``."""
    def writable(path: str) -> bool:
        directory = os.path.dirname(os.path.abspath(path)) or "."
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError:
            return False
        return os.access(directory, os.W_OK)

    if writable(configured):
        return configured, None
    if not explicit and writable(FALLBACK_ALERT_LOG):
        return (
            FALLBACK_ALERT_LOG,
            f"alert log {configured} is not writable; falling back to {FALLBACK_ALERT_LOG}",
        )
    raise SystemExit(f"error: alert log directory for {configured} is not writable")


# --------------------------------------------------------------------------- #
# UDS transport
# --------------------------------------------------------------------------- #

class UdsTransport:
    """Non-blocking AF_UNIX/SOCK_SEQPACKET client used by the engine."""

    def __init__(
        self,
        path: str,
        *,
        loop: asyncio.AbstractEventLoop | None = None,
        on_frame: Callable[[bytes], None] | None = None,
        on_connect: Callable[[], None] | None = None,
        on_disconnect: Callable[[], None] | None = None,
    ) -> None:
        self.path = path
        self._loop = loop
        self._sock: socket.socket | None = None
        self._on_frame = on_frame
        self._on_connect = on_connect
        self._on_disconnect = on_disconnect
        self._outbox: Deque[bytes] = deque()
        self._writer_registered = False
        self._closed = False
        self.frames_received = 0
        self.bytes_sent = 0
        self.connect_count = 0
        self.last_error: str | None = None

    # -- lifecycle --------------------------------------------------------- #
    @property
    def connected(self) -> bool:
        return self._sock is not None

    async def connect(self, *, retry_interval: float = 1.0,
                      attempts: int | None = None) -> bool:
        """Connect, retrying until success (or ``attempts`` is exhausted)."""
        loop = self._loop or asyncio.get_running_loop()
        self._loop = loop
        tries = 0
        while not self._closed:
            tries += 1
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            sock.setblocking(False)
            try:
                await loop.sock_connect(sock, self.path)
            except (FileNotFoundError, ConnectionRefusedError, ConnectionResetError,
                    OSError) as exc:
                self.last_error = str(exc)
                sock.close()
                if attempts is not None and tries >= attempts:
                    return False
                await asyncio.sleep(retry_interval)
                continue

            self._sock = sock
            self._outbox.clear()
            self.connect_count += 1
            loop.add_reader(sock.fileno(), self._on_readable)
            if self._on_connect is not None:
                self._on_connect()
            return True
        return False

    def send(self, data: bytes) -> bool:
        """Queue one control datagram; returns True when it is on the wire."""
        sock = self._sock
        if sock is None:
            return False
        if self._outbox:
            self._outbox.append(data)
            self._ensure_writer()
            return True
        try:
            sent = sock.send(data)
        except BlockingIOError:
            self._outbox.append(data)
            self._ensure_writer()
            return True
        except OSError as exc:
            self.last_error = str(exc)
            self._drop_connection()
            return False
        if sent == len(data):
            self.bytes_sent += sent
            return True
        # A partial datagram cannot be completed on SOCK_SEQPACKET; drop it.
        self.last_error = f"short send ({sent}/{len(data)} bytes)"
        return False

    def close(self) -> None:
        self._closed = True
        self._drop_connection()

    # -- internals --------------------------------------------------------- #
    def _ensure_writer(self) -> None:
        if self._sock is None or self._writer_registered:
            return
        loop = self._loop
        if loop is None:
            return
        loop.add_writer(self._sock.fileno(), self._on_writable)
        self._writer_registered = True

    def _on_writable(self) -> None:
        sock = self._sock
        if sock is None:
            return
        while self._outbox:
            try:
                sent = sock.send(self._outbox[0])
            except BlockingIOError:
                return
            except OSError as exc:
                self.last_error = str(exc)
                self._drop_connection()
                return
            if sent != len(self._outbox[0]):
                self.last_error = "short send on control socket"
                self._outbox.popleft()
                continue
            self.bytes_sent += sent
            self._outbox.popleft()

        if self._writer_registered and self._sock is not None and self._loop is not None:
            self._loop.remove_writer(self._sock.fileno())
        self._writer_registered = False

    def _on_readable(self) -> None:
        sock = self._sock
        if sock is None:
            return
        for _ in range(256):
            try:
                data = sock.recv(WIRE_EVENT_SIZE * 4)
            except BlockingIOError:
                return
            except OSError as exc:
                self.last_error = str(exc)
                self._drop_connection()
                return
            if not data:
                self.last_error = "collector closed the socket"
                self._drop_connection()
                return
            self.frames_received += 1
            if self._on_frame is not None:
                self._on_frame(data)

    def _drop_connection(self) -> None:
        sock, self._sock = self._sock, None
        loop = self._loop
        if sock is None:
            return
        if loop is not None:
            try:
                loop.remove_reader(sock.fileno())
            except (OSError, ValueError):
                pass
            if self._writer_registered:
                try:
                    loop.remove_writer(sock.fileno())
                except (OSError, ValueError):
                    pass
        self._writer_registered = False
        try:
            sock.close()
        except OSError:
            pass
        if self._on_disconnect is not None:
            self._on_disconnect()


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #

class Engine:
    """Wire decoding + lineage + rules + mitigation + observability."""

    def __init__(self, config: EngineConfig, *, tui: Tui | None = None) -> None:
        self.config = config
        self.metrics: MetricsRegistry = build_registry()
        self.lineage = LineageGraph(ttl=config.lineage_ttl, max_nodes=config.max_tracked)
        self.rules = RuleEngine.from_file(config.rules_path)
        self.alert_log = AlertLog(config.alert_log_path, fsync=config.fsync_alerts)
        self.tui = tui or Tui(
            color=config.color, verbose=config.verbose, show_events=not config.quiet
        )
        self.transport: UdsTransport | None = None
        self.mitigator = Mitigator(
            self.alert_log,
            command_sink=self.send_command,
            active_kill=config.active_kill,
            enforce=config.enforce_kernel,
            log=self.tui.info if config.verbose else None,
        )
        self.metrics_server = MetricsServer(
            self.metrics, host=config.metrics_host, port=config.metrics_port
        )
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._consumer: asyncio.Task | None = None
        self._metrics_task: asyncio.Task | None = None
        self._stopping = False
        self._closed = False
        self._sim_done = False
        self._malformed_frames = 0
        self._processed = 0
        self._dropped_queue = 0
        self._started_at = time.monotonic()
        self._last_status = 0.0
        self._chain_ok = True
        # Heartbeat / fail-closed bookkeeping.
        self._last_heartbeat_ns = 0
        self._heartbeat_task: asyncio.Task | None = None
        self._collector_online = False

    # -- lifecycle --------------------------------------------------------- #
    async def start(self) -> None:
        if self.config.simulate:
            self.tui.banner(
                socket_path="(simulation)",
                rules=len(self.rules.rules),
                enforcing=self.config.enforce_kernel,
                active_kill=self.config.active_kill,
                metrics_url=f"http://{self.config.metrics_host}:"
                            f"{self.config.metrics_port}/metrics",
                collector_connected=True,
            )
            self.tui.info("simulation mode: no kernel, no collector socket")
        else:
            self.transport = UdsTransport(
                self.config.socket_path,
                on_frame=self._enqueue_frame,
                on_connect=self._on_connected,
                on_disconnect=self._on_disconnected,
            )
            self.tui.info(f"connecting to collector at {self.config.socket_path} ...")
            connected = await self.transport.connect(
                retry_interval=self.config.reconnect_interval
            )
            if not connected:
                raise RuntimeError(
                    f"unable to connect to collector socket {self.config.socket_path}"
                )
            self.tui.banner(
                socket_path=self.config.socket_path,
                rules=len(self.rules.rules),
                enforcing=self.config.enforce_kernel,
                active_kill=self.config.active_kill,
                metrics_url=f"http://{self.config.metrics_host}:"
                            f"{self.config.metrics_port}/metrics",
                collector_connected=True,
            )
            self._collector_online = True
            # Register the engine's own tgid with the collector so lsm/task_kill
            # cannot terminate it, and apply the fail-closed policy if asked.
            if self.transport is not None:
                self.transport.send(
                    PolicyCommand.protect_pid(os.getpid()).to_bytes()
                )
                if self.config.fail_closed:
                    self.transport.send(
                        PolicyCommand.set_fail_closed(True).to_bytes()
                    )
            self._heartbeat_task = asyncio.create_task(
                self._heartbeat_loop(), name="xsypher-heartbeat"
            )

        self.tui.good(
            f"loaded {len(self.rules.rules)} rules from {self.config.rules_path}; "
            f"alert log {self.config.alert_log_path} (chain seq={self.alert_log.sequence})"
        )
        ok, records, chain_error = AlertLog.verify(self.config.alert_log_path)
        self._chain_ok = ok
        if ok:
            self.tui.info(f"audit hash chain verified ({records} record(s))")
        else:
            self.tui.error(f"audit hash chain is INVALID: {chain_error}")
        if self.config.enforce_kernel and not self.config.simulate:
            self.tui.info("kernel enforcement is ON (wire_policy_cmd_t -> eBPF maps)")

        try:
            port = await self.metrics_server.start()
            self.tui.good(f"prometheus exporter listening on "
                          f"{self.config.metrics_host}:{port}/metrics")
        except OSError as exc:
            self.tui.warn(f"metrics exporter disabled: {exc}")

        self._consumer = asyncio.create_task(self._consume(), name="xsypher-consumer")

    async def stop(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stopping = True
        self.tui.info("stopping engine ...")

        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except (asyncio.CancelledError, Exception):  # pragma: no cover
                pass
            self._heartbeat_task = None

        if self.transport is not None:
            # Best effort: release every quarantine we applied so a restart does
            # not leave the node in a locked-down state.
            try:
                released = await self.mitigator.release_all_async()
                if released:
                    self.tui.info(f"released {released} kernel policy entries")
            except Exception as exc:  # pragma: no cover - defensive
                self.tui.warn(f"failed to release policy entries: {exc}")
            # Lift fail-closed and, if configured, arm the authenticated
            # shutdown token so the protected collector can be stopped.
            try:
                if self.config.fail_closed:
                    self.transport.send(
                        PolicyCommand.set_fail_closed(False).to_bytes()
                    )
                if self.config.shutdown_token:
                    self.transport.send(
                        PolicyCommand.set_shutdown_token(
                            self.config.shutdown_token
                        ).to_bytes()
                    )
            except Exception as exc:  # pragma: no cover - defensive
                self.tui.warn(f"failed to release kernel policy: {exc}")
            self.transport.close()
            self._collector_online = False

        if self._consumer is not None:
            # Drain whatever is already queued, then cancel.
            try:
                await asyncio.wait_for(self._queue.join(), timeout=2.0)
            except asyncio.TimeoutError:
                pass
            self._consumer.cancel()
            try:
                await self._consumer
            except (asyncio.CancelledError, Exception):
                pass
            self._consumer = None

        await self.metrics_server.stop()
        self._print_summary()

    async def run(self, stop_event: asyncio.Event) -> None:
        await self.start()
        if self.config.simulate:
            await self._simulate_loop(stop_event)
        else:
            await self._socket_loop(stop_event)
        await self.stop()

    async def _heartbeat_loop(self) -> None:
        """Publish a monotonic heartbeat into config_map on a fixed interval.

        The collector records it in ``xsypher_config_t.last_heartbeat_ns``;
        the BPF fail-closed check treats an expired heartbeat as "the agent is
        gone" and denies tracked AI lineages at the LSM hooks.
        """
        interval = max(0.1, self.config.heartbeat_interval)
        while True:
            await asyncio.sleep(interval)
            if self.transport is None or not self.transport.connected:
                self._collector_online = False
                continue
            self._last_heartbeat_ns = time.monotonic_ns()
            self._collector_online = True
            self.transport.send(
                PolicyCommand.set_heartbeat(self._last_heartbeat_ns).to_bytes()
            )

    async def _socket_loop(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                pass
            self.lineage.prune()
            self._refresh_gauges()
            self._maybe_status()

    async def _simulate_loop(self, stop_event: asyncio.Event) -> None:
        last_maintenance = time.monotonic()
        while not stop_event.is_set() and not self._sim_done:
            await self._simulate_step()
            # Yield to the loop regularly so signals and metrics stay live.
            if self._processed % 16 == 0:
                await asyncio.sleep(0)
            now = time.monotonic()
            if now - last_maintenance >= 1.0:
                last_maintenance = now
                self.lineage.prune()
                self._refresh_gauges()
                self._maybe_status()
        if self.config.simulate_count:
            self.tui.info(f"simulation finished after {self._processed} events")

    # -- observability ----------------------------------------------------- #
    def _refresh_gauges(self) -> None:
        self.metrics.set("xsypher_active_tracked_processes", len(self.lineage))
        self.metrics.set("xsypher_rule_cooldowns_active", self.rules.cooldown_entries)
        if self._last_heartbeat_ns:
            age = max(0.0, (time.monotonic_ns() - self._last_heartbeat_ns) / 1e9)
            self.metrics.set("xsypher_collector_heartbeat_age_seconds", age)
        self.metrics.set("xsypher_collector_status", 1 if self._collector_online else 0)

    def _maybe_status(self) -> None:
        now = time.monotonic()
        if now - self._last_status < 30.0:
            return
        self._last_status = now
        uptime = now - self._started_at
        rate = self._processed / uptime if uptime > 0 else 0.0
        self.tui.status(
            {
                "events": self._processed,
                "events/s": f"{rate:.0f}",
                "alerts": self.mitigator.alerts_written,
                "tracked": len(self.lineage),
                "queue": self._queue.qsize(),
            }
        )

    def _print_summary(self) -> None:
        uptime = max(1e-9, time.monotonic() - self._started_at)
        summary = {
            "uptime_s": round(uptime, 2),
            "events_processed": self._processed,
            "events_per_sec": round(self._processed / uptime, 1),
            "malformed_frames": self._malformed_frames,
            "alerts": self.mitigator.alerts_written,
            "commands_sent": self.mitigator.commands_sent,
            "kills": self.mitigator.kills_delivered,
            "lineage_nodes": len(self.lineage),
            "hash_chain_ok": self._chain_ok,
        }
        self.tui.status(summary)

    # -- frame handling ---------------------------------------------------- #
    def _enqueue_frame(self, data: bytes) -> None:
        if self._stopping:
            return
        try:
            self._queue.put_nowait(data)
        except asyncio.QueueFull:  # pragma: no cover - unbounded by default
            self._dropped_queue += 1

    def _on_connected(self) -> None:
        self.metrics.inc("xsypher_socket_reconnects_total")
        if self.transport is not None and self.transport.connect_count > 1:
            self.tui.info("reconnected to collector")
        if self.config.enforce_kernel and self.transport is not None:
            self.transport.send(
                PolicyCommand.set_enforcement_mode(1).to_bytes()
            )

    def _on_disconnected(self) -> None:
        if not self._stopping:
            self.tui.warn("collector disconnected; retrying")
            asyncio.ensure_future(self._reconnect())

    async def _reconnect(self) -> None:
        if self.transport is None or self._stopping:
            return
        await self.transport.connect(retry_interval=self.config.reconnect_interval)

    async def _consume(self) -> None:
        """Drain queued datagrams in order; a batch keeps the loop responsive."""
        while True:
            data = await self._queue.get()
            try:
                await self._process_frame(data)
                for _ in range(4096):
                    try:
                        queued = self._queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    try:
                        await self._process_frame(queued)
                    finally:
                        self._queue.task_done()
            finally:
                self._queue.task_done()
            self.lineage.prune()
            self._refresh_gauges()

    async def _process_frame(self, data: bytes) -> None:
        """Decode one wire frame, evaluate rules and apply mitigations."""
        try:
            frame = decode_wire_frame(data, strict=True)
        except ValueError:
            self._malformed_frames += 1
            return

        event = frame.event
        event.received_ns = time.time_ns()
        self._processed += 1
        self.metrics.inc("xsypher_events_total", {"type": event.event_name})
        self.lineage.observe(event)
        if event.event_type == EventType.LSM_BLOCK:
            self.metrics.inc("xsypher_lsm_blocks_seen", {"type": "lsm_block"})
        if event.event_type == EventType.ENFORCED_INLINE:
            self.metrics.inc("xsypher_enforced_inline_events_total",
                             {"reason": BlockReason.name(event.open_flags)})
            self.metrics.inc("xsypher_lsm_blocks_seen", {"type": "enforced_inline"})

        started = time.perf_counter()
        matches = self.rules.evaluate(event, self.lineage)
        self.metrics.observe("xsypher_rule_eval_seconds", time.perf_counter() - started)

        self.tui.event_line(event, matches)
        if matches and not self._stopping:
            await self._handle_matches(matches)

    async def _handle_matches(self, matches: Iterable[RuleMatch]) -> None:
        for match in matches:
            try:
                result = await self.mitigator.handle(match)
            except Exception as exc:  # pragma: no cover - defensive
                self.tui.error(f"mitigation failed for {match.rule_id}: {exc}")
                continue
            self.metrics.inc(
                "xsypher_alerts_total",
                {"rule": match.rule_id, "severity": match.severity},
            )
            for entry in result.record.get("mitigations", []):
                if entry.get("delivered"):
                    self.metrics.inc("xsypher_mitigations_total",
                                     {"action": str(entry.get("action"))})
            self.tui.alert(result)

    # -- command path ------------------------------------------------------ #
    def send_command(self, command: PolicyCommand) -> bool:
        """Mitigator sink: ship one command to the collector."""
        if self.transport is None or not self.transport.connected:
            self.metrics.inc("xsypher_commands_failed_total",
                             {"reason": "disconnected"})
            return False
        ok = self.transport.send(command.to_bytes())
        if ok:
            self.metrics.inc("xsypher_commands_sent_total", {"command": command.name})
        else:
            self.metrics.inc("xsypher_commands_failed_total", {"reason": "send_error"})
        if self.config.verbose:
            self.tui.info(f"-> {command.describe()}")
        return ok

    # -- synthetic traffic ------------------------------------------------- #
    async def _simulate_step(self) -> None:
        """Feed one synthetic event (or a whole attack chain) into the engine."""
        generator = getattr(self, "_sim_generator", None)
        if generator is None:
            generator = synthetic_stream(seed=self.config.simulate_seed)
            self._sim_generator = generator
        try:
            events = next(generator)
        except StopIteration:
            await asyncio.sleep(0.05)
            return
        for event in events:
            self._processed += 1
            self.metrics.inc("xsypher_events_total", {"type": event.event_name})
            self.lineage.observe(event)
            started = time.perf_counter()
            matches = self.rules.evaluate(event, self.lineage)
            self.metrics.observe("xsypher_rule_eval_seconds",
                                 time.perf_counter() - started)
            self.tui.event_line(event, matches)
            if matches:
                await self._handle_matches(matches)
            if self.config.simulate_count and self._processed >= self.config.simulate_count:
                self._sim_done = True


# --------------------------------------------------------------------------- #
# Synthetic event generator (used by --simulate)
# --------------------------------------------------------------------------- #

BENIGN_COMMANDS: tuple[tuple[str, str], ...] = (
    ("python3", "/usr/bin/python3"),
    ("node", "/usr/bin/node"),
    ("uvicorn", "/usr/local/bin/uvicorn"),
    ("ls", "/usr/bin/ls"),
    ("cat", "/usr/bin/cat"),
    ("git", "/usr/bin/git"),
    ("pip3", "/usr/bin/pip3"),
    ("systemctl", "/usr/bin/systemctl"),
)

BENIGN_PEERS: tuple[str, ...] = (
    "10.0.0.12",
    "10.0.4.31",
    "140.82.121.4",
    "151.101.1.63",
)


def synthetic_stream(*, seed: int = 1337, chain_every: int = 40) -> Iterable[list[Event]]:
    """Yield batches of synthetic events: benign traffic + periodic breakouts."""
    rng = random.Random(seed)
    container = f"{rng.getrandbits(256):064x}"
    pid = 1000
    cgroup = 0x3000
    chain = 0
    step = 0

    while True:
        step += 1
        events: list[Event] = []

        if step % chain_every == 0:
            chain += 1
            cgroup += 1
            base = pid
            mcp_pid, agent_pid, shell_pid, tool_pid = (
                base + 1, base + 2, base + 3, base + 4
            )
            chain_id = f"{rng.getrandbits(256):064x}"
            events.append(
                Event(pid=mcp_pid, tgid=mcp_pid, ppid=1, comm="mcp-server",
                      filename="/usr/local/bin/mcp-server", uid=1000, gid=1000,
                      cgroup_id=cgroup, container_id=chain_id,
                      event_type=EventType.EXECVE, timestamp_ns=time.time_ns())
            )
            events.append(
                Event(pid=agent_pid, tgid=agent_pid, ppid=mcp_pid, comm="python3",
                      filename="/usr/bin/python3", args="-m agent_runtime",
                      uid=1000, gid=1000, cgroup_id=cgroup, container_id=chain_id,
                      event_type=EventType.EXECVE, timestamp_ns=time.time_ns())
            )
            events.append(
                Event(pid=shell_pid, tgid=shell_pid, ppid=agent_pid, comm="sh",
                      filename="/bin/sh", args="-c curl http://169.254.169.254",
                      uid=1000, gid=1000, cgroup_id=cgroup, container_id=chain_id,
                      event_type=EventType.EXECVE, timestamp_ns=time.time_ns())
            )
            events.append(
                Event(pid=tool_pid, tgid=tool_pid, ppid=shell_pid, comm="curl",
                      filename="/usr/bin/curl",
                      args="http://169.254.169.254/latest/meta-data/iam/",
                      uid=1000, gid=1000, cgroup_id=cgroup, container_id=chain_id,
                      event_type=EventType.EXECVE, timestamp_ns=time.time_ns())
            )
            events.append(
                Event(pid=tool_pid, tgid=tool_pid, ppid=shell_pid, comm="curl",
                      uid=1000, gid=1000, cgroup_id=cgroup, container_id=chain_id,
                      event_type=EventType.CONNECT, af_family=2,
                      daddr_v4="169.254.169.254", dport=80,
                      timestamp_ns=time.time_ns())
            )
            pid = base + 10
        else:
            pid += 1
            comm, exe = rng.choice(BENIGN_COMMANDS)
            events.append(
                Event(pid=pid, tgid=pid, ppid=pid - 1, comm=comm, filename=exe,
                      uid=1000, gid=1000, cgroup_id=cgroup, container_id=container,
                      event_type=EventType.EXECVE, timestamp_ns=time.time_ns())
            )
            if rng.random() < 0.5:
                events.append(
                    Event(pid=pid, tgid=pid, ppid=pid - 1, comm=comm, uid=1000,
                          gid=1000, cgroup_id=cgroup, container_id=container,
                          event_type=EventType.CONNECT, af_family=2,
                          daddr_v4=rng.choice(BENIGN_PEERS),
                          dport=rng.choice((443, 443, 80, 5432)),
                          timestamp_ns=time.time_ns())
                )
            if rng.random() < 0.3:
                events.append(
                    Event(pid=pid, tgid=pid, ppid=pid - 1, comm=comm, uid=1000,
                          gid=1000, cgroup_id=cgroup, container_id=container,
                          event_type=EventType.OPENAT,
                          filename=rng.choice(
                              ("/app/data.json", "/etc/hosts", "/tmp/cache.bin")
                          ),
                          timestamp_ns=time.time_ns())
                )
        yield events


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xsypher-engine",
        description="xSypher-Stream threat engine: lineage, rules, mitigation, "
                    "Prometheus metrics and live terminal monitor.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--socket-path", default=os.environ.get(
        "XSYPHER_SOCKET", DEFAULT_SOCKET_PATHS[0]),
        help="collector AF_UNIX SOCK_SEQPACKET socket")
    parser.add_argument("--rules", default=default_rules_path(),
                        help="declarative YAML/JSON rule document")
    parser.add_argument("--alert-log", default=os.environ.get(
        "XSYPHER_ALERT_LOG", DEFAULT_ALERT_LOG),
        help="hash-chained JSONL audit log")
    parser.add_argument("--metrics-host", default="0.0.0.0",
                        help="Prometheus exporter bind address")
    parser.add_argument("--metrics-port", type=int, default=DEFAULT_METRICS_PORT,
                        help="Prometheus exporter port (0 = ephemeral)")
    parser.add_argument("--enforce-kernel", action="store_true",
                        help="push quarantine commands into the eBPF LSM maps")
    parser.add_argument("--active-kill", action="store_true",
                        help="also SIGKILL offending processes from user space")
    parser.add_argument("--simulate", action="store_true",
                        help="synthetic traffic generator (no root, no eBPF)")
    parser.add_argument("--simulate-count", type=int, default=0,
                        help="stop after N synthetic events (0 = run forever)")
    parser.add_argument("--simulate-seed", type=int, default=1337,
                        help="seed for the synthetic generator")
    parser.add_argument("--lineage-ttl", type=float, default=5.0,
                        help="seconds an exited process stays resolvable")
    parser.add_argument("--max-tracked", type=int, default=200_000,
                        help="maximum processes tracked in the lineage graph")
    parser.add_argument("--fsync-alerts", action="store_true",
                        help="fsync the alert log after every record")
    parser.add_argument("--fail-closed", action="store_true",
                        help="arm kernel fail-closed when the agent heartbeat expires")
    parser.add_argument("--heartbeat-interval", type=float, default=2.0,
                        help="seconds between collector heartbeats")
    parser.add_argument("--collector-timeout", type=float, default=10.0,
                        help="seconds without a heartbeat before the collector is "
                             "considered dead")
    parser.add_argument("--shutdown-token", type=int, default=0,
                        help="authenticated token that lifts collector self-protection "
                             "on shutdown (0 = do not send)")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    parser.add_argument("--quiet", action="store_true",
                        help="only print alerts, not every telemetry line")
    parser.add_argument("--verbose", action="store_true", help="verbose output")
    parser.add_argument("--version", action="version",
                        version=f"xsypher-engine {__version__}")
    return parser


def config_from_args(argv: list[str] | None = None) -> EngineConfig:
    args = build_parser().parse_args(argv)
    alert_log, warning = _resolve_alert_log(
        args.alert_log, explicit=args.alert_log != DEFAULT_ALERT_LOG
    )
    config = EngineConfig(
        socket_path=args.socket_path,
        rules_path=args.rules,
        alert_log_path=alert_log,
        metrics_host=args.metrics_host,
        metrics_port=args.metrics_port,
        enforce_kernel=args.enforce_kernel,
        active_kill=args.active_kill,
        simulate=args.simulate,
        simulate_count=args.simulate_count,
        simulate_seed=args.simulate_seed,
        color=False if args.no_color else None,
        verbose=args.verbose,
        quiet=args.quiet,
        lineage_ttl=args.lineage_ttl,
        max_tracked=args.max_tracked,
        fsync_alerts=args.fsync_alerts,
        fail_closed=args.fail_closed,
        heartbeat_interval=args.heartbeat_interval,
        collector_timeout=args.collector_timeout,
        shutdown_token=args.shutdown_token,
    )
    if warning:
        print(f"[xsypher] WARNING: {warning}", file=sys.stderr)
    return config


async def _async_main(config: EngineConfig) -> int:
    engine = Engine(config)
    stop_event = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except (NotImplementedError, RuntimeError):  # pragma: no cover
            pass

    try:
        await engine.run(stop_event)
    except KeyboardInterrupt:  # pragma: no cover - signal handler normally wins
        stop_event.set()
        await engine.stop()
    return 0


def main(argv: list[str] | None = None) -> int:
    config = config_from_args(argv)
    try:
        return asyncio.run(_async_main(config))
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
