"""Lineage graph, rule engine, mitigation and observability tests."""

from __future__ import annotations

import asyncio
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from engine import abi  # noqa: E402
from engine.lineage import LineageGraph, ProcessNode, basename, is_ai_runtime  # noqa: E402
from engine.main import EngineConfig, UdsTransport  # noqa: E402
from engine.metrics import MetricsServer, build_registry  # noqa: E402
from engine.mitigator import AlertLog, Mitigator  # noqa: E402
from engine.rule_engine import (  # noqa: E402
    RuleEngine,
    RuleError,
    SEVERITIES,
)
from engine.tui import Tui  # noqa: E402

RULES_PATH = REPO_ROOT / "config" / "rules.yaml"
CONTAINER = "a" * 64


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_event(**overrides) -> abi.Event:
    base = dict(
        timestamp_ns=time.time_ns(),
        cgroup_id=1000,
        pid=500,
        tgid=500,
        ppid=1,
        uid=1000,
        gid=1000,
        event_type=abi.EventType.EXECVE,
        comm="sh",
        filename="/bin/sh",
        container_id=CONTAINER,
    )
    base.update(overrides)
    return abi.Event(**base)


def rule_engine(**kwargs) -> RuleEngine:
    return RuleEngine.from_file(RULES_PATH, **kwargs)


# --------------------------------------------------------------------------- #
# Lineage
# --------------------------------------------------------------------------- #

class TestLineage(unittest.TestCase):
    def test_basename_and_ai_runtime(self) -> None:
        self.assertEqual(basename("/usr/bin/python3"), "python3")
        self.assertEqual(basename(""), "")
        self.assertTrue(is_ai_runtime("node"))
        self.assertTrue(is_ai_runtime("python3.12"))
        self.assertTrue(is_ai_runtime("mcp-server"))
        self.assertFalse(is_ai_runtime("curl"))
        self.assertFalse(is_ai_runtime(""))

    def test_builds_ancestry_chain(self) -> None:
        graph = LineageGraph()
        graph.observe(make_event(pid=10, tgid=10, comm="node", filename="/usr/bin/node"))
        graph.observe(make_event(pid=11, tgid=11, ppid=10, comm="python3",
                                 filename="/usr/bin/python3"))
        graph.observe(make_event(pid=12, tgid=12, ppid=11, comm="sh", filename="/bin/sh"))
        graph.observe(make_event(pid=13, tgid=13, ppid=12, comm="curl",
                                 filename="/usr/bin/curl"))

        chain = graph.get_ancestry_chain(13)
        self.assertEqual([node.pid for node in chain], [13, 12, 11, 10])
        self.assertEqual(graph.ancestry_names(13), ["sh", "python3", "node"])
        self.assertTrue(graph.ancestry_has_ai_runtime(13))
        self.assertFalse(graph.ancestry_has_ai_runtime(10))

    def test_max_depth_is_respected(self) -> None:
        graph = LineageGraph()
        previous = None
        for pid in range(100, 110):
            graph.observe(make_event(pid=pid, tgid=pid, ppid=previous or 1,
                                     comm=f"p{pid}", filename=f"/bin/p{pid}"))
            previous = pid
        chain = graph.get_ancestry_chain(109, max_depth=3)
        self.assertEqual([node.pid for node in chain], [109, 108, 107])

    def test_cycle_is_broken(self) -> None:
        graph = LineageGraph()
        graph.observe(make_event(pid=1, tgid=1, ppid=2, comm="a", filename="/bin/a"))
        graph.observe(make_event(pid=2, tgid=2, ppid=1, comm="b", filename="/bin/b"))
        chain = graph.get_ancestry_chain(1)
        self.assertEqual([node.pid for node in chain], [1, 2])

    def test_exit_grace_window(self) -> None:
        clock = FakeClock()
        graph = LineageGraph(ttl=5.0, clock=clock)
        graph.observe(make_event(pid=20, tgid=20, comm="node", filename="/usr/bin/node"))
        graph.observe(make_event(pid=21, tgid=21, ppid=20, comm="sh", filename="/bin/sh"))
        graph.observe(make_event(pid=20, tgid=20, comm="node",
                                 event_type=abi.EventType.PROCESS_EXIT))

        # Still inside the 5 s grace window: ancestry stays resolvable.
        clock.advance(4.9)
        self.assertEqual(graph.prune(), 0)
        self.assertIn(20, graph)
        self.assertEqual([n.pid for n in graph.get_ancestry_chain(21)], [21, 20])

        clock.advance(0.2)
        self.assertEqual(graph.prune(), 1)
        self.assertNotIn(20, graph)
        self.assertEqual([n.pid for n in graph.get_ancestry_chain(21)], [21])

    def test_exec_updates_existing_node(self) -> None:
        graph = LineageGraph()
        graph.observe(make_event(pid=30, tgid=30, comm="bash", filename="/bin/bash"))
        graph.observe(make_event(pid=30, tgid=30, comm="python3",
                                 filename="/usr/bin/python3", args="-c print(1)"))
        node = graph.node(30)
        self.assertIsNotNone(node)
        assert node is not None
        self.assertEqual(node.exe, "/usr/bin/python3")
        self.assertEqual(node.args, "-c print(1)")
        self.assertEqual(node.exec_count, 2)

    def test_lru_eviction_is_bounded(self) -> None:
        graph = LineageGraph(max_nodes=32)
        for pid in range(1, 200):
            graph.observe(make_event(pid=pid, tgid=pid, comm=f"p{pid}",
                                     filename=f"/bin/p{pid}"))
        self.assertLessEqual(len(graph), 32)
        self.assertGreater(graph.stats["evictions"], 0)

    def test_container_membership_and_descendants(self) -> None:
        graph = LineageGraph()
        graph.observe(make_event(pid=40, tgid=40, comm="node", filename="/usr/bin/node"))
        graph.observe(make_event(pid=41, tgid=41, ppid=40, comm="sh", filename="/bin/sh"))
        graph.observe(make_event(pid=42, tgid=42, ppid=40, comm="ls", filename="/bin/ls"))
        self.assertEqual(
            sorted(node.pid for node in graph.descendants(40)), [41, 42]
        )
        self.assertEqual(len(graph.container_members(CONTAINER)), 3)

    def test_node_helpers(self) -> None:
        node = ProcessNode(pid=7, comm="curl", exe="/usr/bin/curl", container_id="host")
        self.assertEqual(node.name, "curl")
        self.assertEqual(node.describe(), "curl[7]")
        self.assertFalse(node.is_container)
        self.assertIn("pid", node.to_dict())
        self.assertEqual(node.to_row(), "curl(7)@host")


# --------------------------------------------------------------------------- #
# Rule engine
# --------------------------------------------------------------------------- #

class TestRuleEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = rule_engine(cooldown_seconds=0.0)
        self.graph = LineageGraph()

    def fire(self, *events: abi.Event) -> list[str]:
        matches: list[str] = []
        for event in events:
            self.graph.observe(event)
            matches.extend(match.rule_id for match in self.engine.evaluate(event, self.graph))
        return matches

    def test_all_rules_loaded(self) -> None:
        ids = {rule.id for rule in self.engine.rules}
        self.assertEqual(
            ids,
            {
                "MCP_SHELL_BREAKOUT",
                "MCP_RECON_OR_EXFIL_TOOL",
                "CLOUD_IMDS_CREDENTIAL_THEFT",
                "SENSITIVE_CREDENTIAL_HARVEST",
                "FILELESS_MEMFD_EXECUTION",
                "SUSPICIOUS_OUTBOUND_C2_PORT",
            },
        )
        for rule in self.engine.rules:
            self.assertIn(rule.severity, SEVERITIES)
            self.assertTrue(rule.actions)
            self.assertTrue(rule.actions[0] in {
                "quarantine_pid", "quarantine_cgroup", "block_ipv4", "kill", "block_imds",
            })

    def test_mcp_shell_breakout(self) -> None:
        matches = self.fire(
            make_event(pid=100, tgid=100, comm="node", filename="/usr/bin/node"),
            make_event(pid=101, tgid=101, ppid=100, comm="python3",
                       filename="/usr/bin/python3"),
            make_event(pid=102, tgid=102, ppid=101, comm="sh", filename="/bin/sh"),
        )
        self.assertEqual(matches, ["MCP_SHELL_BREAKOUT"])

    def test_shell_from_non_ai_parent_is_benign(self) -> None:
        matches = self.fire(
            make_event(pid=110, tgid=110, comm="systemd", filename="/usr/lib/systemd"),
            make_event(pid=111, tgid=111, ppid=110, comm="bash", filename="/bin/bash"),
        )
        self.assertEqual(matches, [])

    def test_recon_tool_from_mcp_ancestor(self) -> None:
        matches = self.fire(
            make_event(pid=120, tgid=120, comm="node", filename="/usr/bin/node"),
            make_event(pid=121, tgid=121, ppid=120, comm="python3",
                       filename="/usr/bin/python3"),
            make_event(pid=122, tgid=122, ppid=121, comm="curl",
                       filename="/usr/bin/curl", args="http://example.com"),
        )
        self.assertEqual(matches, ["MCP_RECON_OR_EXFIL_TOOL"])

    def test_imds_only_inside_container(self) -> None:
        container_matches = self.fire(
            make_event(pid=130, tgid=130, comm="curl", filename="/usr/bin/curl",
                       event_type=abi.EventType.CONNECT, af_family=2,
                       daddr_v4="169.254.169.254", dport=80),
        )
        self.assertIn("CLOUD_IMDS_CREDENTIAL_THEFT", container_matches)

        host_matches = self.fire(
            make_event(pid=131, tgid=131, comm="curl", filename="/usr/bin/curl",
                       event_type=abi.EventType.CONNECT, af_family=2,
                       daddr_v4="169.254.169.254", dport=80, container_id="host"),
        )
        self.assertNotIn("CLOUD_IMDS_CREDENTIAL_THEFT", host_matches)

    def test_credential_harvest_and_authorised_binaries(self) -> None:
        harvest = self.fire(
            make_event(pid=140, tgid=140, comm="cat", event_type=abi.EventType.OPENAT,
                       filename="/etc/shadow"),
        )
        self.assertEqual(harvest, ["SENSITIVE_CREDENTIAL_HARVEST"])

        sshd = self.fire(
            make_event(pid=141, tgid=141, comm="sshd",
                       event_type=abi.EventType.OPENAT, filename="/etc/shadow"),
        )
        self.assertEqual(sshd, [])

        env_file = self.fire(
            make_event(pid=142, tgid=142, comm="python3", event_type=abi.EventType.OPENAT,
                       filename="/app/.env"),
        )
        self.assertEqual(env_file, ["SENSITIVE_CREDENTIAL_HARVEST"])

        private_key = self.fire(
            make_event(pid=143, tgid=143, comm="tar", event_type=abi.EventType.OPENAT,
                       filename="/root/.ssh/id_rsa"),
        )
        self.assertEqual(private_key, ["SENSITIVE_CREDENTIAL_HARVEST"])

    def test_fileless_memfd_and_proc_fd_exec(self) -> None:
        memfd = self.fire(
            make_event(pid=150, tgid=150, comm="python3",
                       event_type=abi.EventType.MEMFD_CREATE, filename="payload"),
        )
        self.assertEqual(memfd, ["FILELESS_MEMFD_EXECUTION"])

        proc_fd = self.fire(
            make_event(pid=151, tgid=151, comm="bash", filename="/proc/self/fd/3"),
        )
        self.assertEqual(proc_fd, ["FILELESS_MEMFD_EXECUTION"])

        shm = self.fire(
            make_event(pid=152, tgid=152, comm="evil", filename="/dev/shm/.x"),
        )
        self.assertEqual(shm, ["FILELESS_MEMFD_EXECUTION"])

    def test_c2_port_from_container(self) -> None:
        matches = self.fire(
            make_event(pid=160, tgid=160, comm="bash", event_type=abi.EventType.CONNECT,
                       af_family=2, daddr_v4="203.0.113.7", dport=4444),
        )
        self.assertEqual(matches, ["SUSPICIOUS_OUTBOUND_C2_PORT"])

        benign = self.fire(
            make_event(pid=161, tgid=161, comm="bash", event_type=abi.EventType.CONNECT,
                       af_family=2, daddr_v4="203.0.113.7", dport=443),
        )
        self.assertEqual(benign, [])

    def test_benign_stream_never_alerts(self) -> None:
        matches: list[str] = []
        for index in range(500):
            matches.extend(
                self.fire(
                    make_event(pid=1000 + index, tgid=1000 + index,
                               ppid=1 + index // 2, comm="python3",
                               filename="/usr/bin/python3"),
                )
            )
            matches.extend(
                self.fire(
                    make_event(pid=1000 + index, tgid=1000 + index,
                               comm="python3", event_type=abi.EventType.CONNECT,
                               af_family=2, daddr_v4="10.0.0.5", dport=443),
                )
            )
        self.assertEqual(matches, [])

    def test_cooldown_suppresses_repeats(self) -> None:
        engine = rule_engine(cooldown_seconds=60.0)
        graph = LineageGraph()
        event = make_event(pid=170, tgid=170, comm="sh", filename="/bin/sh")
        graph.observe(make_event(pid=171, tgid=171, comm="node", filename="/usr/bin/node"))
        graph.observe(make_event(pid=170, tgid=170, ppid=171, comm="sh", filename="/bin/sh"))
        first = engine.evaluate(event, graph)
        second = engine.evaluate(event, graph)
        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        self.assertEqual(engine.stats["suppressed"], 1)

    def test_match_payload(self) -> None:
        self.graph.observe(make_event(pid=180, tgid=180, comm="node",
                                      filename="/usr/bin/node"))
        event = make_event(pid=181, tgid=181, ppid=180, comm="sh", filename="/bin/sh")
        self.graph.observe(event)
        match = self.engine.evaluate(event, self.graph)[0]
        payload = match.to_dict()
        self.assertEqual(payload["rule"], "MCP_SHELL_BREAKOUT")
        self.assertEqual(payload["severity"], "critical")
        self.assertEqual(payload["ancestry"], ["node"])
        self.assertIn("quarantine_cgroup", payload["actions"])

    def test_json_rules_document(self) -> None:
        document = {
            "settings": {"max_ancestry_depth": 4, "cooldown_seconds": 0},
            "rules": [
                {
                    "id": "JSON_TEST",
                    "title": "json rule",
                    "severity": "low",
                    "event_types": ["execve"],
                    "conditions": {"exe_in": ["ncat"]},
                    "actions": ["quarantine_pid"],
                }
            ],
        }
        engine = RuleEngine.from_document(document)
        graph = LineageGraph()
        event = make_event(pid=190, tgid=190, comm="ncat", filename="/usr/bin/ncat")
        graph.observe(event)
        self.assertEqual([m.rule_id for m in engine.evaluate(event, graph)], ["JSON_TEST"])

    def test_invalid_rules_are_rejected(self) -> None:
        with self.assertRaises(RuleError):
            RuleEngine.from_document({"rules": [{"id": "X", "severity": "nope",
                                                 "actions": ["kill"]}]})
        with self.assertRaises(RuleError):
            RuleEngine.from_document({"rules": [{"id": "X", "severity": "low",
                                                 "actions": ["launch_missiles"]}]})
        with self.assertRaises(RuleError):
            RuleEngine.from_document({"rules": [
                {"id": "X", "severity": "low", "actions": ["kill"]},
                {"id": "X", "severity": "low", "actions": ["kill"]},
            ]})
        with self.assertRaises(RuleError):
            RuleEngine.from_document({"rules": []})
        with self.assertRaises(RuleError):
            RuleEngine.from_document({"rules": [
                {"id": "X", "severity": "low", "actions": ["kill"],
                 "conditions": {"not_a_condition": True}},
            ]})

    def test_evaluation_is_fast(self) -> None:
        """The hot path must stay far below the 500 us budget."""
        graph = LineageGraph()
        graph.observe(make_event(pid=200, tgid=200, comm="node", filename="/usr/bin/node"))
        graph.observe(make_event(pid=201, tgid=201, ppid=200, comm="python3",
                                 filename="/usr/bin/python3"))
        event = make_event(pid=202, tgid=202, ppid=201, comm="cat", filename="/usr/bin/cat")
        engine = rule_engine(cooldown_seconds=0.0)

        samples = []
        for _ in range(2000):
            started = time.perf_counter()
            engine.evaluate(event, graph)
            samples.append((time.perf_counter() - started) * 1e6)
        samples.sort()
        p99 = samples[int(len(samples) * 0.99)]
        self.assertLess(p99, 500.0, f"p99 rule evaluation was {p99:.1f} us")


# --------------------------------------------------------------------------- #
# Mitigation + audit trail
# --------------------------------------------------------------------------- #

class TestMitigator(unittest.IsolatedAsyncioTestCase):
    async def test_commands_and_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "alerts.jsonl")
            sent: list[abi.PolicyCommand] = []
            mitigator = Mitigator(
                AlertLog(log_path),
                command_sink=sent.append,
                active_kill=False,
                enforce=True,
            )
            engine = rule_engine(cooldown_seconds=0.0)
            graph = LineageGraph()
            graph.observe(make_event(pid=300, tgid=300, comm="node",
                                     filename="/usr/bin/node"))
            graph.observe(make_event(pid=301, tgid=301, ppid=300, comm="python3",
                                     filename="/usr/bin/python3"))
            shell = make_event(pid=302, tgid=302, ppid=301, comm="sh",
                               filename="/bin/sh", cgroup_id=4242)
            graph.observe(shell)
            match = engine.evaluate(shell, graph)[0]

            result = await mitigator.handle(match)
            self.assertTrue(result.enforced)
            self.assertEqual([c.name for c in result.commands], ["quarantine_cgroup"])
            self.assertEqual(len(sent), 1)
            self.assertEqual(sent[0].cmd_type, abi.CmdType.QUARANTINE_CGROUP)
            self.assertEqual(sent[0].target_cgroup_id, 4242)
            self.assertTrue(result.alert_id)
            self.assertEqual(len(result.alert_id), 16)

            # Second identical match must not resend the same map update.
            await mitigator.handle(match)
            self.assertEqual(len(sent), 1)

            ok, records, error = AlertLog.verify(log_path)
            self.assertTrue(ok, error)
            self.assertEqual(records, 2)

            with open(log_path, encoding="utf-8") as handle:
                first = json.loads(handle.readline())
                second = json.loads(handle.readline())
            self.assertEqual(first["prev_hash"], "0" * 64)
            self.assertEqual(second["prev_hash"], first["hash"])
            self.assertEqual(second["sequence"], 1)

    async def test_tampering_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "alerts.jsonl")
            sink: list[abi.PolicyCommand] = []
            mitigator = Mitigator(AlertLog(log_path), command_sink=sink.append, enforce=True)
            engine = rule_engine(cooldown_seconds=0.0)
            graph = LineageGraph()
            for pid in range(400, 405):
                event = make_event(pid=pid, tgid=pid, comm="cat",
                                   event_type=abi.EventType.OPENAT,
                                   filename="/etc/shadow", cgroup_id=pid)
                graph.observe(event)
                for match in engine.evaluate(event, graph):
                    await mitigator.handle(match)

            self.assertTrue(AlertLog.verify(log_path)[0])

            lines = Path(log_path).read_text(encoding="utf-8").splitlines()
            record = json.loads(lines[0])
            record["severity"] = "low"
            lines[0] = json.dumps(record)
            Path(log_path).write_text("\n".join(lines) + "\n", encoding="utf-8")

            ok, count, error = AlertLog.verify(log_path)
            self.assertFalse(ok)
            self.assertIsNotNone(error)
            self.assertEqual(count, 0)

    async def test_chain_resumes_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "alerts.jsonl")
            first = AlertLog(log_path)
            first.append({"rule": "A", "severity": "high"})
            first.append({"rule": "B", "severity": "low"})

            resumed = AlertLog(log_path)
            self.assertEqual(resumed.sequence, 2)
            record = resumed.append({"rule": "C", "severity": "critical"})
            self.assertEqual(record["sequence"], 2)

            ok, records, error = AlertLog.verify(log_path)
            self.assertTrue(ok, error)
            self.assertEqual(records, 3)

    async def test_audit_mode_does_not_enforce(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sink: list[abi.PolicyCommand] = []
            mitigator = Mitigator(
                AlertLog(os.path.join(tmp, "a.jsonl")),
                command_sink=sink.append,
                enforce=False,
            )
            engine = rule_engine(cooldown_seconds=0.0)
            graph = LineageGraph()
            event = make_event(pid=500, tgid=500, comm="cat",
                               event_type=abi.EventType.OPENAT, filename="/etc/shadow")
            graph.observe(event)
            result = await mitigator.handle(engine.evaluate(event, graph)[0])
            self.assertEqual(sink, [])
            self.assertEqual(result.record["mitigations"][0]["detail"], "audit-only mode")

    async def test_release_all_builds_inverse_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sink: list[abi.PolicyCommand] = []
            mitigator = Mitigator(AlertLog(os.path.join(tmp, "a.jsonl")),
                                  command_sink=sink.append, enforce=True)
            engine = rule_engine(cooldown_seconds=0.0)
            graph = LineageGraph()
            imds = make_event(pid=600, tgid=600, comm="curl", filename="/usr/bin/curl",
                              event_type=abi.EventType.CONNECT, af_family=2,
                              daddr_v4="169.254.169.254", dport=80, cgroup_id=700)
            graph.observe(imds)
            for match in engine.evaluate(imds, graph):
                await mitigator.handle(match)
            self.assertTrue(sink)

            released = mitigator.release_all()
            self.assertTrue(any(c.cmd_type == abi.CmdType.UNQUARANTINE_CGROUP
                                for c in released))
            self.assertTrue(any(c.cmd_type == abi.CmdType.UNBLOCK_IPV4
                                for c in released))


# --------------------------------------------------------------------------- #
# Metrics, TUI, config
# --------------------------------------------------------------------------- #

class TestMetrics(unittest.IsolatedAsyncioTestCase):
    def test_render_contains_required_series(self) -> None:
        registry = build_registry()
        registry.inc("xsypher_events_total", {"type": "execve"}, 3)
        registry.inc("xsypher_alerts_total",
                     {"rule": "MCP_SHELL_BREAKOUT", "severity": "critical"}, 1)
        registry.inc("xsypher_mitigations_total", {"action": "quarantine_pid"}, 1)
        registry.set("xsypher_active_tracked_processes", 12)

        text = registry.render()
        self.assertIn('xsypher_events_total{type="execve"} 3', text)
        self.assertIn('xsypher_alerts_total{rule="MCP_SHELL_BREAKOUT",severity="critical"} 1',
                      text)
        self.assertIn('xsypher_mitigations_total{action="quarantine_pid"} 1', text)
        self.assertIn("xsypher_active_tracked_processes 12", text)
        self.assertIn("# TYPE xsypher_events_total counter", text)
        self.assertIn("xsypher_engine_uptime_seconds", text)

    def test_label_escaping(self) -> None:
        registry = build_registry()
        registry.inc("xsypher_alerts_total", {"rule": 'weird"rule', "severity": "low"})
        self.assertIn('rule="weird\\"rule"', registry.render())

    async def test_http_endpoint(self) -> None:
        registry = build_registry()
        registry.inc("xsypher_events_total", {"type": "connect"}, 9)
        server = MetricsServer(registry, host="127.0.0.1", port=0)
        port = await server.start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            response = await reader.read(-1)
            writer.close()
            text = response.decode("latin-1")
            self.assertIn("200 OK", text.splitlines()[0])
            self.assertIn('xsypher_events_total{type="connect"} 9', text)

            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            self.assertIn("200 OK", (await reader.read(-1)).decode("latin-1"))
            writer.close()

            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET /nope HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            self.assertIn("404", (await reader.read(-1)).decode("latin-1"))
            writer.close()
        finally:
            await server.stop()


class TestTui(unittest.TestCase):
    def test_renders_event_and_alert_without_color(self) -> None:
        buffer = io.StringIO()
        tui = Tui(stream=buffer, color=False)
        engine = rule_engine(cooldown_seconds=0.0)
        graph = LineageGraph()
        graph.observe(make_event(pid=900, tgid=900, comm="node", filename="/usr/bin/node"))
        graph.observe(make_event(pid=901, tgid=901, ppid=900, comm="python3",
                                 filename="/usr/bin/python3"))
        event = make_event(pid=902, tgid=902, ppid=901, comm="sh", filename="/bin/sh")
        graph.observe(event)
        matches = engine.evaluate(event, graph)

        tui.event_line(event, matches)
        output = buffer.getvalue()
        self.assertIn("EXEC", output)
        self.assertIn("pid=902", output)
        self.assertIn("MCP_SHELL_BREAKOUT", output)
        self.assertNotIn("\033[", output)

    def test_color_mode_emits_ansi(self) -> None:
        buffer = io.StringIO()
        tui = Tui(stream=buffer, color=True)
        tui.event_line(make_event(), [])
        self.assertIn("\033[", buffer.getvalue())


class TestEngineConfig(unittest.TestCase):
    def test_defaults(self) -> None:
        config = EngineConfig()
        self.assertEqual(config.metrics_port, 9109)
        self.assertFalse(config.enforce_kernel)
        self.assertEqual(config.lineage_ttl, 5.0)

    def test_cli_parsing(self) -> None:
        from engine.main import config_from_args

        with tempfile.TemporaryDirectory() as tmp:
            config = config_from_args([
                "--socket-path", os.path.join(tmp, "s.sock"),
                "--alert-log", os.path.join(tmp, "alerts.jsonl"),
                "--metrics-port", "0",
                "--enforce-kernel",
                "--active-kill",
                "--no-color",
                "--quiet",
                "--rules", str(RULES_PATH),
            ])
        self.assertTrue(config.enforce_kernel)
        self.assertTrue(config.active_kill)
        self.assertEqual(config.metrics_port, 0)
        self.assertFalse(config.color)
        self.assertTrue(config.quiet)

    def test_rules_path_is_discovered(self) -> None:
        from engine.main import default_rules_path

        self.assertTrue(Path(default_rules_path()).is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
