"""xSypher-Stream threat engine package.

The package is import-safe without root privileges and without eBPF: importing
it never touches the kernel, never opens the collector socket and never writes
the audit log.  Everything happens in :class:`engine.main.Engine`.

Typical use::

    from engine.lineage import LineageGraph
    from engine.rule_engine import RuleEngine
    from engine.abi import Event, EventType

    graph = LineageGraph()
    rules = RuleEngine.from_file("config/rules.yaml")
    event = Event(pid=42, tgid=42, comm="sh", filename="/bin/sh",
                  event_type=EventType.EXECVE, container_id="host")
    graph.observe(event)
    for match in rules.evaluate(event, graph):
        print(match.rule_id, match.severity)
"""

from __future__ import annotations

from .abi import (
    MAX_ARGS_LEN,
    MAX_COMM_LEN,
    MAX_CONTAINER_ID_LEN,
    MAX_PATH_LEN,
    XSYPHER_ABI_VERSION,
    XSYPHER_WIRE_MAGIC,
    CmdType,
    Event,
    EventType,
    PolicyCommand,
)
from .lineage import LineageGraph, ProcessNode
from .mitigator import AlertLog, Mitigator
from .rule_engine import RuleEngine, RuleMatch

__version__ = "2.0.0"
__abi_version__ = XSYPHER_ABI_VERSION

__all__ = [
    "AlertLog",
    "CmdType",
    "Event",
    "EventType",
    "LineageGraph",
    "MAX_ARGS_LEN",
    "MAX_COMM_LEN",
    "MAX_CONTAINER_ID_LEN",
    "MAX_PATH_LEN",
    "Mitigator",
    "PolicyCommand",
    "ProcessNode",
    "RuleEngine",
    "RuleMatch",
    "XSYPHER_ABI_VERSION",
    "XSYPHER_WIRE_MAGIC",
    "__abi_version__",
    "__version__",
]
