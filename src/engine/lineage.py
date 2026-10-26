"""xSypher-Stream - real-time process lineage graph.

The lineage graph reconstructs the ancestry of every observed process from the
telemetry stream alone.  It is deliberately independent of /proc: a container
that is being attacked may already be gone by the time an alert is raised, but
the kernel events still describe the full parent chain.

Design
------
* ``ProcessNode`` is a ``__slots__`` dataclass: cheap to allocate, cheap to
  read, no ``__dict__`` per process.
* Events arrive out of order (ring buffer per-CPU sections, concurrent probes),
  so a node is kept alive for a TTL grace window after ``EVENT_PROCESS_EXIT``
  before it is evicted.  A parent that exits before its child is still
  resolvable during that window.
* The graph is bounded (``max_nodes``) with oldest-first eviction so a
  fork-bomb cannot exhaust memory.
* All lookups are O(depth) with a cycle guard, so a `get_ancestry_chain()` call
  is a handful of dict hits - well inside the 500 us rule evaluation budget.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Final, Iterable, Iterator

from .abi import Event, EventType

#: Binaries that frequently host AI agents / Model Context Protocol servers.
AI_RUNTIME_BASENAMES: Final[frozenset[str]] = frozenset(
    {
        "node",
        "nodejs",
        "deno",
        "bun",
        "python",
        "python3",
        "python3.10",
        "python3.11",
        "python3.12",
        "python3.13",
        "uvicorn",
        "gunicorn",
        "hypercorn",
        "fastapi",
        "claude-mcp",
        "mcp-server",
        "mcp",
        "npx",
        "ollama",
        "llama-server",
        "vllm",
    }
)

#: Interactive shells - the classic escape hatch from an MCP tool call.
SHELL_BASENAMES: Final[frozenset[str]] = frozenset(
    {"sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "busybox"}
)

#: Terminal multiplexers used to persist an interactive foothold.
MULTIPLEXER_BASENAMES: Final[frozenset[str]] = frozenset(
    {"tmux", "screen", "dtach", "abduco"}
)

#: Network / recon / exfiltration tooling.
NETWORK_TOOL_BASENAMES: Final[frozenset[str]] = frozenset(
    {
        "curl",
        "wget",
        "nc",
        "ncat",
        "netcat",
        "socat",
        "nmap",
        "masscan",
        "ssh",
        "scp",
        "sftp",
        "rsync",
        "ftp",
        "tftp",
        "telnet",
        "base64",
        "xxd",
        "od",
        "openssl",
        "chisel",
        "ngrok",
    }
)


def basename(path: str) -> str:
    """Return the last path component of ``path`` (empty string for empty)."""
    if not path:
        return ""
    return path.rsplit("/", 1)[-1]


def is_ai_runtime(name: str) -> bool:
    """True when ``name`` (basename or comm) looks like an AI/MCP runtime."""
    lowered = name.lower()
    if not lowered:
        return False
    if lowered in AI_RUNTIME_BASENAMES:
        return True
    # Handle versioned interpreters such as "python3.12" or "node18".
    base = lowered.split("-", 1)[0]
    if base in AI_RUNTIME_BASENAMES:
        return True
    return any(lowered.startswith(prefix) for prefix in ("python3", "node", "mcp"))


@dataclass(slots=True)
class ProcessNode:
    """One tracked process.

    ``pid`` is the *thread group id* (tgid) for user-space processes; kernel
    threads are not tracked.
    """

    pid: int
    ppid: int = 0
    comm: str = ""
    exe: str = ""
    args: str = ""
    uid: int = 0
    gid: int = 0
    cgroup_id: int = 0
    container_id: str = "host"
    mnt_ns: int = 0
    pid_ns: int = 0
    net_ns: int = 0
    start_time: int = 0
    last_seen: float = 0.0
    exit_seen: bool = False
    children: set[int] = field(default_factory=set)
    exec_count: int = 0

    @property
    def name(self) -> str:
        """Best available label for this process."""
        return basename(self.exe) or self.comm

    @property
    def is_container(self) -> bool:
        return self.container_id not in ("", "host")

    def describe(self) -> str:
        label = self.name or "?"
        return f"{label}[{self.pid}]"

    def to_dict(self) -> dict[str, object]:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "comm": self.comm,
            "exe": self.exe,
            "args": self.args,
            "uid": self.uid,
            "gid": self.gid,
            "cgroup_id": self.cgroup_id,
            "container_id": self.container_id,
            "mnt_ns": self.mnt_ns,
            "pid_ns": self.pid_ns,
            "net_ns": self.net_ns,
            "start_time": self.start_time,
            "exec_count": self.exec_count,
        }

    def to_row(self) -> str:
        """Compact ancestry row used by the TUI."""
        container = self.container_id[:12] if self.is_container else "host"
        return f"{self.name or '?'}({self.pid})@{container}"


class LineageGraph:
    """Bounded, TTL aware pid -> :class:`ProcessNode` index."""

    __slots__ = (
        "_nodes",
        "_exited",
        "_ttl",
        "_max_nodes",
        "_clock",
        "_evictions",
        "_updates",
    )

    def __init__(
        self,
        ttl: float = 5.0,
        max_nodes: int = 200_000,
        clock=time.monotonic,
    ) -> None:
        if ttl < 0:
            raise ValueError("ttl must be >= 0")
        if max_nodes < 16:
            raise ValueError("max_nodes must be >= 16")
        self._nodes: OrderedDict[int, ProcessNode] = OrderedDict()
        self._exited: dict[int, float] = {}
        self._ttl = float(ttl)
        self._max_nodes = int(max_nodes)
        self._clock = clock
        self._evictions = 0
        self._updates = 0

    # -- introspection ---------------------------------------------------- #
    def __len__(self) -> int:
        return len(self._nodes)

    def __contains__(self, pid: object) -> bool:
        return pid in self._nodes

    def __iter__(self) -> Iterator[ProcessNode]:
        return iter(list(self._nodes.values()))

    def node(self, pid: int) -> ProcessNode | None:
        """Return the node for ``pid`` (or ``None``)."""
        return self._nodes.get(pid)

    @property
    def stats(self) -> dict[str, int]:
        return {
            "nodes": len(self._nodes),
            "pending_exits": len(self._exited),
            "evictions": self._evictions,
            "updates": self._updates,
        }

    # -- ingestion -------------------------------------------------------- #
    def observe(self, event: Event) -> ProcessNode | None:
        """Feed one telemetry event into the graph.

        Returns the node it referred to.  Handles:
          * EXECVE   - (re)initialise the process image
          * PROCESS_EXIT - defer eviction by the grace TTL
          * anything else - refresh ``last_seen`` and create an implicit node
        """
        pid = event.tgid or event.pid
        if pid <= 0:
            return None

        now = self._clock()
        self._updates += 1
        node = self._nodes.get(pid)

        if event.event_type == EventType.PROCESS_EXIT:
            if node is None:
                node = ProcessNode(pid=pid, comm=event.comm)
                self._nodes[pid] = node
            node.comm = event.comm or node.comm
            node.exit_seen = True
            node.last_seen = now
            self._exited[pid] = now + self._ttl
            self._nodes.move_to_end(pid)
            return node

        if node is None:
            node = ProcessNode(
                pid=pid,
                ppid=event.ppid,
                comm=event.comm,
                exe=event.filename if event.event_type == EventType.EXECVE else "",
                args=event.args,
                uid=event.uid,
                gid=event.gid,
                cgroup_id=event.cgroup_id,
                container_id=event.container_id,
                mnt_ns=event.mnt_ns_id,
                pid_ns=event.pid_ns_id,
                net_ns=event.net_ns_id,
                start_time=event.timestamp_ns,
                last_seen=now,
                exec_count=1 if event.event_type == EventType.EXECVE else 0,
            )
            self._nodes[pid] = node
            # Register the child with its parent (if the parent is known) so
            # the graph can also be walked downwards.
            if node.ppid and node.ppid != pid:
                parent = self._nodes.get(node.ppid)
                if parent is not None:
                    parent.children.add(pid)
            self._evict_if_needed()
            return node

        # Refresh mutable identity; the kernel is authoritative.
        if event.ppid:
            node.ppid = event.ppid
        if event.comm:
            node.comm = event.comm
        if event.cgroup_id:
            node.cgroup_id = event.cgroup_id
        if event.container_id and event.container_id != "host":
            node.container_id = event.container_id
        if event.mnt_ns_id:
            node.mnt_ns = event.mnt_ns_id
        if event.pid_ns_id:
            node.pid_ns = event.pid_ns_id
        if event.net_ns_id:
            node.net_ns = event.net_ns_id
        if event.uid:
            node.uid = event.uid

        if event.event_type == EventType.EXECVE:
            node.exe = event.filename or node.exe
            node.args = event.args or node.args
            node.comm = event.comm or node.comm
            node.exec_count += 1
            node.start_time = event.timestamp_ns or node.start_time
            node.exit_seen = False
            self._exited.pop(pid, None)

        node.last_seen = now
        self._nodes.move_to_end(pid)
        return node

    # -- queries ---------------------------------------------------------- #
    def get_ancestry_chain(self, pid: int, max_depth: int = 8) -> list[ProcessNode]:
        """Return ``[self, parent, grandparent, ...]`` up to ``max_depth``.

        Unknown ancestors simply terminate the chain.  Cycles (possible with
        PID reuse across namespaces) are broken with a visited set.
        """
        chain: list[ProcessNode] = []
        seen: set[int] = set()
        current = pid
        depth = 0
        while current and depth < max_depth and current not in seen:
            node = self._nodes.get(current)
            if node is None:
                break
            chain.append(node)
            seen.add(current)
            if node.ppid == current:
                break
            current = node.ppid
            depth += 1
        return chain

    def ancestors(self, pid: int, max_depth: int = 8) -> list[ProcessNode]:
        """Ancestors excluding the process itself."""
        return self.get_ancestry_chain(pid, max_depth=max_depth)[1:]

    def ancestry_names(self, pid: int, max_depth: int = 8) -> list[str]:
        """Basenames along the ancestry chain, self excluded, nearest first."""
        return [basename(node.exe) or node.comm for node in self.ancestors(pid, max_depth)]

    def ancestry_has_ai_runtime(self, pid: int, max_depth: int = 8) -> bool:
        """True when any ancestor is an AI agent / MCP runtime binary."""
        return any(is_ai_runtime(name) for name in self.ancestry_names(pid, max_depth))

    def descendants(self, pid: int) -> list[ProcessNode]:
        """All known descendants of ``pid`` (breadth first)."""
        result: list[ProcessNode] = []
        queue = list(self._nodes.get(pid, ProcessNode(pid=pid)).children)
        seen: set[int] = set()
        while queue:
            current = queue.pop(0)
            if current in seen:
                continue
            seen.add(current)
            node = self._nodes.get(current)
            if node is None:
                continue
            result.append(node)
            queue.extend(node.children)
        return result

    def container_members(self, container_id: str) -> list[ProcessNode]:
        return [node for node in self._nodes.values() if node.container_id == container_id]

    def mark_exit(self, pid: int) -> None:
        """Schedule eviction of ``pid`` after the grace TTL."""
        node = self._nodes.get(pid)
        if node is None:
            return
        node.exit_seen = True
        self._exited[pid] = self._clock() + self._ttl

    # -- maintenance ------------------------------------------------------ #
    def prune(self) -> int:
        """Evict processes whose grace window elapsed.  Returns the count."""
        if not self._exited:
            return 0
        now = self._clock()
        expired = [pid for pid, deadline in self._exited.items() if deadline <= now]
        for pid in expired:
            self._exited.pop(pid, None)
            node = self._nodes.pop(pid, None)
            if node is None:
                continue
            parent = self._nodes.get(node.ppid)
            if parent is not None:
                parent.children.discard(pid)
            self._evictions += 1
        return len(expired)

    def _evict_if_needed(self) -> None:
        while len(self._nodes) > self._max_nodes:
            pid, node = self._nodes.popitem(last=False)
            self._exited.pop(pid, None)
            parent = self._nodes.get(node.ppid)
            if parent is not None:
                parent.children.discard(pid)
            self._evictions += 1

    def snapshot(self, limit: int = 20) -> list[dict[str, object]]:
        """Return the most recently active nodes (for the TUI / JSON dumps)."""
        nodes: Iterable[ProcessNode] = list(self._nodes.values())[-limit:]
        return [node.to_dict() for node in nodes]

    def clear(self) -> None:
        self._nodes.clear()
        self._exited.clear()


__all__ = [
    "AI_RUNTIME_BASENAMES",
    "LineageGraph",
    "MULTIPLEXER_BASENAMES",
    "NETWORK_TOOL_BASENAMES",
    "ProcessNode",
    "SHELL_BASENAMES",
    "basename",
    "is_ai_runtime",
]
