"""xSypher-Stream - declarative, hot-path threat rule engine.

Rules are loaded from YAML (or JSON) and compiled once into ``RuleSpec``
objects holding pre-normalised sets, so evaluating an event is a handful of
set lookups and string prefix tests.  The whole evaluation path is allocation
light and measures well under the 500 us budget (see the benchmark output of
``tests/simulate_mcp_attack.py``).

Condition model
---------------
``conditions`` is a mapping that is ANDed:

* a scalar condition (``container_only: true``) must hold;
* a list condition (``exe_in: [sh, bash]``) holds when the event matches *any*
  element;
* ``any_of`` holds when *any* of the nested condition groups holds.  Each group
  is itself evaluated with the same AND/OR rules, which keeps genuinely
  multi-shape rules (memfd_create **or** exec-from-shm) in one declaration.

Supported conditions
--------------------
``event_types``, ``exe_in``, ``exe_not_in``, ``exe_prefix_in``, ``exe_suffix_in``,
``comm_in``, ``comm_not_in``, ``path_prefix_in``, ``path_suffix_in``,
``path_contains``, ``args_contains``, ``dport_in``, ``daddr_in``,
``container_only``, ``container_or_comm_in``, ``ancestor_has_ai_runtime``,
``ancestor_any_in``, ``ancestor_min_depth``, ``uid_in``, ``uid_not_in``,
``monitor_only``.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Final, Iterable, Mapping, Sequence

from .abi import BlockReason, Event, EventType
from .lineage import LineageGraph, basename, is_ai_runtime

SEVERITIES: Final[tuple[str, ...]] = ("info", "low", "medium", "high", "critical")
_SEVERITY_RANK: Final[dict[str, int]] = {name: rank for rank, name in enumerate(SEVERITIES)}

VALID_ACTIONS: Final[frozenset[str]] = frozenset(
    {"quarantine_pid", "quarantine_cgroup", "block_ipv4", "kill", "block_imds"}
)

_EVENT_NAME_TO_TYPE: Final[dict[str, int]] = {
    name: value for value, name in EventType.NAMES.items()
}

#: Condition keys understood by the evaluator (used for validation).
_KNOWN_CONDITIONS: Final[frozenset[str]] = frozenset(
    {
        "event_types",
        "exe_in",
        "exe_not_in",
        "exe_prefix_in",
        "exe_suffix_in",
        "comm_in",
        "comm_not_in",
        "path_prefix_in",
        "path_suffix_in",
        "path_contains",
        "args_contains",
        "dport_in",
        "daddr_in",
        "uid_in",
        "uid_not_in",
        "container_only",
        "container_or_comm_in",
        "ancestor_has_ai_runtime",
        "ancestor_any_in",
        "ancestor_min_depth",
        "monitor_only",
        "any_of",
        "exe_ino_in",
        "block_reason_in",
        "enforced_inline",
    }
)


class RuleError(ValueError):
    """Raised when a rule document is malformed."""


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass(slots=True)
class RuleMatch:
    """A rule that fired for a specific event."""

    rule_id: str
    title: str
    severity: str
    level: int
    description: str
    actions: tuple[str, ...]
    reason: str
    tags: tuple[str, ...]
    event: Event
    ancestry: tuple[str, ...]
    timestamp_ns: int = 0
    monitored: bool = False

    @property
    def subject_pid(self) -> int:
        return self.event.tgid or self.event.pid

    @property
    def subject_cgroup(self) -> int:
        return self.event.cgroup_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "reason": self.reason,
            "actions": list(self.actions),
            "tags": list(self.tags),
            "pid": self.event.pid,
            "tgid": self.event.tgid,
            "comm": self.event.comm,
            "container_id": self.event.container_id,
            "cgroup_id": self.event.cgroup_id,
            "event_type": self.event.event_name,
            "filename": self.event.filename,
            "args": self.event.args,
            "daddr": self.event.daddr_v4 or self.event.daddr_v6,
            "dport": self.event.dport,
            "ancestry": list(self.ancestry),
        }


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return [str(item) for item in value]
    return [str(value)]


def _as_int_list(value: Any) -> list[int]:
    result: list[int] = []
    for item in _as_list(value):
        try:
            result.append(int(item, 0) if isinstance(item, str) else int(item))
        except (TypeError, ValueError) as exc:
            raise RuleError(f"expected integer list element, got {item!r}") from exc
    return result


@dataclass(slots=True)
class ConditionGroup:
    """One AND-group of conditions."""

    event_types: frozenset[int] = frozenset()
    exe_in: frozenset[str] = frozenset()
    exe_not_in: frozenset[str] = frozenset()
    exe_prefix_in: tuple[str, ...] = ()
    exe_suffix_in: tuple[str, ...] = ()
    comm_in: frozenset[str] = frozenset()
    comm_not_in: frozenset[str] = frozenset()
    path_prefix_in: tuple[str, ...] = ()
    path_suffix_in: tuple[str, ...] = ()
    path_contains: tuple[str, ...] = ()
    args_contains: tuple[str, ...] = ()
    dport_in: frozenset[int] = frozenset()
    daddr_in: frozenset[str] = frozenset()
    uid_in: frozenset[int] = frozenset()
    uid_not_in: frozenset[int] = frozenset()
    container_only: bool = False
    container_or_comm_in: frozenset[str] = frozenset()
    ancestor_has_ai_runtime: bool = False
    ancestor_any_in: frozenset[str] = frozenset()
    ancestor_min_depth: int = 0
    monitor_only: bool = False
    exe_ino_in: frozenset[int] = frozenset()
    block_reason_in: frozenset[int] = frozenset()
    enforced_inline: bool = False

    def evaluate(self, event: Event, exe: str, comm: str,
                 ancestry: Sequence[str]) -> str | None:
        """Return a human readable reason when the group matches, else None."""
        if self.event_types and event.event_type not in self.event_types:
            return None
        if self.exe_in and exe not in self.exe_in:
            return None
        if self.exe_not_in and exe in self.exe_not_in:
            return None
        if self.exe_prefix_in and not event.filename.startswith(self.exe_prefix_in):
            return None
        if self.exe_suffix_in and not event.filename.endswith(self.exe_suffix_in):
            return None
        if self.comm_in and comm not in self.comm_in:
            return None
        if self.comm_not_in and comm in self.comm_not_in:
            return None

        path = event.filename
        if self.path_prefix_in and not path.startswith(self.path_prefix_in):
            return None
        if self.path_suffix_in and not path.endswith(self.path_suffix_in):
            return None
        if self.path_contains and not any(token in path for token in self.path_contains):
            return None

        if self.args_contains:
            blob = event.args.lower()
            if not any(token in blob for token in self.args_contains):
                return None

        if self.dport_in and event.dport not in self.dport_in:
            return None
        if self.daddr_in:
            daddr = event.daddr_v4 or event.daddr_v6
            if daddr not in self.daddr_in:
                return None

        if self.uid_in and event.uid not in self.uid_in:
            return None
        if self.uid_not_in and event.uid in self.uid_not_in:
            return None

        if self.container_only and not event.is_container:
            return None
        if self.container_or_comm_in:
            in_container = event.is_container
            if not in_container and comm not in self.container_or_comm_in:
                return None

        if self.ancestor_min_depth and len(ancestry) < self.ancestor_min_depth:
            return None
        if self.ancestor_any_in and not any(name in self.ancestor_any_in for name in ancestry):
            return None
        if self.ancestor_has_ai_runtime:
            if not any(is_ai_runtime(name) for name in ancestry):
                return None

        if self.exe_ino_in and event.target_ino not in self.exe_ino_in:
            return None
        if self.block_reason_in and event.open_flags not in self.block_reason_in:
            return None
        if self.enforced_inline and not event.enforced_inline:
            return None

        return "matched"

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any], where: str) -> "ConditionGroup":
        unknown = set(raw) - _KNOWN_CONDITIONS
        if unknown:
            raise RuleError(f"{where}: unknown condition(s) {sorted(unknown)}")

        def lowered(values: Any) -> frozenset[str]:
            return frozenset(item.lower() for item in _as_list(values))

        def raw_strings(values: Any) -> tuple[str, ...]:
            return tuple(_as_list(values))

        try:
            return cls(
                event_types=frozenset(
                    _EVENT_NAME_TO_TYPE[name.lower()] for name in _as_list(raw.get("event_types"))
                ),
                exe_in=lowered(raw.get("exe_in")),
                exe_not_in=lowered(raw.get("exe_not_in")),
                exe_prefix_in=raw_strings(raw.get("exe_prefix_in")),
                exe_suffix_in=raw_strings(raw.get("exe_suffix_in")),
                comm_in=lowered(raw.get("comm_in")),
                comm_not_in=lowered(raw.get("comm_not_in")),
                path_prefix_in=raw_strings(raw.get("path_prefix_in")),
                path_suffix_in=raw_strings(raw.get("path_suffix_in")),
                path_contains=tuple(token.lower() for token in _as_list(raw.get("path_contains"))),
                args_contains=tuple(token.lower() for token in _as_list(raw.get("args_contains"))),
                dport_in=frozenset(_as_int_list(raw.get("dport_in"))),
                daddr_in=frozenset(_as_list(raw.get("daddr_in"))),
                uid_in=frozenset(_as_int_list(raw.get("uid_in"))),
                uid_not_in=frozenset(_as_int_list(raw.get("uid_not_in"))),
                container_only=bool(raw.get("container_only", False)),
                container_or_comm_in=lowered(raw.get("container_or_comm_in")),
                ancestor_has_ai_runtime=bool(raw.get("ancestor_has_ai_runtime", False)),
                ancestor_any_in=lowered(raw.get("ancestor_any_in")),
                ancestor_min_depth=int(raw.get("ancestor_min_depth", 0) or 0),
                monitor_only=bool(raw.get("monitor_only", False)),
                exe_ino_in=frozenset(_as_int_list(raw.get("exe_ino_in"))),
                block_reason_in=frozenset(_as_int_list(raw.get("block_reason_in"))),
                enforced_inline=bool(raw.get("enforced_inline", False)),
            )
        except KeyError as exc:  # unknown event type name
            raise RuleError(f"{where}: unknown event type {exc}") from exc


@dataclass(slots=True)
class RuleSpec:
    """A compiled rule."""

    id: str
    title: str
    severity: str
    level: int
    description: str
    actions: tuple[str, ...]
    tags: tuple[str, ...]
    enabled: bool = True
    monitor_only: bool = False
    conditions: ConditionGroup = field(default_factory=ConditionGroup)
    any_of: tuple[ConditionGroup, ...] = ()

    @property
    def event_types(self) -> frozenset[int]:
        types = set(self.conditions.event_types)
        for group in self.any_of:
            types |= set(group.event_types)
        return frozenset(types)

    def matches(self, event: Event, exe: str, comm: str,
                ancestry: Sequence[str]) -> str | None:
        """Return a reason string when the rule matches, else ``None``."""
        if self.conditions.evaluate(event, exe, comm, ancestry) is None:
            return None
        matched_group = -1
        if self.any_of:
            for index, group in enumerate(self.any_of):
                if group.evaluate(event, exe, comm, ancestry) is not None:
                    matched_group = index
                    break
            if matched_group < 0:
                return None
        return self._describe(event, exe, comm, matched_group)

    @staticmethod
    def _describe(event: Event, exe: str, comm: str, group_index: int) -> str:
        """Build the short human readable match reason shown in the TUI."""
        parts = [f"exe={exe or comm or '?'}"]
        if event.event_type == EventType.CONNECT:
            target = event.daddr_v4 or event.daddr_v6 or "?"
            parts.append(f"peer={target}:{event.dport}")
        elif event.event_type in (EventType.OPENAT, EventType.MEMFD_CREATE):
            parts.append(f"path={event.filename or '?'}")
        elif event.event_type == EventType.LSM_BLOCK:
            parts.append(f"lsm_denied={event.filename or '?'}")
        elif event.event_type == EventType.ENFORCED_INLINE:
            parts.append(f"inline_block={BlockReason.name(event.open_flags)}")
        if event.container_id and event.container_id != "host":
            parts.append(f"container={event.container_id[:12]}")
        if group_index >= 0:
            parts.append(f"variant={group_index}")
        return " ".join(parts)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any], where: str) -> "RuleSpec":
        rule_id = str(raw.get("id", "")).strip()
        if not rule_id:
            raise RuleError(f"{where}: rule is missing an 'id'")
        severity = str(raw.get("severity", "medium")).lower()
        if severity not in _SEVERITY_RANK:
            raise RuleError(f"{where}: invalid severity {severity!r}")

        actions_raw = _as_list(raw.get("actions"))
        actions = tuple(action.lower() for action in actions_raw)
        for action in actions:
            if action not in VALID_ACTIONS:
                raise RuleError(f"{where}: unknown action {action!r}")
        if not actions:
            raise RuleError(f"{where}: rule declares no actions")

        conditions_raw = raw.get("conditions") or {}
        if not isinstance(conditions_raw, Mapping):
            raise RuleError(f"{where}: 'conditions' must be a mapping")

        any_of_raw = conditions_raw.get("any_of") or []
        if not isinstance(any_of_raw, Sequence) or isinstance(any_of_raw, (str, bytes)):
            raise RuleError(f"{where}: 'any_of' must be a list of condition mappings")

        base_mapping = {k: v for k, v in conditions_raw.items() if k != "any_of"}
        # `event_types` is conventionally declared at the rule level; fold it
        # into the base condition group so indexing stays a single lookup.
        if "event_types" in raw and "event_types" not in base_mapping:
            base_mapping["event_types"] = raw["event_types"]
        groups = tuple(
            ConditionGroup.from_mapping(group, f"{where}.any_of[{index}]")
            for index, group in enumerate(any_of_raw)
        )

        monitor_only = bool(raw.get("monitor_only", False))

        return cls(
            id=rule_id,
            title=str(raw.get("title", rule_id)),
            severity=severity,
            level=_SEVERITY_RANK[severity],
            description=str(raw.get("description", "")).strip(),
            actions=actions,
            tags=tuple(_as_list(raw.get("tags"))),
            enabled=bool(raw.get("enabled", True)),
            monitor_only=monitor_only,
            conditions=ConditionGroup.from_mapping(base_mapping, f"{where}.conditions"),
            any_of=groups,
        )


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #

class RuleEngine:
    """Loads, validates and evaluates the rule set."""

    def __init__(
        self,
        rules: Iterable[RuleSpec],
        *,
        max_ancestry_depth: int = 8,
        cooldown_seconds: float = 5.0,
        clock=time.monotonic,
    ) -> None:
        self._rules = tuple(rule for rule in rules if rule.enabled)
        if not self._rules:
            raise RuleError("no enabled rules loaded")
        self._by_event_type: dict[int, tuple[RuleSpec, ...]] = {}
        for rule in self._rules:
            types = rule.event_types
            if not types:
                # A rule without event_type constraints must run on everything.
                types = frozenset(EventType.NAMES)
            for event_type in types:
                self._by_event_type.setdefault(event_type, ())
                self._by_event_type[event_type] += (rule,)

        self.max_ancestry_depth = int(max_ancestry_depth)
        self.cooldown_seconds = float(cooldown_seconds)
        self._clock = clock
        self._last_fired: dict[tuple[str, int], float] = {}
        self._evaluations = 0
        self._matches = 0
        self._suppressed = 0

    # -- construction ------------------------------------------------------ #
    @classmethod
    def from_file(cls, path: str | os.PathLike[str], **kwargs: Any) -> "RuleEngine":
        """Load rules from YAML (``.yaml``/``.yml``) or JSON (``.json``)."""
        text = open(os.fspath(path), "r", encoding="utf-8").read()
        document = cls.parse_document(text, path=os.fspath(path))
        settings = document.get("settings") or {}
        kwargs.setdefault("max_ancestry_depth", int(settings.get("max_ancestry_depth", 8)))
        kwargs.setdefault("cooldown_seconds", float(settings.get("cooldown_seconds", 5.0)))
        return cls(cls.parse_rules(document, path=os.fspath(path)), **kwargs)

    @classmethod
    def from_document(cls, document: Mapping[str, Any], **kwargs: Any) -> "RuleEngine":
        settings = document.get("settings") or {}
        kwargs.setdefault("max_ancestry_depth", int(settings.get("max_ancestry_depth", 8)))
        kwargs.setdefault("cooldown_seconds", float(settings.get("cooldown_seconds", 5.0)))
        return cls(cls.parse_rules(document, path="<document>"), **kwargs)

    @staticmethod
    def parse_document(text: str, *, path: str = "<string>") -> dict[str, Any]:
        """Parse a JSON or YAML rule document into a mapping."""
        stripped = text.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            return json.loads(text)
        try:
            import yaml  # noqa: PLC0415 - optional dependency, imported lazily
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise RuleError(
                "PyYAML is required to load YAML rule files; install it with "
                "`pip install pyyaml` or provide a JSON rule document instead"
            ) from exc
        document = yaml.safe_load(text)
        if not isinstance(document, dict):
            raise RuleError(f"{path}: rule document must be a mapping")
        return document

    @staticmethod
    def parse_rules(document: Mapping[str, Any], *, path: str = "<document>") -> list[RuleSpec]:
        raw_rules = document.get("rules")
        if not isinstance(raw_rules, Sequence) or not raw_rules:
            raise RuleError(f"{path}: 'rules' must be a non-empty list")
        specs: list[RuleSpec] = []
        seen: set[str] = set()
        for index, raw in enumerate(raw_rules):
            if not isinstance(raw, Mapping):
                raise RuleError(f"{path}: rules[{index}] must be a mapping")
            spec = RuleSpec.from_mapping(raw, where=f"{path}:rules[{index}]")
            if spec.id in seen:
                raise RuleError(f"{path}: duplicate rule id {spec.id!r}")
            seen.add(spec.id)
            specs.append(spec)
        return specs

    # -- evaluation -------------------------------------------------------- #
    def candidates(self, event_type: int) -> tuple[RuleSpec, ...]:
        """Rules that can possibly fire for an event type (pre-indexed)."""
        return self._by_event_type.get(event_type, ())

    def evaluate(self, event: Event, lineage: LineageGraph) -> list[RuleMatch]:
        """Evaluate every candidate rule for ``event``.

        ``lineage`` is used to resolve the ancestry chain once per event (not
        once per rule), which keeps the hot path cheap.
        """
        self._evaluations += 1
        rules = self._by_event_type.get(event.event_type)
        if not rules:
            return []

        comm = event.comm.lower()
        pid = event.tgid or event.pid
        if event.event_type == EventType.EXECVE:
            # For execve the observed path *is* the new process image.
            exe = basename(event.filename).lower() or comm
        else:
            # For connect/openat/memfd the filename is a resource, not the
            # process, so use the identity recorded by the lineage graph.
            node = lineage.node(pid) if pid > 0 else None
            exe = (basename(node.exe).lower() or node.comm.lower()) if node else comm

        needs_ancestry = any(
            rule.conditions.ancestor_has_ai_runtime
            or rule.conditions.ancestor_any_in
            or rule.conditions.ancestor_min_depth
            or any(
                group.ancestor_has_ai_runtime or group.ancestor_any_in or group.ancestor_min_depth
                for group in rule.any_of
            )
            for rule in rules
        )
        ancestry: tuple[str, ...] = ()
        if needs_ancestry and pid > 0:
            ancestry = tuple(
                name.lower() for name in lineage.ancestry_names(pid, self.max_ancestry_depth)
            )

        matches: list[RuleMatch] = []
        now = self._clock()
        for rule in rules:
            reason = rule.matches(event, exe, comm, ancestry)
            if reason is None:
                continue

            key = (rule.id, pid)
            last = self._last_fired.get(key)
            if last is not None and now - last < self.cooldown_seconds:
                self._suppressed += 1
                continue
            self._last_fired[key] = now

            self._matches += 1
            matches.append(
                RuleMatch(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    level=rule.level,
                    description=rule.description,
                    actions=rule.actions,
                    reason=reason,
                    tags=rule.tags,
                    event=event,
                    ancestry=ancestry,
                    timestamp_ns=event.timestamp_ns,
                    monitored=rule.monitor_only,
                )
            )
        return matches

    def evaluate_many(self, events: Iterable[Event], lineage: LineageGraph) -> list[RuleMatch]:
        """Convenience helper for batch/replay evaluation."""
        results: list[RuleMatch] = []
        for event in events:
            lineage.observe(event)
            results.extend(self.evaluate(event, lineage))
        return results

    # -- introspection ----------------------------------------------------- #
    @property
    def rules(self) -> tuple[RuleSpec, ...]:
        return self._rules

    @property
    def stats(self) -> dict[str, int]:
        return {
            "evaluations": self._evaluations,
            "matches": self._matches,
            "suppressed": self._suppressed,
            "rules": len(self._rules),
        }

    @property
    def cooldown_entries(self) -> int:
        """Number of live (rule, pid) cooldown entries (exported as a gauge)."""
        return len(self._last_fired)

    def reset_cooldowns(self) -> None:
        self._last_fired.clear()


__all__ = [
    "ConditionGroup",
    "RuleEngine",
    "RuleError",
    "RuleMatch",
    "RuleSpec",
    "SEVERITIES",
    "VALID_ACTIONS",
]
