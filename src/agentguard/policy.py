"""The policy engine.

A tool call becomes a :class:`Request` -- a capability plus resolved facts about
it (canonical binary path, resolved file paths, whether anything escaped the
workspace). The engine answers ALLOW / ASK / DENY. It is pure: no I/O, no
environment, no model input beyond the request. That makes every decision unit
testable and every verdict reproducible from the audit log.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import yaml

from .paths import rel_posix

__all__ = ["ALLOW", "ASK", "DENY", "Decision", "Request", "Rule", "Policy"]

ALLOW = "allow"
ASK = "ask"
DENY = "deny"


@dataclass(frozen=True)
class Decision:
    action: str
    reason: str = ""
    rule: str = "default"

    @property
    def allowed(self) -> bool:
        return self.action == ALLOW

    def __str__(self) -> str:  # pragma: no cover - display helper
        label = self.action.upper()
        return f"{label} [{self.rule}]: {self.reason}" if self.reason else f"{label} [{self.rule}]"


@dataclass(frozen=True)
class Request:
    """One capability request, compiled from a tool call."""

    tool: str
    capability: str
    root: str
    display: str = ""
    argv: tuple[str, ...] = ()
    binary: str = ""
    binary_path: str = ""
    untrusted_binary: bool = False
    paths: tuple[str, ...] = ()
    outside_paths: tuple[str, ...] = ()
    note: str = ""

    def rel(self, path: str) -> str:
        return rel_posix(path, self.root)


def _norm(value: Any) -> str:
    return os.path.normcase(str(value))


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def _match_glob(rel: str, pattern: str) -> bool:
    """Glob match where ``**/x`` also matches a bare ``x`` at the root."""
    rel = rel.replace(os.sep, "/")
    pat = str(pattern).replace(os.sep, "/")
    if fnmatch.fnmatchcase(rel, pat):
        return True
    if pat.startswith("**/"):
        tail = pat[3:]
        if fnmatch.fnmatchcase(rel, tail):
            return True
        if fnmatch.fnmatchcase(rel.rsplit("/", 1)[-1], tail):
            return True
    return False


@dataclass(frozen=True)
class Rule:
    id: str
    when: Mapping[str, Any] = field(default_factory=dict)
    action: str = DENY
    reason: str = ""

    def matches(self, req: Request) -> bool:
        for key, expected in self.when.items():
            if key == "binary":
                if _norm(req.binary) != _norm(expected):
                    return False
            elif key == "tool":
                if req.tool != expected:
                    return False
            elif key == "capability":
                if req.capability != expected:
                    return False
            elif key == "args_any":
                tail = " ".join(req.argv[1:]).lower()
                if not any(str(p).lower() in tail for p in _as_list(expected)):
                    return False
            elif key == "args_prefix":
                prefix = [str(p) for p in _as_list(expected)]
                if list(req.argv[1 : 1 + len(prefix)]) != prefix:
                    return False
            elif key == "args_contains":
                if not all(str(p) in req.argv for p in _as_list(expected)):
                    return False
            elif key == "path_any":
                patterns = _as_list(expected)
                rels = [req.rel(p) for p in req.paths]
                if not any(_match_glob(r, pat) for r in rels for pat in patterns):
                    return False
            else:  # unknown matcher: fail closed, never treat as "matches"
                return False
        return True


class Policy:
    #: Keys a rule may match on. An unknown key is a policy bug, not a no-op:
    #: `args_prefx` would silently disable the rule, so loading is strict.
    RULE_KEYS = frozenset(
        {"binary", "tool", "capability", "args_any", "args_prefix", "args_contains", "path_any"}
    )

    def __init__(self, data: Mapping[str, Any], source: str = "<memory>"):
        self.source = source
        self.version = data.get("version", 1)
        self.default = str(data.get("default", DENY)).lower()
        if self.default not in (ALLOW, ASK, DENY):
            raise ValueError(f"{source}: default must be allow/ask/deny, got {self.default!r}")
        self.capabilities: dict[str, Mapping[str, Any]] = dict(data.get("capabilities") or {})
        self.rules: list[Rule] = []
        for i, r in enumerate(data.get("rules") or []):
            when = dict(r.get("when") or {})
            unknown = set(when) - self.RULE_KEYS
            if unknown:
                raise ValueError(
                    f"{source}: rule {r.get('id', i)!r} uses unknown matcher(s) {sorted(unknown)}; "
                    f"known: {sorted(self.RULE_KEYS)}"
                )
            action = str(r.get("action", DENY)).lower()
            if action not in (ALLOW, ASK, DENY):
                raise ValueError(f"{source}: rule {r.get('id', i)!r} has invalid action {action!r}")
            self.rules.append(
                Rule(id=str(r.get("id", f"rule-{i}")), when=when, action=action, reason=str(r.get("reason", "")))
            )
        # Top-level protected patterns apply to every capability that touches a
        # path: `cat .env` and `read_file(".env")` are the same request wearing
        # different clothes, so they must not have separate policy lists.
        self.protected: tuple[str, ...] = tuple(str(p) for p in (data.get("protected") or ()))
        self.trusted_binary_roots: tuple[str, ...] = tuple(
            str(p) for p in (data.get("trusted_binary_roots") or ())
        )

    # ------------------------------------------------------------------ loading
    @classmethod
    def load(cls, path: os.PathLike[str] | str) -> "Policy":
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if not isinstance(data, Mapping):
            raise ValueError(f"policy {path} must be a mapping")
        return cls(data, source=os.fspath(path))

    @classmethod
    def permissive(cls) -> "Policy":
        """Baseline policy: everything allowed. Used by the eval harness only."""
        return cls(
            {
                "default": ALLOW,
                "capabilities": {
                    "fs.read": {"scope": "any"},
                    "fs.write": {"scope": "any"},
                    "proc.spawn": {"allow": [], "ask": [], "deny": []},
                },
            },
            source="<permissive>",
        )

    # --------------------------------------------------------------- evaluation
    def evaluate(self, req: Request) -> Decision:
        if req.untrusted_binary:
            return Decision(
                DENY,
                f"binary {req.binary_path or req.binary!r} resolves outside the trusted binary roots",
                "untrusted-binary",
            )

        for rule in self.rules:
            if rule.matches(req):
                return Decision(rule.action, rule.reason or rule.id, rule.id)

        cap = self.capabilities.get(req.capability)
        if not cap:
            return Decision(DENY, f"no policy for capability {req.capability!r}", "unmapped-capability")

        if req.capability.startswith("fs."):
            return self._evaluate_fs(req, cap)
        if req.capability == "proc.spawn":
            return self._evaluate_spawn(req, cap)
        action = str(cap.get("action", self.default)).lower()
        return Decision(action, f"{req.capability}", f"{req.capability}.action")

    # ----------------------------------------------------------------- fs.*
    def _evaluate_fs(self, req: Request, cap: Mapping[str, Any]) -> Decision:
        scope = str(cap.get("scope", "none")).lower()
        if scope == "none":
            return Decision(DENY, f"{req.capability} is disabled by policy", f"{req.capability}.scope")

        if req.outside_paths and scope != "any":
            reason = req.note or "path resolves outside the workspace"
            return Decision(
                DENY,
                f"{reason}: {req.outside_paths[0]}",
                f"{req.capability}.scope",
            )

        protected = [*self.protected, *_as_list(cap.get("protected"))]
        for path in req.paths:
            rel = req.rel(path)
            for pattern in protected:
                if _match_glob(rel, pattern):
                    return Decision(
                        DENY,
                        f"{rel} matches protected pattern {pattern}",
                        f"{req.capability}.protected",
                    )

        action = str(cap.get("action", ALLOW)).lower()
        if action == ALLOW:
            return Decision(ALLOW, f"{req.capability} within {scope} scope", f"{req.capability}.scope")
        return Decision(action, f"{req.capability} requires confirmation", f"{req.capability}.action")

    # ------------------------------------------------------------- proc.spawn
    def _evaluate_spawn(self, req: Request, cap: Mapping[str, Any]) -> Decision:
        name = _norm(req.binary)
        tail = list(req.argv[1:])

        subcommands = cap.get("subcommands") or {}
        per_binary = subcommands.get(req.binary) or subcommands.get(name) or {}
        for action in (DENY, ASK):
            for prefix in per_binary.get(action) or []:
                wanted = [str(p) for p in prefix]
                if tail[: len(wanted)] == wanted:
                    return Decision(
                        action,
                        f"`{req.binary} {' '.join(wanted)}` is {action}ed by policy",
                        f"proc.spawn.subcommands.{req.binary}.{action}",
                    )

        if name in {_norm(b) for b in _as_list(cap.get("deny"))}:
            return Decision(DENY, f"`{req.binary}` is a blocked binary", "proc.spawn.deny")

        if req.outside_paths:
            reason = req.note or "argument resolves outside the workspace"
            return Decision(DENY, f"{reason}: {req.outside_paths[0]}", "proc.spawn.scope")

        protected = [*self.protected, *_as_list(cap.get("protected"))]
        for path in req.paths:
            rel = req.rel(path)
            for pattern in protected:
                if _match_glob(rel, pattern):
                    return Decision(
                        DENY,
                        f"argument {rel} matches protected pattern {pattern}",
                        "proc.spawn.protected",
                    )

        if name in {_norm(b) for b in _as_list(cap.get("ask"))}:
            return Decision(ASK, f"`{req.binary}` requires human confirmation", "proc.spawn.ask")

        if name in {_norm(b) for b in _as_list(cap.get("allow"))}:
            return Decision(ALLOW, f"`{req.binary}` is allowlisted", "proc.spawn.allow")

        return Decision(
            self.default,
            f"`{req.binary}` is not allowlisted",
            "proc.spawn.unmapped",
        )
