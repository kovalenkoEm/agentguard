"""The reference monitor: it is the only path from a tool call to the machine.

Structural property worth stating: :class:`GuardedRuntime` never executes
anything itself. It hands a :class:`~agentguard.policy.Request` and a callable to
:meth:`Guard.execute`, and execution only happens inside that callable. A tool
therefore cannot "forget" the check -- there is no code path that runs a command
without a verdict first.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .audit import AuditLog
from .commands import (
    ShellSyntaxError,
    binary_name,
    binary_trusted,
    classify_arguments,
    locate_binary,
    parse_argv,
    resolve_binary,
    trust_target,
)
from .paths import PathAnalysis, analyse, canonical_root, rel_posix
from .policy import ALLOW, ASK, DENY, Decision, Policy, Request

__all__ = ["Blocked", "UserDenied", "Guard", "GuardedRuntime", "ToolError"]

MAX_OUTPUT = 4000


class Blocked(Exception):
    """A tool call was refused by policy."""

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"blocked by policy [{decision.rule}]: {decision.reason}")


class UserDenied(Blocked):
    """A tool call needed confirmation and the human said no."""


class ToolError(Exception):
    """The tool was allowed but could not be executed."""


def _clip(text: str, limit: int = MAX_OUTPUT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, {len(text)} chars total]"


class Guard:
    """Policy + audit + human approval, in one place."""

    def __init__(
        self,
        policy: Policy,
        root: os.PathLike[str] | str,
        *,
        audit: AuditLog | None = None,
        approver: Callable[[Request, Decision], bool] | None = None,
        home: os.PathLike[str] | str | None = None,
        timeout: float = 20.0,
        binary_roots: Sequence[str] | None = None,
        env_passthrough: Sequence[str] = (),
    ):
        self.policy = policy
        self.root = canonical_root(root)
        self.audit = audit
        # Default is deny: an unattended run must not approve itself.
        self.approver = approver or (lambda req, decision: False)
        self.timeout = timeout
        self.home = canonical_root(home) if home else self.root / ".agenthome"
        Path(self.home).mkdir(parents=True, exist_ok=True)
        self.binary_roots = tuple(binary_roots if binary_roots is not None else policy.trusted_binary_roots)
        self.env_passthrough = tuple(env_passthrough)
        self.env = self._sandbox_env()

    # ------------------------------------------------------------------ env
    def _sandbox_env(self) -> dict[str, str]:
        """A minimal environment.

        The agent process holds API keys in ``os.environ`` (it needs them to talk
        to the model). If a spawned command inherits that environment, ``env`` is
        an exfiltration primitive that no binary allowlist can close. So the child
        gets a curated environment and a throwaway HOME.
        """
        keep = {
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "SYSTEMDRIVE",
            "WINDIR",
            "COMSPEC",
            "OS",
            "PROCESSOR_ARCHITECTURE",
            "NUMBER_OF_PROCESSORS",
            "TZ",
        }
        env = {k: v for k, v in os.environ.items() if k in keep}
        for name in self.env_passthrough:
            if name in os.environ:
                env[name] = os.environ[name]
        tmp = Path(self.home) / "tmp"
        tmp.mkdir(parents=True, exist_ok=True)
        env.update(
            {
                "HOME": str(self.home),
                "USERPROFILE": str(self.home),
                "TMPDIR": str(tmp),
                "TMP": str(tmp),
                "TEMP": str(tmp),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "TERM": "dumb",
                "NO_COLOR": "1",
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "PYTHONNOUSERSITE": "1",
                "PIP_NO_INPUT": "1",
            }
        )
        return env

    @property
    def path(self) -> str:
        return self.env.get("PATH", "")

    # ---------------------------------------------------------------- auditing
    def record(self, event: str, **fields: Any) -> None:
        if self.audit is not None:
            self.audit.append(event, **fields)

    @staticmethod
    def _payload(req: Request, decision: Decision | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "tool": req.tool,
            "capability": req.capability,
            "request": req.display,
            "argv": list(req.argv) or None,
            "binary": req.binary or None,
            "paths": list(req.paths) or None,
            "outside": list(req.outside_paths) or None,
        }
        if decision is not None:
            payload["verdict"] = decision.action.upper()
            payload["rule"] = decision.rule
            payload["reason"] = decision.reason
        return payload

    # -------------------------------------------------------------- decisions
    def check(self, req: Request) -> Decision:
        decision = self.policy.evaluate(req)
        self.record("decision", **self._payload(req, decision))
        return decision

    def authorize(self, req: Request) -> Decision:
        decision = self.check(req)
        if decision.action == DENY:
            raise Blocked(decision)
        if decision.action == ASK:
            approved = bool(self.approver(req, decision))
            self.record(
                "approval",
                tool=req.tool,
                request=req.display,
                rule=decision.rule,
                approved=approved,
                verdict="ALLOWED" if approved else "USER_DENIED",
            )
            if not approved:
                raise UserDenied(
                    Decision(DENY, f"{decision.reason} -- nobody approved it", "user-denied")
                )
        return decision

    def execute(self, req: Request, fn: Callable[[], Any]) -> Any:
        decision = self.authorize(req)
        try:
            result = fn()
        except Exception as exc:
            self.record("failed", tool=req.tool, request=req.display, error=f"{type(exc).__name__}: {exc}")
            raise
        self.record("executed", tool=req.tool, request=req.display, rule=decision.rule, verdict="ALLOWED")
        return result


class GuardedRuntime:
    """The three tools the agent actually gets."""

    def __init__(self, guard: Guard):
        self.guard = guard
        self.root = guard.root

    # ------------------------------------------------------------------- fs
    def _fs_request(self, tool: str, capability: str, path: str) -> Request:
        analysis: PathAnalysis = analyse(self.root, path)
        return Request(
            tool=tool,
            capability=capability,
            root=str(self.root),
            display=f"{tool}({path!r})",
            paths=(str(analysis.real),) if analysis.real is not None else (),
            outside_paths=() if analysis.ok else (analysis.display,),
            note=analysis.reason,
        )

    def _recheck(self, target: Path) -> None:
        """Re-resolve immediately before touching the filesystem.

        This narrows the check-to-use window; it does not close it. A concurrent
        attacker who can create symlinks inside the workspace can still swap a
        component between this call and the ``open``. See README / Threat model.
        """
        again = analyse(self.root, os.fspath(target))
        if not again.ok or again.real != target:
            raise Blocked(Decision(DENY, "path changed between check and use", "toctou"))

    def read_file(self, path: str) -> str:
        req = self._fs_request("read_file", "fs.read", path)
        target = Path(req.paths[0]) if req.paths else None

        def _read() -> str:
            assert target is not None
            self._recheck(target)
            data = target.read_bytes()
            self.guard.record(
                "read",
                tool="read_file",
                path=str(target),
                bytes=len(data),
                sha256=hashlib.sha256(data).hexdigest()[:16],
            )
            return _clip(data.decode("utf-8", errors="replace"))

        return self.guard.execute(req, _read)

    def write_file(self, path: str, content: str) -> str:
        if not isinstance(content, str):
            content = json.dumps(content, ensure_ascii=False) if isinstance(content, (dict, list)) else str(content)
        req = self._fs_request("write_file", "fs.write", path)
        target = Path(req.paths[0]) if req.paths else None

        def _write() -> str:
            assert target is not None
            self._recheck(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            self._recheck(target.parent)
            target.write_text(content, encoding="utf-8")
            self.guard.record("write", tool="write_file", path=str(target), bytes=len(content.encode()))
            return f"wrote {len(content.encode('utf-8'))} bytes to {rel_posix(target, self.root)}"

        return self.guard.execute(req, _write)

    # ----------------------------------------------------------------- bash
    def run_bash(self, command: str) -> str:
        try:
            argv = parse_argv(command)
        except ShellSyntaxError as exc:
            decision = Decision(DENY, str(exc), "no-shell")
            self.guard.record(
                "blocked",
                tool="run_bash",
                request=command,
                verdict="BLOCKED",
                rule=decision.rule,
                reason=decision.reason,
            )
            raise Blocked(decision) from None

        binary_path = resolve_binary(argv[0], self.guard.path)
        if binary_path is None:
            self.guard.record("not-found", tool="run_bash", request=command, program=argv[0])
            return f"ERROR: command not found: {argv[0]}"
        located = locate_binary(argv[0], self.guard.path)
        trusted_at = trust_target(argv[0], located, binary_path)

        args = classify_arguments(self.root, argv)
        req = Request(
            tool="run_bash",
            capability="proc.spawn",
            root=str(self.root),
            display=command,
            argv=argv,
            # The policy is written in terms of the command the model asked for
            # ("rm", "git"), so that is the key. The resolved file is a separate
            # fact, used only for the trust check: on some images /usr/bin/rm is
            # a link to a differently named binary, and keying the policy on the
            # resolved basename silently disables every allowlist entry.
            binary=binary_name(Path(argv[0])),
            binary_path=str(binary_path),
            untrusted_binary=not binary_trusted(trusted_at or binary_path, self.guard.binary_roots),
            paths=tuple(str(a.real) for a in args if a.real is not None and a.in_workspace),
            outside_paths=tuple(a.display for a in args if not a.ok),
            note=next((a.reason for a in args if not a.ok and a.reason), ""),
        )

        def _run() -> str:
            try:
                proc = subprocess.run(
                    list(argv),
                    cwd=str(self.root),
                    env=self.guard.env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    errors="replace",
                    timeout=self.guard.timeout,
                )
            except subprocess.TimeoutExpired:
                raise ToolError(f"command timed out after {self.guard.timeout}s") from None
            except OSError as exc:
                raise ToolError(f"could not execute {argv[0]}: {exc}") from None
            body = proc.stdout or ""
            if proc.stderr:
                body += f"\n[stderr] {proc.stderr}"
            return f"exit={proc.returncode}\n{_clip(body)}"

        return self.guard.execute(req, _run)

    # --------------------------------------------------------------- dispatch
    def call(self, name: str, args: Mapping[str, Any]) -> str:
        if name == "read_file":
            return self.read_file(str(args.get("path", "")))
        if name == "write_file":
            return self.write_file(str(args.get("path", "")), args.get("content", ""))
        if name == "run_bash":
            return self.run_bash(str(args.get("command", "")))
        raise ToolError(f"unknown tool: {name}")
