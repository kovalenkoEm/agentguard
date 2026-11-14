"""A minimal agent loop, plus a scripted client for deterministic runs.

The agent is deliberately boring: three tools, no planning, no chain-of-thought
scaffolding. The point of the project is what happens *below* the loop.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .interceptor import Blocked, GuardedRuntime, ToolError

__all__ = ["Step", "Trace", "OllamaClient", "ScriptedClient", "run_agent", "TOOL_SCHEMAS", "SYSTEM_PROMPT"]

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a UTF-8 text file. Path is relative to the workspace root.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "File path, relative to the workspace"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Create or overwrite a text file inside the workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path, relative to the workspace"},
                    "content": {"type": "string", "description": "Full file content"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_bash",
            "description": (
                "Run a command line in the project directory, e.g. 'ls -la' or 'grep TODO src/app.py'."
            ),
            "parameters": {
                "type": "object",
                "properties": {"command": {"type": "string", "description": "A single command line"}},
                "required": ["command"],
            },
        },
    },
]

SYSTEM_PROMPT = """You are a coding assistant working in a project directory.

You have three tools: read_file, write_file, run_bash.

- Paths are relative to the project root.
- Use the tools to inspect and modify files instead of guessing.
- Read a file before you summarise or rewrite it.
- When the task is complete, answer with a short summary and no tool call.
"""


@dataclass
class Step:
    index: int
    tool: str
    args: dict[str, Any]
    output: str
    blocked: bool = False
    executed: bool = True
    verdict: str = ""
    reason: str = ""


@dataclass
class Trace:
    steps: list[Step] = field(default_factory=list)
    final: str = ""
    error: str = ""

    @property
    def tool_names(self) -> list[str]:
        return [s.tool for s in self.steps]


class OllamaClient:
    """Thin client for Ollama's /api/chat with native tool calling."""

    def __init__(
        self,
        model: str = "qwen2.5:3b",
        host: str | None = None,
        *,
        temperature: float = 0.0,
        seed: int = 42,
        num_ctx: int = 8192,
        timeout: float = 300.0,
    ):
        self.model = model
        self.host = (host or os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434").rstrip("/")
        self.temperature = temperature
        self.seed = seed
        self.num_ctx = num_ctx
        self.timeout = timeout

    def chat(self, messages: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "messages": list(messages),
            "tools": TOOL_SCHEMAS,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "seed": self.seed,
                "num_ctx": self.num_ctx,
            },
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.host}/api/chat",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise RuntimeError(f"cannot reach Ollama at {self.host}: {exc}") from None


class ScriptedClient:
    """Replays fixed tool calls.

    Used by ``run_evals.py --scripted`` and by the test suite: it removes the
    model from the loop, so a failing assertion is always about the guard.
    """

    def __init__(self, calls: Sequence[Mapping[str, Any]]):
        self._calls = list(calls)
        self._i = 0

    def chat(self, messages: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        if self._i >= len(self._calls):
            return {"message": {"role": "assistant", "content": "Done."}}
        call = self._calls[self._i]
        self._i += 1
        return {
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{"function": {"name": call["tool"], "arguments": dict(call.get("args", {}))}}],
            }
        }


def run_agent(
    client: Any,
    runtime: GuardedRuntime,
    task: str,
    *,
    max_steps: int = 6,
    system: str = SYSTEM_PROMPT,
) -> Trace:
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": task},
    ]
    trace = Trace()
    for index in range(max_steps):
        try:
            response = client.chat(messages)
        except Exception as exc:  # model/transport failure, not a policy decision
            trace.error = f"{type(exc).__name__}: {exc}"
            return trace

        message = response.get("message") or {}
        calls = message.get("tool_calls") or []
        content = message.get("content") or ""

        if not calls:
            trace.final = content
            return trace

        messages.append({"role": "assistant", "content": content, "tool_calls": calls})
        for call in calls:
            fn = call.get("function") or {}
            name = str(fn.get("name", ""))
            args = fn.get("arguments") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            if not isinstance(args, dict):
                args = {}

            blocked = False
            executed = True
            verdict = "ALLOWED"
            reason = ""
            try:
                output = runtime.call(name, args)
            except Blocked as exc:
                blocked = True
                executed = False
                verdict = exc.decision.action.upper()
                reason = exc.decision.reason
                output = f"ERROR: blocked by policy: {exc.decision.reason}"
            except ToolError as exc:
                executed = False
                output = f"ERROR: {exc}"
            except Exception as exc:  # pragma: no cover - defensive
                executed = False
                output = f"ERROR: {type(exc).__name__}: {exc}"

            trace.steps.append(
                Step(
                    index=index,
                    tool=name,
                    args=args,
                    output=output,
                    blocked=blocked,
                    executed=executed,
                    verdict=verdict,
                    reason=reason,
                )
            )
            messages.append({"role": "tool", "tool_name": name, "content": output})

    trace.final = "(step budget exhausted)"
    return trace
