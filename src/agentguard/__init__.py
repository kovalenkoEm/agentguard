"""AgentGuard -- a policy-enforcing capability layer for LLM agents."""

from .agent import OllamaClient, ScriptedClient, run_agent
from .audit import AuditLog
from .interceptor import Blocked, Guard, GuardedRuntime, ToolError, UserDenied
from .paths import analyse
from .policy import ALLOW, ASK, DENY, Decision, Policy, Request

__version__ = "0.1.0"

__all__ = [
    "ALLOW",
    "ASK",
    "DENY",
    "AuditLog",
    "Blocked",
    "Decision",
    "Guard",
    "GuardedRuntime",
    "OllamaClient",
    "Policy",
    "Request",
    "ScriptedClient",
    "ToolError",
    "UserDenied",
    "analyse",
    "run_agent",
    "__version__",
]
