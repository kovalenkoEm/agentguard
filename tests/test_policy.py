from __future__ import annotations

from pathlib import Path

import pytest

from agentguard.policy import ALLOW, ASK, DENY, Policy, Request


@pytest.fixture()
def policy() -> Policy:
    return Policy(
        {
            "default": DENY,
            "trusted_binary_roots": ["/usr/bin", "/bin"],
            "capabilities": {
                "fs.read": {"scope": "workspace", "protected": ["**/.env", "**/.ssh/**"]},
                "fs.write": {"scope": "workspace"},
                "proc.spawn": {
                    "deny": ["sudo", "chmod", "python3"],
                    "ask": ["rm", "curl"],
                    "allow": ["ls", "cat", "git"],
                    "subcommands": {"git": {"deny": [["push"]], "ask": [["commit"]]}},
                },
            },
            "rules": [
                {"id": "no-network", "when": {"args_any": ["http://", "https://"]}, "action": ASK, "reason": "net"},
            ],
        }
    )


def req(capability, **kwargs) -> Request:
    base = {"tool": "t", "capability": capability, "root": "/ws"}
    base.update(kwargs)
    return Request(**base)


def test_read_inside_workspace(policy):
    decision = policy.evaluate(req("fs.read", paths=("/ws/a.txt",)))
    assert decision.action == ALLOW


def test_read_outside_workspace(policy):
    decision = policy.evaluate(req("fs.read", paths=(), outside_paths=("/home/x/.ssh/id_rsa",)))
    assert decision.action == DENY


def test_protected_glob(policy):
    decision = policy.evaluate(req("fs.read", paths=("/ws/.env",)))
    assert decision.action == DENY
    assert "protected" in decision.rule


def test_protected_glob_nested(policy):
    assert policy.evaluate(req("fs.read", paths=("/ws/.ssh/id_rsa",))).action == DENY


def test_scope_any(policy):
    p = Policy(
        {"default": DENY, "capabilities": {"fs.read": {"scope": "any"}}},
    )
    assert p.evaluate(req("fs.read", paths=("/etc/hosts",), outside_paths=("/etc/hosts",))).action == ALLOW


def test_scope_none(policy):
    p = Policy({"default": DENY, "capabilities": {"fs.read": {"scope": "none"}}})
    assert p.evaluate(req("fs.read", paths=("/ws/a.txt",))).action == DENY


def test_spawn_allowlisted(policy):
    assert policy.evaluate(req("proc.spawn", argv=("ls", "-la"), binary="ls", binary_path="/usr/bin/ls")).action == ALLOW


def test_spawn_denied_binary(policy):
    assert policy.evaluate(req("proc.spawn", argv=("sudo", "ls"), binary="sudo", binary_path="/usr/bin/sudo")).action == DENY


def test_spawn_ask_binary(policy):
    assert policy.evaluate(req("proc.spawn", argv=("rm", "x"), binary="rm", binary_path="/usr/bin/rm")).action == ASK


def test_spawn_unmapped_binary_fails_closed(policy):
    assert policy.evaluate(req("proc.spawn", argv=("nc", "x"), binary="nc", binary_path="/usr/bin/nc")).action == DENY


def test_spawn_untrusted_binary(policy):
    decision = policy.evaluate(
        req("proc.spawn", argv=("./ls",), binary="ls", binary_path="/tmp/evil/ls", untrusted_binary=True)
    )
    assert decision.action == DENY
    assert decision.rule == "untrusted-binary"


def test_subcommand_denied(policy):
    decision = policy.evaluate(req("proc.spawn", argv=("git", "push", "origin", "main"), binary="git", binary_path="/usr/bin/git"))
    assert decision.action == DENY
    assert "push" in decision.reason


def test_subcommand_ask(policy):
    assert policy.evaluate(req("proc.spawn", argv=("git", "commit", "-m", "x"), binary="git", binary_path="/usr/bin/git")).action == ASK


def test_subcommand_not_triggered_by_similar_word(policy):
    assert policy.evaluate(req("proc.spawn", argv=("git", "log"), binary="git", binary_path="/usr/bin/git")).action == ALLOW


def test_rule_precedes_capability(policy):
    decision = policy.evaluate(req("proc.spawn", argv=("ls", "http://x"), binary="ls", binary_path="/usr/bin/ls"))
    assert decision.action == ASK
    assert decision.rule == "no-network"


def test_spawn_argument_outside_workspace(policy):
    decision = policy.evaluate(
        req("proc.spawn", argv=("cat", "../private/.env"), binary="cat", binary_path="/usr/bin/cat", outside_paths=("../private/.env",))
    )
    assert decision.action == DENY


def test_unmapped_capability_fails_closed(policy):
    assert policy.evaluate(req("net.egress")).action == DENY


def test_unknown_rule_key_is_a_load_error():
    """A typo must not silently disable a rule."""
    with pytest.raises(ValueError, match="unknown matcher"):
        Policy({"rules": [{"id": "x", "when": {"args_prefx": ["rm"]}, "action": DENY}]})


def test_invalid_default_is_a_load_error():
    with pytest.raises(ValueError):
        Policy({"default": "allow-ish"})


def test_global_protected_applies_to_spawn():
    """`cat .env` must hit the same guard rail as `read_file('.env')`."""
    p = Policy(
        {
            "default": DENY,
            "protected": ["**/.env"],
            "capabilities": {"proc.spawn": {"allow": ["cat"]}},
        }
    )
    decision = p.evaluate(req("proc.spawn", argv=("cat", ".env"), binary="cat", binary_path="/bin/cat", paths=("/ws/.env",)))
    assert decision.action == DENY
    assert decision.rule == "proc.spawn.protected"


def test_global_protected_applies_to_fs():
    p = Policy({"default": DENY, "protected": ["**/id_rsa*"], "capabilities": {"fs.read": {"scope": "workspace"}}})
    assert p.evaluate(req("fs.read", paths=("/ws/deploy/id_rsa",))).action == DENY


def test_example_policy_loads():
    path = Path(__file__).resolve().parents[1] / "policy.example.yaml"
    loaded = Policy.load(path)
    assert loaded.default == DENY
    assert "proc.spawn" in loaded.capabilities
    assert loaded.trusted_binary_roots


def test_example_policy_blocks_ssh_and_pytest_ask():
    path = Path(__file__).resolve().parents[1] / "policy.example.yaml"
    loaded = Policy.load(path)
    assert loaded.evaluate(req("proc.spawn", argv=("cat", "~/.ssh/id_rsa"), binary="cat", binary_path="/usr/bin/cat", outside_paths=("/home/x/.ssh/id_rsa",))).action == DENY
    assert loaded.evaluate(req("proc.spawn", argv=("pytest",), binary="pytest", binary_path="/usr/bin/pytest")).action == ASK
