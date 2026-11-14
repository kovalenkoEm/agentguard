from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from agentguard.audit import AuditLog
from agentguard.interceptor import Blocked, Guard, GuardedRuntime, ToolError, UserDenied
from agentguard.policy import DENY, Policy


def _policy() -> Policy:
    return Policy(
        {
            "default": DENY,
            "protected": ["**/.env"],
            "capabilities": {
                "fs.read": {"scope": "workspace"},
                "fs.write": {"scope": "workspace"},
                "proc.spawn": {"deny": ["chmod", "python3"], "ask": ["rm"], "allow": ["ls", "cat"]},
            },
        }
    )


def _trusted_roots(*names: str) -> list[str]:
    """Installation roots of the binaries this test actually runs.

    Deriving the trusted roots from the binary under test (rather than from a
    random other one) keeps the test honest on hosts where `realpath` lands in a
    different directory — some images ship `/usr/bin/rm` as a link elsewhere.
    """
    roots = set()
    for name in names:
        found = shutil.which(name)
        if found:
            roots.add(str(Path(os.path.realpath(found)).parent))
    return sorted(roots)


@pytest.fixture()
def env(tmp_path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / "README.md").write_text("# hi\n", encoding="utf-8")
    (ws / ".env").write_text("TOKEN=inside\n", encoding="utf-8")
    private = tmp_path / "private"
    private.mkdir()
    (private / ".env").write_text("SECRET=AGENTGUARD_TEST\n", encoding="utf-8")

    roots = _trusted_roots("ls", "cat", "rm")
    if not roots:
        pytest.skip("no POSIX tools on PATH")
    guard = Guard(
        _policy(),
        ws,
        audit=AuditLog(tmp_path / "audit.jsonl"),
        binary_roots=roots,
    )
    return ws, private, guard, GuardedRuntime(guard)


def test_read_inside(env):
    ws, _, _, runtime = env
    assert "hi" in runtime.read_file("README.md")


def test_direct_call_is_still_checked(env):
    """The bypass that matters: a tool called directly, without the agent loop."""
    _, _, _, runtime = env
    with pytest.raises(Blocked):
        runtime.read_file("../private/.env")


def test_protected_file_inside_workspace(env):
    _, _, _, runtime = env
    with pytest.raises(Blocked):
        runtime.read_file(".env")


def test_absolute_path_outside(env):
    ws, private, _, runtime = env
    with pytest.raises(Blocked):
        runtime.read_file(str(private / ".env"))


def test_home_path_refused(env):
    _, _, _, runtime = env
    with pytest.raises(Blocked):
        runtime.read_file("~/.ssh/id_rsa")


def test_symlink_escape(env):
    ws, private, _, runtime = env
    link = ws / "pub"
    try:
        os.symlink(private, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted for this user")
    with pytest.raises(Blocked):
        runtime.read_file("pub/.env")


def test_write_inside(env):
    ws, _, _, runtime = env
    runtime.write_file("out/new.txt", "hello")
    assert (ws / "out" / "new.txt").read_text(encoding="utf-8") == "hello"


def test_write_outside(env):
    _, private, _, runtime = env
    with pytest.raises(Blocked):
        runtime.write_file("../private/pwned.txt", "x")
    assert not (private / "pwned.txt").exists()


@pytest.mark.skipif(shutil.which("cat") is None, reason="no cat on this host")
def test_cat_outside_path(env):
    _, _, _, runtime = env
    with pytest.raises(Blocked):
        runtime.run_bash("cat ../private/.env")


@pytest.mark.skipif(shutil.which("cat") is None, reason="no cat on this host")
def test_cat_inside_is_allowed(env):
    _, _, _, runtime = env
    assert "hi" in runtime.run_bash("cat README.md")


@pytest.mark.skipif(shutil.which("cat") is None, reason="no cat on this host")
def test_cat_protected_file_inside_workspace(env):
    _, _, _, runtime = env
    with pytest.raises(Blocked):
        runtime.run_bash("cat .env")


def test_shell_syntax_blocked(env):
    _, _, _, runtime = env
    with pytest.raises(Blocked):
        runtime.run_bash("ls -la; cat ../private/.env")


def test_denied_binary(env):
    _, _, _, runtime = env
    with pytest.raises(Blocked):
        runtime.run_bash("chmod -R 777 .")


def test_ask_without_approver_denies(env):
    _, _, _, runtime = env
    with pytest.raises(UserDenied):
        runtime.run_bash("rm README.md")


def test_ask_with_approver_allows(env):
    ws, _, guard, runtime = env
    guard.approver = lambda req, decision: True
    (ws / "junk.txt").write_text("x", encoding="utf-8")
    runtime.run_bash("rm junk.txt")
    assert not (ws / "junk.txt").exists()


def test_env_is_sanitized(env):
    _, _, guard, _ = env
    os.environ["AGENTGUARD_TEST_CANARY"] = "must-not-leak"
    try:
        guard2 = Guard(_policy(), guard.root, binary_roots=list(guard.binary_roots))
        assert "AGENTGUARD_TEST_CANARY" not in guard2.env
        assert "OPENAI_API_KEY" not in guard2.env
    finally:
        os.environ.pop("AGENTGUARD_TEST_CANARY", None)


def test_unknown_tool(env):
    _, _, _, runtime = env
    with pytest.raises(Exception):
        runtime.call("rm_rf", {"path": "/"})


def test_policy_key_is_the_invoked_name(env, monkeypatch):
    """`rm` must stay `rm` in the policy even when it resolves to another file.

    Some images ship /usr/bin/rm as a link to a differently named binary. Keying
    the policy on the resolved basename made every allowlist entry miss and the
    guard blocked everything -- found by CI on a fresh runner, not locally.
    """
    ws, _, guard, runtime = env
    real = shutil.which("cat")
    if not real:
        pytest.skip("no cat on this host")
    shadow = Path(real).with_name("gnu-cat")
    monkeypatch.setattr("agentguard.interceptor.resolve_binary", lambda name, path=None: shadow)

    output = runtime.run_bash("cat README.md")
    assert "hi" in output

    events = [
        json.loads(line)
        for line in Path(guard.audit.path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    decision = [event for event in events if event.get("event") == "decision"][-1]
    assert decision["binary"] == "cat", "policy key must be the invoked name, not the resolved file"
    assert decision["verdict"] == "ALLOW"

