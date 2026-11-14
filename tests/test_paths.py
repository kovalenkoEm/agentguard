from __future__ import annotations

import os

import pytest

from agentguard.paths import analyse, canonical_root, is_within, rel_posix


@pytest.fixture()
def ws(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "notes.txt").write_text("hello", encoding="utf-8")
    return root


def test_relative_path_inside(ws):
    result = analyse(ws, "notes.txt")
    assert result.ok
    assert result.real == canonical_root(ws) / "notes.txt"


def test_dotdot_escape(ws):
    (ws.parent / "secret.txt").write_text("s3cret", encoding="utf-8")
    result = analyse(ws, "../secret.txt")
    assert not result.ok
    assert "outside" in result.reason


def test_deep_dotdot_escape(ws):
    assert not analyse(ws, "docs/../../secret.txt").ok


def test_absolute_outside(ws):
    assert not analyse(ws, str(ws.parent / "secret.txt")).ok


def test_home_expansion_refused(ws):
    result = analyse(ws, "~/.ssh/id_rsa")
    assert not result.ok
    assert "expansion" in result.reason


def test_nul_byte(ws):
    assert not analyse(ws, "notes\x00.txt").ok


def test_prefix_lookalike_is_not_contained(ws):
    sibling = ws.parent / (ws.name + "-evil")
    sibling.mkdir()
    assert not analyse(ws, str(sibling)).ok


def test_symlink_escape(ws):
    outside = ws.parent / "private"
    outside.mkdir()
    (outside / ".env").write_text("TOKEN=1", encoding="utf-8")
    link = ws / "pub"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted for this user")
    result = analyse(ws, "pub/.env")
    assert not result.ok, "a link out of the workspace must not be readable"


@pytest.mark.skipif(os.name != "nt", reason="windows path semantics")
def test_alternate_data_stream(ws):
    assert not analyse(ws, "notes.txt::$DATA").ok


@pytest.mark.skipif(os.name != "nt", reason="windows path semantics")
def test_device_name(ws):
    assert not analyse(ws, "NUL").ok
    assert not analyse(ws, "con.txt").ok


@pytest.mark.skipif(os.name != "nt", reason="windows path semantics")
def test_drive_relative(ws):
    assert not analyse(ws, "C:notes.txt").ok


def test_is_within_root_itself(ws):
    assert is_within(ws, ws)


def test_rel_posix(ws):
    assert rel_posix(ws / "a" / "b.txt", ws) == "a/b.txt"
