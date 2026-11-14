"""Command parsing and binary resolution.

Two structural rules, both cheap to state and cheap to enforce:

1. **There is no shell.** The tool layer executes an argv vector, never a
   command string. ``;``, ``&&``, ``|``, ``$()`` and backticks therefore cannot
   chain or substitute anything: with ``shell=False`` they are literals.
2. **Shell syntax is refused, not interpreted.** If a command line contains a
   control operator we block it instead of trying to reason about quoting.
   Quoting never makes a control operator safe, so there is nothing to be
   clever about -- and no quoting-based bypass to find.

Because there is no shell there is also no globbing: ``rm -rf *`` deletes a file
literally named ``*``. That is a feature, not an oversight.

What is *not* structural and needs the policy: which binary, with which
arguments, against which paths.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
from pathlib import Path
from typing import Sequence

from .paths import WINDOWS, PathAnalysis, analyse

__all__ = [
    "ShellSyntaxError",
    "parse_argv",
    "resolve_binary",
    "binary_trusted",
    "looks_like_path",
    "classify_arguments",
]

# Any of these in the raw command line means "this is shell, not argv".
#
# Notes on what is deliberately NOT here: `{}` and `(` `)` carry no meaning to an
# argv vector, and they are load-bearing for legitimate commands
# (`find . -name '*.py' -exec grep -n TODO {} +`). Refusing them costs utility and
# buys nothing -- the eval found that false positive and the set was narrowed.
SHELL_CONTROL = ";&|$`<>\n\r\x00"

_DRIVE = re.compile(r"^[A-Za-z]:")


class ShellSyntaxError(ValueError):
    """The command line used shell syntax, which this tool layer never runs."""


def parse_argv(command: str) -> tuple[str, ...]:
    """Split a command line into an argv vector or refuse it."""
    if not isinstance(command, str):
        raise ShellSyntaxError("command must be a string")
    text = command.strip()
    if not text:
        raise ShellSyntaxError("empty command")

    bad = sorted({ch for ch in text if ch in SHELL_CONTROL})
    if bad:
        rendered = ", ".join(repr(ch) for ch in bad)
        raise ShellSyntaxError(
            f"shell control characters are not accepted ({rendered}): "
            "run a single command with arguments instead"
        )
    if text.startswith("!"):
        raise ShellSyntaxError("history expansion is not accepted")

    try:
        argv = shlex.split(text, posix=True)
    except ValueError as exc:
        raise ShellSyntaxError(f"unparsable command line: {exc}") from exc

    if not argv:
        raise ShellSyntaxError("empty command")
    if argv[0].startswith("-"):
        raise ShellSyntaxError(f"command must start with a program name, got {argv[0]!r}")
    return tuple(argv)


def resolve_binary(name: str, search_path: str | None = None) -> Path | None:
    """Resolve a program name to its real location, or None if it is missing."""
    if not name or name.startswith("-"):
        return None
    if os.sep in name or "/" in name or (WINDOWS and _DRIVE.match(name)):
        candidate = Path(name)
        try:
            if not candidate.exists():
                return None
            return Path(os.path.realpath(os.fspath(candidate)))
        except OSError:  # pragma: no cover - platform dependent
            return None
    found = shutil.which(name, path=search_path)
    if not found:
        return None
    try:
        return Path(os.path.realpath(found))
    except OSError:  # pragma: no cover
        return Path(found)


def binary_trusted(path: Path, roots: Sequence[str]) -> bool:
    """True when the binary lives in one of the trusted installation roots.

    Without this, ``./ls`` or ``/tmp/payload/ls`` would match an allowlist entry
    named after a harmless tool while running attacker-controlled code.
    """
    if not roots:
        return False
    real = os.path.normcase(os.fspath(path))
    for root in roots:
        r = os.path.normcase(os.fspath(root)).rstrip("\\/")
        if real == r or real.startswith(r + os.sep):
            return True
    return False


_EXE_SUFFIXES = (".exe", ".cmd", ".bat", ".com")


def binary_name(path: Path) -> str:
    """The name a user typed: ``ls.exe`` and ``./bin/ls`` are both ``ls``.

    This is the *policy key*, not the trust decision. Trust uses the resolved
    path (see :func:`binary_trusted`); keying the policy on the resolved
    basename breaks on any host that ships ``rm`` as a link to a differently
    named file, which silently disables the whole allowlist.
    """
    name = path.name
    if WINDOWS:
        lowered = name.lower()
        for suffix in _EXE_SUFFIXES:
            if lowered.endswith(suffix) and len(name) > len(suffix):
                return name[: -len(suffix)]
    return name


def looks_like_path(token: str) -> bool:
    """True when a token is unambiguously a path (kept for callers that need a
    cheap pre-filter without touching the filesystem)."""
    if not token or token.startswith("-"):
        return False
    if token.startswith("~"):
        return True
    if "/" in token or ("\\" in token and WINDOWS):
        return True
    if WINDOWS and _DRIVE.match(token):
        return True
    return False


_VALUE_PREFIXES = ("file://", "@", "file=")


def _candidates(token: str) -> list[str]:
    """Path candidates inside one token.

    ``curl -d @file``, ``--data=@file``, ``--output=file`` and ``file://host/p``
    all carry a path that is not the whole token. Detection has to see it, or a
    network client becomes a private-file reader with an extra step.
    """
    out = [token]
    for prefix in _VALUE_PREFIXES:
        if token.startswith(prefix) and len(token) > len(prefix):
            out.append(token[len(prefix) :])
    if "=" in token:
        out.append(token.split("=", 1)[1])
    return out


def classify_arguments(
    root: os.PathLike[str] | str, argv: Sequence[str]
) -> list[PathAnalysis]:
    """Classify every argument that could name an existing file.

    Existence is the filter, deliberately. A ``*``-glob, a regex like
    ``/src/.*?TODO`` or a search pattern is not a path, and treating it as one
    produces false positives that cost real utility (the eval caught ``grep -oP
    '/src/.*?TODO'`` being denied as an absolute path). A path that does not
    exist cannot be read anyway, and every binary that *creates* files (``cp``,
    ``mv``, ``tar``, ``curl``, ``tee``) is in ``ask`` or ``deny``, so the gap is
    covered by the binary policy instead of by guessing about strings.

    ``~`` is always classified: expanding it is refused outright, whatever the
    file's existence.
    """
    out: list[PathAnalysis] = []
    for token in argv[1:]:
        if token.startswith("-"):
            if "=" not in token:
                continue
            candidates = [token.split("=", 1)[1]]
        else:
            candidates = _candidates(token)
        for candidate in candidates:
            if candidate.startswith("~"):
                out.append(analyse(root, candidate))
                continue
            resolved = Path(candidate) if os.path.isabs(candidate) else Path(root) / candidate
            try:
                exists = resolved.exists()
            except OSError:  # pragma: no cover - unreadable parent
                exists = False
            if exists:
                out.append(analyse(root, candidate))
    return out
