"""Path classification.

Everything the model names is a *claim*, not a fact. This module turns a claim
into a resolved location and classifies it against the workspace root.

Resolution has to survive the tricks that make naive ``startswith()`` checks
fail:

* ``../`` traversal and ``..\\`` on Windows
* symlinks and NTFS junctions (reparse points)
* 8.3 short names (``PROGRA~1``)
* case folding
* NTFS alternate data streams (``file.txt::$DATA``)
* Windows device names (``CON``, ``NUL``, ``COM1`` ...)
* ``~`` expansion into a home directory full of credentials

The rule is deliberately blunt: if the resolved location is not inside the
workspace root, the request is outside the sandbox. No exceptions, no
"it looked harmless".
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "PathAnalysis",
    "analyse",
    "canonical_root",
    "is_within",
    "rel_posix",
]

WINDOWS = os.name == "nt"

_DEVICE = re.compile(r"^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$", re.IGNORECASE)
_DRIVE = re.compile(r"^[A-Za-z]:")


@dataclass(frozen=True)
class PathAnalysis:
    """Result of classifying one model-supplied path."""

    raw: str
    real: Path | None
    in_workspace: bool
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.real is not None and self.in_workspace

    @property
    def display(self) -> str:
        return str(self.real) if self.real is not None else self.raw


def canonical_root(root: os.PathLike[str] | str) -> Path:
    """Absolute, symlink-free, true-case form of the workspace root."""
    return Path(os.path.realpath(os.fspath(root)))


def is_within(path: os.PathLike[str] | str, root: os.PathLike[str] | str) -> bool:
    p = os.path.normcase(os.path.abspath(os.fspath(path)))
    r = os.path.normcase(os.path.abspath(os.fspath(root)))
    if p == r:
        return True
    return p.startswith(r.rstrip("\\/") + os.sep)


def rel_posix(path: os.PathLike[str] | str, root: os.PathLike[str] | str) -> str:
    """Workspace-relative POSIX path, for glob matching in the policy."""
    try:
        rel = os.path.relpath(os.fspath(path), os.fspath(root))
    except ValueError:  # different drives on Windows
        return os.fspath(path).replace("\\", "/")
    return rel.replace("\\", "/")


def analyse(root: os.PathLike[str] | str, candidate: str) -> PathAnalysis:
    """Resolve ``candidate`` against ``root`` and say whether it is contained."""
    root_real = canonical_root(root)

    if not isinstance(candidate, str) or not candidate.strip():
        return PathAnalysis(str(candidate), None, False, "empty path")

    if "\x00" in candidate:
        return PathAnalysis(candidate, None, False, "embedded NUL byte")

    if candidate.startswith("~"):
        return PathAnalysis(
            candidate,
            None,
            False,
            "home-directory expansion (~) is not permitted",
        )

    if WINDOWS:
        # "C:file" is drive-relative; "a.txt:stream" is an alternate data stream.
        if _DRIVE.match(candidate):
            if len(candidate) > 2 and candidate[2] not in "\\/":
                return PathAnalysis(candidate, None, False, "drive-relative path")
            tail = candidate[2:]
            if ":" in tail:
                return PathAnalysis(candidate, None, False, "alternate data stream")
        elif ":" in candidate:
            return PathAnalysis(candidate, None, False, "alternate data stream")
        name = candidate.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        if _DEVICE.match(name):
            return PathAnalysis(candidate, None, False, "Windows device name")

    try:
        p = Path(candidate)
        if not p.is_absolute():
            p = root_real / candidate
        real = Path(os.path.realpath(os.fspath(p)))
    except (OSError, ValueError) as exc:  # pragma: no cover - platform dependent
        return PathAnalysis(candidate, None, False, f"unresolvable path: {exc}")

    if is_within(real, root_real):
        return PathAnalysis(candidate, real, True, "")
    return PathAnalysis(candidate, real, False, "resolves outside the workspace")
