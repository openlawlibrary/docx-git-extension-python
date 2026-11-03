#!/usr/bin/env python3
"""
zippy_track.py - `git zippy track` / `untrack`: the .gitattributes lines.

Like `git lfs track`, so nobody has to remember the right combination:

    git zippy track "*.docx" "*.odt" --lfs
    ->  *.docx filter=zippy merge=binary -text zippy-lfs=jpg,jpeg,png,emf
        *.odt  filter=zippy merge=binary -text zippy-lfs=jpg,jpeg,png,emf

    filter=zippy     store the document unpacked
    merge=binary     never merge two versions line by line: a text merge of
                     two pointers leaves conflict markers in a pointer and the
                     checkout fails (or, worse, mixes lines of both)
    -text            no line-ending conversion of pointers (core.autocrlf)
    zippy-lfs=...    part types that go to Git LFS; --lfs alone means
                     jpg,jpeg,png,emf, --lfs=gif,png picks them, no --lfs: none

Only the repository's top-level .gitattributes is edited, and only lines for
the given patterns; everything else in the file is kept as it is. Like
`git lfs track`, files already committed are not converted: re-add them.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

ATTRS = "filter=zippy merge=binary -text"
DEFAULT_LFS = "jpg,jpeg,png,emf"
REQUIRED = ("merge=binary", "-text")


def escape(pattern: str) -> str:
    """As git-lfs does: whitespace cannot appear literally in a pattern."""
    p = pattern.replace(" ", "[[:space:]]")
    return "\\" + p if p.startswith("#") else p


def _read(path: Path) -> List[str]:
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


def _write(path: Path, lines: List[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _pattern_of(line: str) -> Optional[str]:
    s = line.strip()
    return s.split()[0] if s and not s.startswith("#") else None


def zippy_lines(repo_dir) -> List[Tuple[str, str]]:
    """(pattern, line) for every filter=zippy line in .gitattributes."""
    return [(_pattern_of(l), l) for l in _read(Path(repo_dir) / ".gitattributes")
            if _pattern_of(l) and "filter=zippy" in l.split()]


def problems(line: str) -> List[str]:
    tokens = line.split()
    return [a for a in REQUIRED if a not in tokens]


def track(repo_dir, patterns: List[str], lfs: Optional[str]) -> List[str]:
    path = Path(repo_dir) / ".gitattributes"
    lines = _read(path)
    report = []
    for pattern in patterns:
        esc = escape(pattern)
        new = f"{esc} {ATTRS}" + (f" zippy-lfs={lfs}" if lfs else "")
        idx = [i for i, l in enumerate(lines) if _pattern_of(l) == esc]
        if not idx:
            lines.append(new)
            report.append(f'Tracking "{pattern}"')
            continue
        old = lines[idx[0]]
        for i in reversed(idx[1:]):              # one line per pattern
            del lines[i]
        lines[idx[0]] = new
        if old.strip() == new:
            report.append(f'"{pattern}" already tracked')
        elif "filter=zippy" in old.split():
            report.append(f'Updated "{pattern}"   (was: {old.strip()})')
        else:
            report.append(f'Tracking "{pattern}" - replaced: {old.strip()}')
    _write(path, lines)
    for pattern in patterns:
        n = subprocess.run(["git", "ls-files", "--", pattern], cwd=repo_dir,
                           capture_output=True, text=True).stdout.split()
        if n:
            report.append(f'{len(n)} file(s) matching "{pattern}" are already committed; '
                          f're-add them: git add --renormalize -- "{pattern}"')
    report.append("Commit .gitattributes so every clone gets it: git add .gitattributes")
    return report


def untrack(repo_dir, patterns: List[str]) -> List[str]:
    path = Path(repo_dir) / ".gitattributes"
    lines = _read(path)
    report = []
    for pattern in patterns:
        esc = escape(pattern)
        keep = [l for l in lines if not (_pattern_of(l) == esc and "filter=zippy" in l.split())]
        report.append(f'Untracking "{pattern}"' if len(keep) < len(lines) else f'"{pattern}" was not tracked')
        lines = keep
    _write(path, lines)
    return report


def parse_args(args: List[str]) -> Tuple[List[str], Optional[str]]:
    patterns, lfs = [], None
    for a in args:
        if a == "--lfs":
            lfs = DEFAULT_LFS
        elif a.startswith("--lfs="):
            lfs = ",".join(e.strip().lstrip(".").lower() for e in a[6:].split(",") if e.strip()) or None
        elif a == "--no-lfs":
            lfs = None
        elif a.startswith("-"):
            raise ValueError(f"unknown option {a}")
        else:
            patterns.append(a)
    return patterns, lfs
