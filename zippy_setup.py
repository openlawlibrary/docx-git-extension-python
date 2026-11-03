#!/usr/bin/env python3
"""
zippy_setup.py - per-repository setup, done once, automatically.

`git zippy install` configures the filter once per machine, like
`git lfs install`. Everything a single repository needs on top of that is set
up here the first time the clean or smudge filter runs in it - so a plain
`git clone` is enough, with no extra step per clone:

  * hooks: post-commit (adds parts trees to the container) and pre-push
    (pushes the container before the branch), each followed by git-lfs's own
    hook so LFS keeps working;
  * fetch refspec per remote: +refs/zippy/parts:refs/zippy-remotes/<remote>/parts;
  * zippy.setup = <SETUP_VERSION> in the repository config, so the work is
    done once - and redone, hooks included, when SETUP_VERSION changes. Bump
    it whenever hook_text() changes: every repository then rewrites its hooks
    on its next filter run (this is how the Rust binary will take over).

The hooks call the launcher, `git-zippy hook <name>`, by its absolute path.
They name no interpreter: the launcher picks the Python `git zippy install`
recorded (zippy.python), so a new venv only needs a new install, and the
Rust binary - also `git-zippy` - will take the same command line.

Hooks are never overwritten blindly: a hook git-zippy wrote is refreshed, one
git-lfs wrote is replaced (ours runs git-lfs's afterwards), and any other hook
is left alone with a warning that says what to add to it.
"""

from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional

import parts_container

SETUP_VERSION = "2"     # 2: hooks call the launcher instead of python + zippy_cli.py
MARKER = "# git-zippy hook"
EXT_DIR = Path(__file__).resolve().parent
LAUNCHER = EXT_DIR / "git-zippy"
HOOK_NAMES = ("post-commit", "pre-push")
REFSPEC = "+{ref}:refs/zippy-remotes/{remote}/parts"


def _git(repo_dir, *args, check=False) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=repo_dir, capture_output=True, text=True, check=check)


def _q(s) -> str:
    return shlex.quote(str(s))


def hook_command(name: str) -> str:
    # `sh <launcher>`, not the launcher alone: copying the extension (e.g. from
    # a Windows drive into WSL) can drop the executable bit.
    return f"sh {_q(LAUNCHER)} hook {name}" + (' "$@"' if name == "pre-push" else "")


def hook_text(name: str) -> str:
    run = hook_command(name).replace(' "$@"', "")
    if name == "post-commit":
        return (f"#!/bin/sh\n{MARKER} (post-commit): git zippy, then git-lfs\n"
                f"{run}\n"
                f"command -v git-lfs >/dev/null 2>&1 && git lfs post-commit \"$@\"\n"
                f"exit 0\n")
    # pre-push: both need the same refs on stdin; a failure in either stops the push
    return (f"#!/bin/sh\n{MARKER} (pre-push): git zippy, then git-lfs\n"
            f"refs=\"$(mktemp)\" || exit 1\n"
            f"trap 'rm -f \"$refs\"' EXIT\n"
            f"cat > \"$refs\"\n"
            f"{run} \"$@\" < \"$refs\" || exit 1\n"
            f"if command -v git-lfs >/dev/null 2>&1; then\n"
            f"  git lfs pre-push \"$@\" < \"$refs\" || exit 1\n"
            f"fi\n"
            f"exit 0\n")


def classify_hook(path: Path) -> str:
    """'missing', 'zippy', 'lfs' (written by git-lfs) or 'foreign'."""
    if not path.exists():
        return "missing"
    try:
        body = path.read_text(errors="replace")
    except OSError:
        return "foreign"
    if MARKER in body:
        return "zippy"
    lines = [l for l in body.splitlines() if l.strip() and not l.startswith("#")]
    if lines and all("git-lfs" in l or "git lfs" in l for l in lines):
        return "lfs"
    return "foreign"


def hooks_dir(repo_dir) -> Optional[Path]:
    """The hooks directory, or None when core.hooksPath points elsewhere (shared)."""
    if _git(repo_dir, "config", "--get", "core.hooksPath").stdout.strip():
        return None
    out = _git(repo_dir, "rev-parse", "--git-path", "hooks").stdout.strip()
    return (Path(repo_dir) / out).resolve() if out else None


def install_hooks(repo_dir, force: bool = False) -> Dict[str, str]:
    """Write our hooks where allowed; returns name -> what happened."""
    result = {}
    hdir = hooks_dir(repo_dir)
    if hdir is None:
        return {n: "skipped: core.hooksPath is set; add the git zippy hooks there by hand"
                for n in HOOK_NAMES}
    hdir.mkdir(parents=True, exist_ok=True)
    for name in HOOK_NAMES:
        path = hdir / name
        kind = classify_hook(path)
        if kind == "foreign" and not force:
            result[name] = (f"left alone: {path} is not git-zippy's; add this line to it: "
                            f"{hook_command(name)}")
            continue
        path.write_text(hook_text(name))
        path.chmod(0o755)
        result[name] = {"missing": "installed", "zippy": "updated", "lfs": "replaced git-lfs's (ours runs it)",
                        "foreign": "overwritten (--force)"}[kind]
    return result


def add_refspecs(repo_dir) -> int:
    added = 0
    for remote in _git(repo_dir, "remote").stdout.split():
        spec = REFSPEC.format(ref=parts_container.REF, remote=remote)
        have = _git(repo_dir, "config", "--get-all", f"remote.{remote}.fetch").stdout.split("\n")
        if spec not in have:
            _git(repo_dir, "config", "--add", f"remote.{remote}.fetch", spec)
            added += 1
    return added


def setup_repo(repo_dir, force: bool = False) -> Dict[str, str]:
    report = install_hooks(repo_dir, force)
    report["refspecs"] = f"{add_refspecs(repo_dir)} added"
    _git(repo_dir, "config", "zippy.setup", SETUP_VERSION)
    return report


def ensure_repo(repo_dir) -> None:
    """Called by clean and smudge: set the repository up once. Never raises."""
    try:
        if _git(repo_dir, "config", "--get", "zippy.setup").stdout.strip() == SETUP_VERSION:
            return
        report = setup_repo(repo_dir)
        notes = [f"{k}: {v}" for k, v in report.items() if not v.startswith(("installed", "updated", "replaced", "0 "))]
        sys.stderr.write("[zippy] set up this repository (hooks, container fetch)"
                         + ("".join(f"\n[zippy]   {n}" for n in notes)) + "\n")
    except Exception as e:                                  # setup must never break a filter
        sys.stderr.write(f"[zippy] could not set up this repository: {e}; run 'git zippy install --local'\n")


def remove_repo(repo_dir) -> Dict[str, str]:
    result = {}
    hdir = hooks_dir(repo_dir)
    for name in HOOK_NAMES:
        path = hdir / name if hdir else None
        if path is not None and classify_hook(path) == "zippy":
            path.unlink()
            result[name] = "removed"
        else:
            result[name] = "not ours, left alone" if path is not None and path.exists() else "none"
    for remote in _git(repo_dir, "remote").stdout.split():
        spec = REFSPEC.format(ref=parts_container.REF, remote=remote)
        _git(repo_dir, "config", "--fixed-value", "--unset-all", f"remote.{remote}.fetch", spec)
    _git(repo_dir, "config", "--unset", "zippy.setup")
    result["refspecs"] = "removed"
    return result
