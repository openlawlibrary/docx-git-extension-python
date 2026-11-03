#!/usr/bin/env python3
"""
git zippy - store zip-based documents (.docx, .odt, .epub) unpacked in git.

`git zippy <command>` runs this through the `git-zippy` launcher next to it
(put that launcher on your PATH). Modelled on git-lfs:

    git zippy install [--local] [--python PATH] [--force]
        Configure the zippy filter: in ~/.gitconfig (default, once per machine)
        or in this repository only (--local). Inside a repository it also sets
        that repository up right away. Other repositories set themselves up
        the first time the filter runs in them - a plain `git clone` is enough.
    git zippy uninstall [--local]
        Remove the filter configuration (and, inside a repository, our hooks
        and the container fetch refspecs). Documents and refs are kept.
    git zippy track [PATTERN...] [--lfs | --lfs=EXT,EXT]
        Add or update the .gitattributes line for each pattern (see
        zippy_track.py); without patterns, list what is tracked.
    git zippy untrack PATTERN...
    git zippy env           What is configured, found and missing.
    git zippy version
    git zippy verify [REV]  Every pointer at REV (HEAD) has its parts tree.
    git zippy sync [REMOTE] Merge with and push the remote parts container.
    git zippy hook post-commit | pre-push REMOTE URL   (called by the hooks)

Documents opt in through .gitattributes, best written by `git zippy track`:

    *.docx filter=zippy merge=binary -text zippy-lfs=jpg,jpeg,png,emf
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

VERSION = "0.1.0"
EXT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EXT_DIR))


def _git(*args, cwd=None) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


def _repo_dir():
    out = _git("rev-parse", "--show-toplevel")
    return out.stdout.strip() if out.returncode == 0 and out.stdout.strip() else None


def _filter_cmd(python: str, script: str) -> str:
    # Quoted inside the value: git runs it through sh, and a path with a space
    # in it (C:\Users\Test user\...) would otherwise split into two arguments.
    return f'"{python}" "{EXT_DIR / script}" %f'


def install(args) -> int:
    local = "--local" in args
    force = "--force" in args
    python = args[args.index("--python") + 1] if "--python" in args else sys.executable
    repo = _repo_dir()
    if local and not repo:
        print("git zippy install --local: not inside a git repository", file=sys.stderr)
        return 1
    check = subprocess.run([python, "-c", "import pygit2"], capture_output=True)
    if check.returncode != 0:
        print(f"{python} cannot import pygit2; install it there or pass --python", file=sys.stderr)
        return 1
    scope = "--local" if local else "--global"
    for key, value in (("filter.zippy.clean", _filter_cmd(python, "clean_filter.py")),
                       ("filter.zippy.smudge", _filter_cmd(python, "smudge_filter.py")),
                       ("filter.zippy.required", "true"),
                       ("zippy.python", python)):
        _git("config", scope, key, value)
    print(f"git zippy {VERSION}: filter configured ({'this repository' if local else '~/.gitconfig'}), "
          f"python {python}")
    if repo:
        import zippy_setup
        report = zippy_setup.setup_repo(repo, force)
        for k, v in report.items():
            print(f"  {k}: {v}")
    _warn_missing()
    return 0


def uninstall(args) -> int:
    local = "--local" in args
    scope = "--local" if local else "--global"
    _git("config", scope, "--remove-section", "filter.zippy")
    _git("config", scope, "--unset", "zippy.python")
    print(f"filter configuration removed ({'this repository' if local else '~/.gitconfig'})")
    repo = _repo_dir()
    if repo:
        import zippy_setup
        for k, v in zippy_setup.remove_repo(repo).items():
            print(f"  {k}: {v}")
    print("documents, pointers and refs/zippy/parts are kept")
    return 0


def _warn_missing():
    import preflate_fallback
    if not preflate_fallback.is_available():
        print(f"  note: no zippy-preflate helper; parts no profile reproduces are stored as their "
              f"original compressed bytes (larger). Build it: {preflate_fallback.BUILD_HINT}")
    if not shutil.which("git-lfs"):
        print("  note: git-lfs not found; zippy-lfs images cannot be uploaded or downloaded")


def env(_args) -> int:
    import preflate_fallback
    print(f"git-zippy {VERSION}   extension {EXT_DIR}")
    print(f"python      {sys.executable}")
    try:
        import pygit2
        print(f"pygit2      {pygit2.__version__} (libgit2 {pygit2.LIBGIT2_VERSION})")
    except ImportError:
        print("pygit2      MISSING")
    try:
        print(f"fallback    {preflate_fallback.version()} at {preflate_fallback.helper_path()}")
    except preflate_fallback.PreflateUnavailable as e:
        print(f"fallback    MISSING ({e})")
    lfs = _git("lfs", "version")
    print(f"git-lfs     {lfs.stdout.strip() or 'MISSING'}")
    for scope in ("--global", "--local"):
        out = _git("config", scope, "--get-regexp", r"^(filter\.zippy\.|zippy\.)").stdout.strip()
        if out:
            print(f"config {scope[2:]}:")
            for line in out.splitlines():
                print(f"  {line}")
    repo = _repo_dir()
    if not repo:
        print("(not inside a repository)")
        return 0
    import zippy_setup, parts_container, zippy_track
    lines = zippy_track.zippy_lines(repo)
    if not lines:
        print("attributes  no filter=zippy pattern in .gitattributes (git zippy track \"*.docx\")")
    for pattern, line in lines:
        bad = zippy_track.problems(line)
        print(f"attributes  {pattern}: " + ("ok" if not bad else
              f"missing {' '.join(bad)} - fix with: git zippy track \"{pattern}\""))
    hdir = zippy_setup.hooks_dir(repo)
    for name in zippy_setup.HOOK_NAMES:
        state = zippy_setup.classify_hook(hdir / name) if hdir else "core.hooksPath is set"
        print(f"hook {name:<11} {state}")
    for remote in _git("remote", cwd=repo).stdout.split():
        specs = _git("config", "--get-all", f"remote.{remote}.fetch", cwd=repo).stdout.split()
        has = any(parts_container.REF in s for s in specs)
        print(f"fetch {remote:<10} {'container refspec present' if has else 'container refspec MISSING'}")
    for ref in (parts_container.REF,) + tuple(
            r for r in _git("for-each-ref", "--format=%(refname)", "refs/zippy-remotes/", cwd=repo).stdout.split()):
        n = _git("ls-tree", "-r", "-d", "--name-only", ref, cwd=repo)
        count = sum(1 for l in n.stdout.splitlines() if l.count("/") == 2) if n.returncode == 0 else None
        print(f"{ref:<36} {'absent' if count is None else f'{count} parts tree(s)'}")
    return 0


def track(args) -> int:
    import zippy_track
    repo = _repo_dir()
    if not repo:
        print("git zippy track: not inside a git repository", file=sys.stderr)
        return 1
    try:
        patterns, lfs = zippy_track.parse_args(args)
    except ValueError as e:
        print(f"git zippy track: {e}", file=sys.stderr)
        return 2
    if not patterns:
        lines = zippy_track.zippy_lines(repo)
        print("Tracked by git zippy:" if lines else "Nothing is tracked by git zippy (.gitattributes)")
        for pattern, line in lines:
            bad = zippy_track.problems(line)
            print(f"    {line.strip()}" + (f"    <- missing {' '.join(bad)}" if bad else ""))
        return 0
    for line in zippy_track.track(repo, patterns, lfs):
        print(line)
    return 0


def untrack(args) -> int:
    import zippy_track
    repo = _repo_dir()
    if not repo or not args:
        print("usage: git zippy untrack PATTERN...", file=sys.stderr)
        return 2
    for line in zippy_track.untrack(repo, args):
        print(line)
    return 0


def main(argv) -> int:
    cmd, args = (argv[1], argv[2:]) if len(argv) > 1 else ("", [])
    if cmd == "install":
        return install(args)
    if cmd == "uninstall":
        return uninstall(args)
    if cmd == "env":
        return env(args)
    if cmd == "track":
        return track(args)
    if cmd == "untrack":
        return untrack(args)
    if cmd in ("version", "--version"):
        print(f"git-zippy {VERSION}")
        return 0
    import parts_container
    try:
        if cmd == "verify":
            return parts_container.verify(parts_container.repo_from_cwd(), args[0] if args else "HEAD")
        if cmd == "sync":
            parts_container.sync(parts_container.repo_from_cwd(), args[0] if args else "origin")
            return 0
        if cmd == "hook" and args[:1] == ["post-commit"]:
            parts_container.post_commit()
            return 0
        if cmd == "hook" and args[:1] == ["pre-push"]:
            parts_container.pre_push(args[1] if len(args) > 1 else "origin", sys.stdin.read().splitlines())
            return 0
    except Exception as e:
        parts_container.log(f"error: {e}")
        return 1
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
