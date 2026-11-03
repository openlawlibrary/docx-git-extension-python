#!/usr/bin/env python3
"""
parts_container.py - one ref that keeps every document's parts tree reachable.

WHY

A pointer names its parts tree by oid (TREE line). Git only keeps, fetches and
pushes objects that a ref reaches, so something has to reach every parts tree
ever committed - with one ref, however many documents there are:

    refs/zippy/parts  ->  commit  ->  tree
                                      ab/
                                        cd/
                                          abcd1234...   (a parts tree)

Each parts tree sits at <first 2 hex>/<next 2 hex>/<its full oid>.

  * Fixed two levels (65,536 buckets): a tree's path depends only on its oid,
    so every clone and branch puts it in the same place. ~5 trees per bucket
    at 300k document versions, so adding one rewrites three small trees.
  * Keyed by the tree's own oid: the name is self-checking, identical part
    sets share one entry, and smudge needs no lookup - it resolves TREE by oid.
  * Append-only. Containers merge by union, which never conflicts: the same
    name always holds the same tree.

LIFECYCLE

  post-commit   adds the parts trees of the pointers the commit added or
                changed to the local container (one container commit).
  pre-push      before a branch goes out: makes sure every pointer in the
                pushed commits has its tree in the container, fetches the
                remote container, merges it in if it moved (union, never a
                conflict), and pushes the container. Only then does the branch
                go - so a remote never has a pointer without its tree. If the
                container cannot be pushed, the branch push is stopped.
  fetch         +refs/zippy/parts:refs/zippy-remotes/<remote>/parts (set up per
                repository by zippy_setup.py). Fetching never overwrites the
                local container; pre-push merges the two.

Objects fetched with the remote container stay reachable from the tracking
ref, so smudge finds trees committed elsewhere before any merge happens.

COMMANDS (through git zippy, see zippy_cli.py)

    git zippy verify [<rev>]      every pointer at <rev> has its tree
    git zippy sync [<remote>]     merge with and push to the remote
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import pygit2

import pointer_format

REF = "refs/zippy/parts"
TRACKING = "refs/zippy-remotes/{remote}/parts"
SYNC_ENV = "ZIPPY_PARTS_SYNC"         # set while the container itself is being pushed
MAX_POINTER_BYTES = 1 << 20          # a pointer is a few KB; never read assets to find out
PUSH_ATTEMPTS = 3
ZERO = re.compile(r"0+")
# What git says when the remote ref moved after we read it: worth another round.
RACE = re.compile(r"non-fast-forward|fetch first|stale info|cannot lock ref|failed to update ref")


def log(msg: str) -> None:
    sys.stderr.write(f"[zippy] {msg}\n")


def repo_from_cwd() -> pygit2.Repository:
    return pygit2.Repository(pygit2.discover_repository(str(Path.cwd())))


def key_path(oid: str) -> str:
    return f"{oid[:2]}/{oid[2:4]}/{oid}"


def tracking_ref(remote: str) -> str:
    # A push to a bare URL has no remote name; give it a stable, legal one.
    if not re.fullmatch(r"[A-Za-z0-9._-]+", remote):
        remote = "url-" + hashlib.sha1(remote.encode()).hexdigest()[:12]
    return TRACKING.format(remote=remote)


def _commit_at(repo, ref: str) -> Optional[pygit2.Commit]:
    try:
        return repo.references[ref].peel(pygit2.Commit)
    except (KeyError, ValueError):
        return None


def contains(tree: Optional[pygit2.Tree], oid: str) -> bool:
    return tree is not None and key_path(oid) in tree


def _signature(repo) -> pygit2.Signature:
    try:
        return repo.default_signature
    except (KeyError, pygit2.GitError):
        return pygit2.Signature("git-zippy", "git-zippy@localhost")


# --- building container trees ----------------------------------------------------

def with_trees(repo, base: Optional[pygit2.Tree], oids: Iterable[str]) -> Optional[pygit2.Oid]:
    """`base` plus every tree in `oids`; None when all of them are already there."""
    groups: Dict[str, Dict[str, List[str]]] = {}
    for oid in sorted(set(oids)):
        if not contains(base, oid):
            groups.setdefault(oid[:2], {}).setdefault(oid[2:4], []).append(oid)
    if not groups:
        return None

    def sub(tree, name):
        return repo[tree[name].id] if tree is not None and name in tree else None

    root = repo.TreeBuilder(base) if base is not None else repo.TreeBuilder()
    for ab, cds in groups.items():
        ab_tree = sub(base, ab)
        ab_b = repo.TreeBuilder(ab_tree) if ab_tree is not None else repo.TreeBuilder()
        for cd, leaves in cds.items():
            cd_tree = sub(ab_tree, cd)
            cd_b = repo.TreeBuilder(cd_tree) if cd_tree is not None else repo.TreeBuilder()
            for oid in leaves:
                cd_b.insert(oid, pygit2.Oid(hex=oid), pygit2.GIT_FILEMODE_TREE)
            ab_b.insert(cd, cd_b.write(), pygit2.GIT_FILEMODE_TREE)
        root.insert(ab, ab_b.write(), pygit2.GIT_FILEMODE_TREE)
    return root.write()


def union(repo, a: pygit2.Tree, b: pygit2.Tree, depth: int = 0) -> pygit2.Oid:
    """Every entry of both containers. Only differing buckets are visited."""
    if a.id == b.id:
        return a.id
    builder = repo.TreeBuilder(a)
    for entry in b:
        if entry.name not in a:
            builder.insert(entry.name, entry.id, entry.filemode)
            continue
        mine = a[entry.name]
        if mine.id == entry.id:
            continue
        if depth >= 2:
            # A leaf's name IS its oid, so two different trees under one name
            # can only mean a damaged container. Refuse rather than pick one.
            raise RuntimeError(f"container entry {entry.name} holds two different objects")
        builder.insert(entry.name, union(repo, repo[mine.id], repo[entry.id], depth + 1),
                       pygit2.GIT_FILEMODE_TREE)
    return builder.write()


def _set_ref(repo, oid) -> None:
    repo.references.create(REF, oid, force=True)


def _tracking_commits(repo) -> List[pygit2.Commit]:
    """Remote containers fetched into refs/zippy-remotes/*/parts, origin first."""
    refs = sorted((r for r in repo.references
                   if r.startswith("refs/zippy-remotes/") and r.endswith("/parts")),
                  key=lambda r: (r != tracking_ref("origin"), r))
    return [c for c in (_commit_at(repo, r) for r in refs) if c is not None]


def known(repo, oid: str) -> bool:
    """In the local container or in a fetched remote one."""
    c = _commit_at(repo, REF)
    return (c is not None and contains(c.tree, oid)) or \
        any(contains(t.tree, oid) for t in _tracking_commits(repo))


def add(repo, oids: Iterable[str], message: str) -> int:
    """Add parts trees to the local container; returns how many were new."""
    oids = list(oids)
    for oid in oids:
        try:
            obj = repo[oid]
        except (KeyError, ValueError):
            raise LookupError(f"parts tree {oid} is not in this repository")
        if obj.type != pygit2.GIT_OBJECT_TREE:
            raise TypeError(f"{oid} is a {obj.type_str}, not a parts tree")
    head = _commit_at(repo, REF)
    if head is None:
        # First container in this clone: build on the fetched remote one, so
        # the next push is a fast-forward rather than a merge of two histories.
        tracked = _tracking_commits(repo)
        head = tracked[0] if tracked else None
    base = head.tree if head is not None else None
    new_tree = with_trees(repo, base, oids)
    if new_tree is None:
        return 0
    n = sum(1 for o in set(oids) if not contains(base, o))
    sig = _signature(repo)
    commit = repo.create_commit(None, sig, sig, f"{message}\n", new_tree,
                                [head.id] if head is not None else [])
    _set_ref(repo, commit)
    return n


def fetch_for_tree(repo, oid: str) -> bool:
    """
    Fetch the remote containers when a parts tree is missing; True if it is
    there afterwards. `git pull origin master` names its refspec, so git skips
    the configured container refspec - smudge then lands here instead of
    failing. One fetch per remote that carries the container refspec (origin
    when none does).
    """
    remotes = []
    for remote in repo.remotes:
        if any(REF in spec for spec in remote.fetch_refspecs):
            remotes.append(remote.name)
    for name in remotes or ["origin"]:
        r = _git("fetch", "--quiet", "--no-tags", name, f"+{REF}:{tracking_ref(name)}", check=False)
        if r.returncode != 0:
            log(f"fetching {REF} from {name} failed: {r.stderr.strip()[:200]}")
        if oid in pygit2.Repository(repo.path):      # fresh handle: new packs
            log(f"parts tree {oid[:12]} fetched with the {name} container")
            return True
    return False


# --- finding pointers ----------------------------------------------------------------

def tree_of_pointer(data: bytes) -> Optional[str]:
    if len(data) > MAX_POINTER_BYTES or not pointer_format.is_pointer(data):
        return None
    for line in data.decode("utf-8", "replace").splitlines()[:8]:
        if line.startswith("TREE "):
            return line[5:].strip()
    return None


def pointers_in_commit(repo, commit: pygit2.Commit) -> List[Tuple[str, str]]:
    """(path, parts tree oid) for each pointer the commit adds or changes
    against its first parent (all of them for a root commit)."""
    if commit.parents:
        diff = repo.diff(commit.parents[0].tree, commit.tree)
    else:
        diff = commit.tree.diff_to_tree(swap=True)
    found = []
    for delta in diff.deltas:
        if delta.status_char() not in ("A", "M", "C", "R", "T"):
            continue
        f = delta.new_file
        if f.mode not in (pygit2.GIT_FILEMODE_BLOB, pygit2.GIT_FILEMODE_BLOB_EXECUTABLE):
            continue
        blob = repo[f.id]
        if blob.size > MAX_POINTER_BYTES:
            continue
        tree = tree_of_pointer(blob.data)
        if tree:
            found.append((f.path, tree))
    return found


def pointers_at(repo, tree: pygit2.Tree, prefix: str = "") -> Iterable[Tuple[str, str]]:
    """Every pointer in a whole tree (for verify)."""
    for entry in tree:
        path = prefix + entry.name
        if entry.type_str == "tree":
            yield from pointers_at(repo, repo[entry.id], path + "/")
        elif entry.type_str == "blob" and repo[entry.id].size <= MAX_POINTER_BYTES:
            t = tree_of_pointer(repo[entry.id].data)
            if t:
                yield path, t


# --- hooks ------------------------------------------------------------------------------

def post_commit() -> None:
    repo = repo_from_cwd()
    commit = repo.head.peel(pygit2.Commit)
    found = pointers_in_commit(repo, commit)
    if not found:
        return
    missing = [(p, t) for p, t in found if t not in repo]
    for p, t in missing:
        log(f"{p}: parts tree {t} is missing; the document was not cleaned in this "
            f"repository. Re-add it with 'git add --renormalize {p}'")
    n = add(repo, [t for p, t in found if t in repo],
            f"zippy parts: {commit.id} ({len(found)} document(s))")
    if n:
        log(f"{n} parts tree(s) added to {REF}")


def _git(*args, env=None, check=True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=check,
                          env={**os.environ, **(env or {})})


def _remote_container(remote: str) -> Optional[str]:
    out = _git("ls-remote", remote, REF).stdout.split()
    return out[0] if out else None


def sync(repo, remote: str) -> None:
    """Merge the remote container into the local one and push the result."""
    track = tracking_ref(remote)
    for attempt in range(1, PUSH_ATTEMPTS + 1):
        theirs = _remote_container(remote)
        if theirs and theirs not in repo:
            _git("fetch", "--quiet", "--no-tags", remote, f"+{REF}:{track}")
        elif theirs:
            repo.references.create(track, pygit2.Oid(hex=theirs), force=True)
        mine = _commit_at(repo, REF)
        if mine is None:
            if theirs:
                _set_ref(repo, pygit2.Oid(hex=theirs))
            return                                   # nothing of ours to publish
        if theirs:
            t = pygit2.Oid(hex=theirs)
            if t == mine.id or repo.descendant_of(t, mine.id):
                _set_ref(repo, t)                    # remote already has all of ours
                return
            if not repo.descendant_of(mine.id, t):
                merged = union(repo, mine.tree, repo[t].tree)
                sig = _signature(repo)
                c = repo.create_commit(None, sig, sig, "zippy parts: merge remote container\n",
                                       merged, [mine.id, t])
                _set_ref(repo, c)
                log(f"merged the remote container into {REF}")
        push = _git("push", "--quiet", remote, f"{REF}:{REF}", env={SYNC_ENV: "1"}, check=False)
        if push.returncode == 0:
            repo.references.create(track, repo.references[REF].target, force=True)
            return
        if not RACE.search(push.stderr):
            # Not someone else's push in between (LFS upload, permissions,
            # network): another round cannot fix it, so say exactly what failed.
            raise RuntimeError(f"pushing {REF} to {remote} failed, so the branch was not "
                               f"pushed either:\n{push.stderr.strip()}")
        log(f"the remote container moved while pushing (attempt {attempt}); merging again")
    raise RuntimeError(f"could not update {REF} on {remote} after {PUSH_ATTEMPTS} attempts; "
                       f"the branch was not pushed. Try again, or run "
                       f"'git zippy sync {remote}'")


def pre_push(remote: str, lines: Iterable[str]) -> None:
    """
    Runs before git sends the branch. `lines` is the hook's stdin:
    <local ref> <local oid> <remote ref> <remote oid> per pushed ref.
    """
    if os.environ.get(SYNC_ENV):
        return                                      # this is our own container push
    repo = repo_from_cwd()
    import zippy_setup                              # a remote added after setup gets its refspec
    zippy_setup.add_refspecs(repo.workdir or os.getcwd())
    tips, hide = [], []
    for line in lines:
        parts = line.split()
        if len(parts) != 4 or ZERO.fullmatch(parts[1]) or parts[2] == REF:
            continue                                # deletion, or the container itself
        tips.append(parts[1])
        if not ZERO.fullmatch(parts[3]) and parts[3] in repo:
            hide.append(parts[3])
    if tips:
        walker = repo.walk(pygit2.Oid(hex=tips[0]), pygit2.GIT_SORT_NONE)
        for t in tips[1:]:
            walker.push(pygit2.Oid(hex=t))
        for h in hide:
            walker.hide(pygit2.Oid(hex=h))
        for ref in repo.references:
            if ref.startswith(f"refs/remotes/{remote}/"):
                try:
                    walker.hide(repo.references[ref].peel(pygit2.Commit).id)
                except (ValueError, KeyError):
                    pass
        found: Dict[str, str] = {}
        for commit in walker:
            for path, tree in pointers_in_commit(repo, commit):
                found.setdefault(tree, path)
        missing = [(p, t) for t, p in found.items() if t not in repo]
        if missing:
            raise LookupError("not pushing: these pointers name parts trees this repository "
                              "does not have, so nobody could check them out: " +
                              ", ".join(f"{p} ({t[:12]})" for p, t in missing[:10]))
        # Trees committed here are already in by post-commit; trees that came
        # with a fetch are in the remote container, which sync merges below.
        # Anything else (hooks off, a commit made by plumbing) is added now.
        extra = [t for t in found if not known(repo, t)]
        n = add(repo, extra, f"zippy parts: before push to {remote}")
        if n:
            log(f"{n} parts tree(s) were missing from {REF} and have been added")
    sync(repo, remote)


# --- maintenance -------------------------------------------------------------------------

def verify(repo, rev: str = "HEAD") -> int:
    tree = repo.revparse_single(rev).peel(pygit2.Tree)
    containers = [c.tree for c in [_commit_at(repo, REF)] + _tracking_commits(repo) if c is not None]
    bad = 0
    total = 0
    for path, t in pointers_at(repo, tree):
        total += 1
        if t not in repo:
            print(f"MISSING OBJECT  {path}  {t}")
            bad += 1
        elif not any(contains(c, t) for c in containers):
            print(f"NOT IN CONTAINER  {path}  {t}")
            bad += 1
    print(f"{total} pointer(s) at {rev}: {total - bad} ok, {bad} problem(s)")
    return 1 if bad else 0
