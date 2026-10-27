#!/usr/bin/env python3
"""
lfs_parts.py - keep selected document parts (images) in Git LFS.

The clean filter writes a document's parts straight into the object database
with create_blob; they never pass through the index, so .gitattributes and the
lfs filter never see them. This module does the two halves of LFS's job for
those parts itself, and leaves only the network to git-lfs:

  clean  - a part chosen for LFS is written to the local LFS store under its
           sha256, and the parts tree gets the three-line LFS pointer in its
           place. No process is started; the pointer format and the store
           layout are the same ones `git lfs clean` produces.
  smudge - a pointer found in a parts tree is read back from the local store,
           and only an object that is not there is fetched, by `git lfs smudge`.
           That is the one place git-lfs runs, so its endpoint, credentials and
           transfer settings (.lfsconfig, credential helper) apply unchanged.
  push   - nothing here. `git lfs pre-push` already scans every commit being
           pushed - refs/docx/* included - for pointer blobs by content and
           uploads what the server lacks.

WHICH PARTS

Opt-in, per document path, through a git attribute on the document:

    *.docx filter=docx docx-lfs=jpg,jpeg

The value is a comma-separated list of part extensions; a bare `docx-lfs`
means jpg,jpeg. Unspecified means no part goes to LFS, which is exactly the
behaviour before this module existed, so documents that do not opt in keep
the pointers they already have.

An attribute rather than local config because it changes what gets committed:
two clones configured differently would produce different parts trees for the
same document and report it as modified forever. .gitattributes travels with
the repository; config does not.

ONE INVARIANT

The smudge side resolves every blob in a parts tree that parses as an LFS
pointer, without asking which parts were meant to be in LFS - the attribute
may have changed since the commit. That is only safe if no part ever stored
raw looks like a pointer, so the clean side guarantees it: a part whose own
bytes happen to parse as an LFS pointer is stored in LFS too, whatever the
attribute says.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Optional, Set

POINTER_VERSION = b"version https://git-lfs.github.com/spec/v1\n"
# git-lfs never treats anything larger than this as a pointer.
MAX_POINTER_SIZE = 1024

ATTRIBUTE = "docx-lfs"
DEFAULT_EXTENSIONS = frozenset({"jpg", "jpeg"})

_OID_RE = re.compile(rb"^oid sha256:([0-9a-f]{64})$")
_SIZE_RE = re.compile(rb"^size (\d+)$")

# Downloads are network-bound, one process each; this many run at once.
FETCH_WORKERS = 8


# --- pointer format -------------------------------------------------------

def make_pointer(oid: str, size: int) -> bytes:
    """The canonical pointer, byte for byte what `git lfs clean` emits."""
    return POINTER_VERSION + f"oid sha256:{oid}\nsize {size}\n".encode("ascii")


def parse_pointer(data: bytes) -> Optional[tuple]:
    """(oid, size) when `data` is an LFS pointer, else None."""
    if len(data) > MAX_POINTER_SIZE or not data.startswith(POINTER_VERSION):
        return None
    oid = size = None
    for line in data[len(POINTER_VERSION):].splitlines():
        m = _OID_RE.match(line)
        if m:
            oid = m.group(1).decode("ascii")
            continue
        m = _SIZE_RE.match(line)
        if m:
            size = int(m.group(1))
    if oid is None or size is None:
        return None
    return oid, size


# --- local store ----------------------------------------------------------

def _common_dir(repo) -> Path:
    """The shared git dir. A linked worktree's repo.path is .git/worktrees/x,
    but its LFS store, like its objects, lives in the main .git."""
    gitdir = Path(repo.path)
    commondir = gitdir / "commondir"
    if commondir.is_file():
        return (gitdir / commondir.read_text().strip()).resolve()
    return gitdir


def lfs_dir(repo) -> Path:
    """Where git-lfs keeps objects for this repository (honours lfs.storage)."""
    common = _common_dir(repo)
    try:
        storage = repo.config["lfs.storage"]
    except KeyError:
        storage = None
    if storage:
        p = Path(storage).expanduser()
        return p if p.is_absolute() else common / p
    return common / "lfs"


def object_path(repo, oid: str) -> Path:
    return lfs_dir(repo) / "objects" / oid[0:2] / oid[2:4] / oid


def store(repo, data: bytes) -> bytes:
    """Put `data` in the local LFS store and return its pointer."""
    oid = hashlib.sha256(data).hexdigest()
    dest = object_path(repo, oid)
    if not (dest.is_file() and dest.stat().st_size == len(data)):
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmpdir = lfs_dir(repo) / "tmp"
        tmpdir.mkdir(parents=True, exist_ok=True)
        # Write then rename, so a concurrent reader never sees half an object.
        fd, tmp = tempfile.mkstemp(dir=tmpdir)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.replace(tmp, dest)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        logging.debug(f"LFS: stored {oid} ({len(data)} bytes)")
    return make_pointer(oid, len(data))


# --- clean side -------------------------------------------------------------

def extensions_for(repo, doc_path: str) -> Set[str]:
    """Part extensions this document sends to LFS, from its docx-lfs attribute."""
    try:
        value = repo.get_attr(doc_path, ATTRIBUTE)
    except Exception as e:
        logging.warning(f"LFS: cannot read attribute {ATTRIBUTE} for {doc_path}: {e}")
        return set()
    if value is True:
        return set(DEFAULT_EXTENSIONS)
    if not value:  # None (unspecified) or False (-docx-lfs)
        return set()
    return {e.strip().lower().lstrip(".") for e in str(value).split(",") if e.strip()}


def blob_for_part(repo, part_name: str, data: bytes, extensions: Set[str]) -> bytes:
    """The bytes to store in the parts tree for one part: the part itself, or
    an LFS pointer to it."""
    if not data:
        # git-lfs stores an empty file as an empty blob, never as a pointer.
        return data
    ext = part_name.rsplit(".", 1)[-1].lower() if "." in part_name else ""
    if ext in extensions:
        return store(repo, data)
    if parse_pointer(data) is not None:
        # See ONE INVARIANT in the module docstring.
        logging.warning(f"LFS: part {part_name} looks like an LFS pointer; "
                        f"storing it in LFS so smudge cannot misread it")
        return store(repo, data)
    return data


# --- smudge side ------------------------------------------------------------

def _read_local(repo, oid: str, size: int) -> Optional[bytes]:
    p = object_path(repo, oid)
    if not p.is_file() or p.stat().st_size != size:
        return None
    data = p.read_bytes()
    if hashlib.sha256(data).hexdigest() != oid:
        logging.warning(f"LFS: local object {oid} is corrupt; fetching it again")
        return None
    return data


def _fetch(repo, oid: str, size: int) -> bytes:
    """One object through `git lfs smudge`, which downloads it, verifies it
    and adds it to the local store."""
    workdir = repo.workdir or str(_common_dir(repo))
    proc = subprocess.run(["git", "lfs", "smudge"], input=make_pointer(oid, size),
                          capture_output=True, cwd=workdir)
    if proc.returncode != 0:
        raise RuntimeError(f"git lfs smudge failed for {oid}: "
                           f"{proc.stderr.decode('utf-8', 'replace').strip()}")
    data = proc.stdout
    if hashlib.sha256(data).hexdigest() != oid:
        hint = (" (GIT_LFS_SKIP_SMUDGE is set, so git-lfs returned the pointer "
                "instead of the content)") if os.environ.get("GIT_LFS_SKIP_SMUDGE") else ""
        raise RuntimeError(f"LFS object {oid} could not be fetched{hint}")
    return data


def resolve_all(repo, wanted: Dict[str, int]) -> Dict[str, bytes]:
    """
    Content for every oid in `wanted` ({oid: size}). Local objects are read
    directly; only the missing ones go to the network, several at a time.
    """
    out: Dict[str, bytes] = {}
    missing = {}
    for oid, size in wanted.items():
        data = _read_local(repo, oid, size)
        if data is None:
            missing[oid] = size
        else:
            out[oid] = data
    if missing:
        logging.info(f"LFS: {len(out)} parts local, fetching {len(missing)}")
        with concurrent.futures.ThreadPoolExecutor(FETCH_WORKERS) as pool:
            futures = {pool.submit(_fetch, repo, oid, size): oid
                       for oid, size in missing.items()}
            for fut in concurrent.futures.as_completed(futures):
                out[futures[fut]] = fut.result()
    elif wanted:
        logging.info(f"LFS: all {len(out)} parts local")
    return out
