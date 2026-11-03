#!/usr/bin/env python3
"""
Smudge filter: turn a pointer back into the original document.

Reads the pointer (pointer_format.py), extracts the parts tree it names,
recompresses every entry with the one profile the pointer records and refuses
the result unless its SHA-256 matches the pointer's HASH.
"""
from __future__ import annotations
from pathlib import Path
import sys
import zlib
from typing import Dict, List, Tuple
import tempfile
import pygit2
import logging
import compression_profiles
import msword_compressor
import lfs_parts
import parts_container
import pointer_format
import preflate_fallback
import zippy_setup
import zip_layout
from utils.utils import calculate_sha256

# Smudge only writes zips (zip_layout.py); reading them is the clean filter's job.
METHOD_STORE = zip_layout.METHOD_STORE
METHOD_DEFLATE = zip_layout.METHOD_DEFLATE

log_path = Path.cwd() / "zippy_smudge.log"
logging.basicConfig(filename=log_path, level=logging.DEBUG, format="%(asctime)s %(levelname)s: %(message)s")

def _compress_raw_deflate(data: bytes, profile: Dict, flush_offsets: tuple = (),
                          break_kind: int = compression_profiles.BREAK_NONE) -> bytes:
    """
    Raw DEFLATE for one entry, per the given compression profile.

    `flush_offsets` means different things depending on `break_kind`: a full
    flush for Word's split parts, or a bare block break for packagers that cut
    blocks with Z_BLOCK. A profile that cannot honour the kind it is handed
    raises rather than quietly producing the wrong framing.
    """
    return compression_profiles.compress_entry(data, profile, break_kind, flush_offsets)

def _preflate_streams(input_dir: Path, entries: List[Dict]) -> Dict[int, bytes]:
    """Deflate streams rebuilt from fallback corrections, keyed by id(entry)."""
    todo = [e for e in entries if e['policy'].get('preflate') is not None
            and e['lfh']['method'] == METHOD_DEFLATE and not e['is_dir']]
    if not todo:
        return {}
    pairs = []
    for e in todo:
        src = input_dir / e['name']
        if not src.is_file():
            raise FileNotFoundError(f"Missing input file for entry: {e['name']}")
        pairs.append((src.read_bytes(), e['policy']['preflate']))
    streams = preflate_fallback.recreate(pairs)
    logging.info(f"Fallback rebuilt {len(streams)} deflated entries with preflate")
    return {id(e): s for e, s in zip(todo, streams)}


def build_docx_bytes(input_dir: Path, entries: List[Dict], profile: Dict,
                     archive_comment: bytes = b"") -> bytes:
    """
    Build the archive in memory from the extracted parts and the pointer's
    entry list (zip_layout.write_archive lays it out). Each deflated entry is
    compressed with `profile`, rebuilt from its preflate corrections (all of a
    document's in one helper call), or - raw=1 - copied from .zippy/raw/.
    """
    rebuilt = _preflate_streams(input_dir, entries)

    def part(ent):
        name, lfh, pol = ent['name'], ent['lfh'], ent['policy']
        if ent['is_dir']:
            return zip_layout.dir_data(lfh['method']), 0, 0
        src = input_dir / name
        if not src.is_file():
            raise FileNotFoundError(f'Missing input file for entry: {name}')
        raw = src.read_bytes()
        crc32 = zlib.crc32(raw) & 0xFFFFFFFF
        if lfh['method'] == METHOD_STORE:
            comp = raw
        elif lfh['method'] != METHOD_DEFLATE:
            raise ValueError(f'Unsupported method {lfh["method"]} for {name}')
        elif pol.get('raw'):
            stored = input_dir / zip_layout.RAW_DIR / name
            if not stored.is_file():
                raise FileNotFoundError(f'Missing raw bytes for entry: {name}')
            comp = stored.read_bytes()
        elif id(ent) in rebuilt:
            comp = rebuilt[id(ent)]
        else:
            comp = _compress_raw_deflate(raw, profile, pol.get('flush_offsets', ()),
                                         pol.get('break_kind', compression_profiles.BREAK_NONE))
        return comp, crc32, len(raw)

    return zip_layout.write_archive(entries, part, archive_comment)

def repo_from_cwd():
    """
    Find pyit2 repository on current path.
    """
    repo = pygit2.Repository(pygit2.discover_repository(Path.cwd()))
    logging.debug(f"Opened repo at {repo.path}")
    return repo

def extract_tree(repo, tree, path: Path, _pending=None):
    """
    Extract xml files from a git tree to a specified path.

    A blob that is an LFS pointer is a part kept in LFS (see lfs_parts.py). Those
    are collected while walking and resolved together at the end, so that the
    ones missing locally are fetched in one parallel batch rather than one at a
    time in tree order.
    """
    top = _pending is None
    pending = {} if top else _pending
    path.mkdir(parents=True, exist_ok=True)
    logging.debug(f"Extracting tree to {path}")
    for entry in tree:
        full_path = path / entry.name
        obj = repo[entry.id]
        if entry.filemode == pygit2.GIT_FILEMODE_TREE:
            extract_tree(repo, obj, full_path, pending)
        else:
            full_path.parent.mkdir(parents=True, exist_ok=True)
            data = obj.read_raw()
            ptr = lfs_parts.parse_pointer(data)
            if ptr is not None:
                pending.setdefault(ptr, []).append(full_path)
                continue
            full_path.write_bytes(data)
            logging.debug(f"Extracted file: {full_path}")
    if top and pending:
        contents = lfs_parts.resolve_all(repo, {oid: size for oid, size in pending})
        for (oid, _size), paths in pending.items():
            for p in paths:
                p.write_bytes(contents[oid])
                logging.debug(f"Extracted LFS part: {p} ({oid})")

def profile_for(profile_name):
    """
    The one profile this pointer is rebuilt with - no search.

    Every pointer names its profile; `fallback` means clean found none that
    reproduces the document. A name this version does not know is an error,
    not a reason to guess: the pointer was written by a newer extension.
    """
    if profile_name == pointer_format.ORIGINAL_PROFILE:
        return {"name": profile_name, "kind": "original"}
    if profile_name == pointer_format.FALLBACK_PROFILE:
        # Entries with preflate corrections are rebuilt from those; this zlib
        # profile only serves deflated entries the fallback could not model.
        logging.info("Pointer records the fallback: preflate corrections where present, "
                     f"otherwise {compression_profiles.describe(compression_profiles.FALLBACK)}")
        return compression_profiles.FALLBACK
    named = compression_profiles.BY_NAME.get(profile_name)
    if named is None:
        raise ValueError(f"pointer names compression profile {profile_name!r}, which this "
                         f"version of the extension does not know; update the extension")
    if named['kind'] == 'msword' and not msword_compressor.is_available():
        raise RuntimeError("pointer needs the msword profile, which needs a shared zlib "
                           "with deflateTune (Windows: zlib1.dll); none was found")
    logging.info(f"Pointer records profile {compression_profiles.describe(named)}")
    return named


def recompress_docx(input_dir: Path, entries: List[Dict], profile: Dict,
                    archive_comment: bytes = b"") -> Tuple[bytes, str, dict]:
    """
    Rebuild the archive once, with `profile`. Return (docx_bytes, profile_name,
    meta); the caller compares meta['sha'] with the committed hash.
    """
    docx_bytes = build_docx_bytes(input_dir, entries, profile, archive_comment)
    sha = calculate_sha256(docx_bytes)
    logging.info(f"Profile {profile['name']} SHA256={sha}")
    meta = {"profile": profile, "level": profile.get("level"),
            "memLevel": profile.get("memlevel"), "sha": sha}
    return docx_bytes, profile["name"], meta


def recreate_docx(repo, ptr: "pointer_format.Pointer", path: str = "<unknown>"):
    """
    Recreate the original document from the pointer.

    1) Load the parts tree the pointer names, BY OID.
    2) Extract it to a temp folder.
    3) Recompress to reproduce the original archive.

    Resolving by oid rather than by ref name is what makes checking out an older
    commit return that commit's document. A ref holds whichever version is
    newest, so resolving by name returns the latest parts for every revision -
    a wrong document, delivered without an error.
    """
    tree_oid, expected_hash = ptr.tree, ptr.hash
    logging.info(f"Creating document from parts tree {tree_oid} "
                 f"(pointer format {pointer_format.format_version(ptr.version)})")
    # Settle the profile first: an unknown or unavailable one fails here,
    # before any parts are extracted or images downloaded.
    profile_def = profile_for(ptr.profile)
    if ptr.fallback:
        # The corrections only mean something to the preflate-rs that made them.
        have = preflate_fallback.version()           # raises when the helper is missing
        if have != ptr.fallback:
            raise RuntimeError(f"pointer was written with {ptr.fallback} but the zippy-preflate "
                               f"helper here is {have}; build the matching helper")
    if tree_oid not in repo:
        # Typically a `git pull origin <branch>`, which does not fetch the
        # parts container: fetch it now rather than fail the checkout.
        if parts_container.fetch_for_tree(repo, tree_oid):
            repo = pygit2.Repository(repo.path)
    try:
        obj = repo[tree_oid]
    except (KeyError, ValueError) as e:
        raise LookupError(
            f"parts tree {tree_oid} is not in this repository ({e}), nor in the remote "
            f"parts container. Check 'git zippy env', then 'git fetch'; if that does "
            f"not help, it was never pushed.") from e

    if isinstance(obj, pygit2.Tree):
        tree = obj
    elif isinstance(obj, pygit2.Commit):
        tree = obj.tree
    else:
        raise TypeError(f"{tree_oid} is a {type(obj).__name__}, not a tree")

    # Extract git tree to a temp folder and recompress it:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        extract_tree(repo, tree, tmp_path)

        if profile_def["kind"] == "original":
            # Stored whole: nothing to rebuild, the hash check still applies.
            stored = tmp_path / zip_layout.ORIGINAL
            if not stored.is_file():
                raise FileNotFoundError(f"parts tree {tree_oid} has no {zip_layout.ORIGINAL}")
            docx_bytes, profile = stored.read_bytes(), profile_def["name"]
            meta = {"level": None, "memLevel": None, "sha": calculate_sha256(docx_bytes)}
        else:
            docx_bytes, profile, meta = recompress_docx(tmp_path, ptr.entries, profile_def,
                                                        ptr.archive.get('comment', b''))

        # Log outcome
        logging.info(f"Emit profile: {profile}, level={meta['level']}, memLevel={meta['memLevel']}, sha={meta['sha']}")

        # Refuse rather than emit. A rebuild that does not match the committed
        # hash is a different document, and writing it puts bytes on disk that
        # git believes are the committed ones - the worst failure available to a
        # version control tool. Raising here exits non-zero, and git then aborts
        # the checkout leaving no file at all, not a truncated one.
        if expected_hash and meta["sha"] != expected_hash:
            logging.error(f"Hash mismatch. Expected: {expected_hash}, Got: {meta['sha']} (profile={profile})")
            raise ValueError(
                f"rebuild does not match the committed hash (expected {expected_hash}, "
                f"got {meta['sha']}, profile={profile})")
        # Report the document by the name the user knows it by. The tree oid is
        # in the log for anyone who needs it; on a corpus run a screen of hashes
        # tells you nothing about which file just went past.
        logging.info(f"Smudged {path}: profile={profile}, tree={tree_oid}")
        # Debug printout to console; stderr because stdout carries the document.
        sys.stderr.write(f"[zippy smudge] {path}: profile={profile}\n")
        sys.stdout.buffer.write(docx_bytes)

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "<unknown>"
    logging.info(f"Smudging document: {path}")

    # Read as BYTES and decide on the raw prefix. Git applies this filter to
    # every path .gitattributes matches, which includes files committed BEFORE
    # the attribute existed - those blobs are whole documents, not pointers.
    # An earlier version of this read stdin in text mode and reassembled the
    # lines. Anything that is not one of our pointers must be copied through
    # byte for byte.
    data = sys.stdin.buffer.read()
    if not pointer_format.is_pointer(data):
        logging.info("Not a zippy pointer (%d bytes); passing through unchanged", len(data))
        sys.stdout.buffer.write(data)
        return

    try:
        ptr = pointer_format.parse(data.decode("utf-8"))
    except (pointer_format.PointerError, UnicodeDecodeError) as e:
        logging.error("Unreadable pointer for %s: %s", path, e)
        sys.stderr.write(f"smudge_filter.py: {path}: {e}\n")
        sys.exit(1)

    try:
        repo = repo_from_cwd()
        zippy_setup.ensure_repo(repo.workdir or Path.cwd())     # once per repository
        recreate_docx(repo, ptr, path)
    except Exception as e:
        logging.exception(f"Unhandled exception: {e}")
        # Fail loudly. Exiting 0 with nothing on stdout makes git write a 0-byte
        # document; exiting non-zero makes git abort the checkout and write no
        # file at all, which is the only honest outcome when the bytes we would
        # produce are not the bytes that were committed.
        sys.stderr.write(f"smudge_filter.py: failed to recreate {path}: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()