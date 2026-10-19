#!/usr/bin/env python3
"""
Format of pointer-file:
    DOCX-POINTER <human-readable notice>      <- magic; identifies the file
    TREE:<oid of the git tree holding the unpacked parts>
    HASH:<sha256 of the original document>
    PROFILE:<compression profile name>        <- only when one was needed
    ENTRIES_BASE85 <b85> SHA256 <hex>

TREE is authoritative. The smudge filter resolves that oid directly and never
looks up a ref: a ref holds whichever version is newest, so resolving by name
hands back the wrong document for every commit except the latest.

There is deliberately no refname in here. It would only restate what the ref
naming already derives from the file's own path (see ref_names.py), and two
sources for one fact is how they drift apart.

The header lines before ENTRIES_BASE85 are parsed by key rather than position,
so a new field can be added without disturbing the readers of the old ones.

Where ENTRIES_BASE85 is a base85 of a compact binary table:
  Header:
    - magic: b"DM3\x00"
    - entry_count: u32
    - global_flags: u32  (bit0: zip64_present)
  Repeated per entry:
    - name_len: u16
    - name_bytes: name_len bytes  (as stored; UTF-8 if GPF_UTF8 else CP437)
    - is_dir: u8  (0/1)
    - lfh.version_needed: u16
    - lfh.flags: u16
    - lfh.method: u16
    - lfh.dos_time: u16
    - lfh.dos_date: u16
    - extra_lfh_len: u16
    - extra_lfh: extra_lfh_len bytes
    - cd.version_made_by: u16
    - cd.version_needed: u16
    - cd.internal_attr: u16
    - cd.external_attr: u32
    - extra_cd_len: u16
    - extra_cd: extra_cd_len bytes
    - comment_len: u16
    - comment: comment_len bytes
    - policy.use_data_descriptor: u8 (0/1)
    - policy.dd_has_signature:  u8 (0/1)

Notes:
- ZIP64 is not built; we error if sizes exceed ZIP32. Typical DOCX is fine.
- We store raw name bytes; for filesystem lookup we decode using GPF_UTF8 or CP437.
"""

from __future__ import annotations
from pathlib import Path
import struct
import sys
from typing import Dict, Iterable, List, Tuple
import sys
import tempfile
import zipfile
import pygit2
import logging
import zlib
import block_breaks
import compression_profiles
import msword_compressor
from utils.utils import (read_u16, read_u32, encode_b85, calculate_sha256, repo_from_cwd, calculate_file_sha256)

# === ZIP constants ===
SIG_LFH   = 0x04034B50
SIG_CFH   = 0x02014B50
SIG_EOCD  = 0x06054B50
SIG_DD    = 0x08074B50

GPF_ENCRYPTED       = 0x0001
GPF_DATA_DESCRIPTOR = 0x0008
GPF_UTF8            = 0x0800

METHOD_STORE = 0
METHOD_DEFLATE = 8
META_MAGIC_V3 = b"DM3\x00"   # no break list at all
META_MAGIC_V4 = b"DM4\x00"   # per-entry Z_FULL_FLUSH offsets (Word)
META_MAGIC = b"DM5\x00"      # per-entry (break kind, offsets)

# Always write the OLDEST magic that can express this document. A pointer whose
# bytes change for no reason makes git report every docx as modified the day a
# new field ships, so DM5 appears only when some entry actually needs it.

# The pointer's first line. POINTER_MAGIC identifies the file as ours; the
# smudge filter and the post-commit hook each repeat this one string rather
# than import it, so none of the three can break the others by being absent,
# edited or moved. It is a format constant - if it ever changes, it changes in
# the pointer format, and all three have to be revisited anyway.
POINTER_MAGIC = "DOCX-POINTER"
POINTER_NOTICE = ("placeholder - this repository stores documents unpacked; "
                  "run the docx extension's install step here, then "
                  "'git checkout -- .' to get the real file")

log_path = Path.cwd() / "docx_clean.log"
logging.basicConfig(filename=log_path, level=logging.DEBUG, format="%(asctime)s %(levelname)s: %(message)s")

def find_eocd(buf: bytes) -> Tuple[int, int, int, int]:
    """
    Locate EOCD (End Of Central Directory) by scanning backwards.
    Return Central Directory offset and Central Directory Size.
    """
    max_scan = min(len(buf), 65557)
    window = buf[len(buf)-max_scan:]
    for i in range(len(window) - 22, -1, -1):
        if read_u32(window, i) == SIG_EOCD:
            comment_len = read_u16(window, i + 20)
            if i + 22 + comment_len <= len(window):
                cd_size = read_u32(window, i + 12)
                cd_off  = read_u32(window, i + 16)
                return cd_off, cd_size
    raise ValueError('EOCD not found')


def iterate_cd_entries(buf: bytes, cd_off: int, cd_size: int) -> Iterable[Dict]:
    """
    Iterate through Central Directory entries.
    """
    p = cd_off
    end = cd_off + cd_size
    while p < end:
        if read_u32(buf, p) != SIG_CFH:
            raise ValueError(f'Invalid CFH signature at 0x{p:X}')
        version_made    = read_u16(buf, p+4)
        version_needed  = read_u16(buf, p+6)
        gpf             = read_u16(buf, p+8)
        method          = read_u16(buf, p+10)
        dos_time        = read_u16(buf, p+12)
        dos_date        = read_u16(buf, p+14)
        crc32           = read_u32(buf, p+16)
        comp_size       = read_u32(buf, p+20)
        uncomp_size     = read_u32(buf, p+24)
        name_len        = read_u16(buf, p+28)
        extra_len       = read_u16(buf, p+30)
        comment_len     = read_u16(buf, p+32)
        disk_start      = read_u16(buf, p+34)
        internal_attr   = read_u16(buf, p+36)
        external_attr   = read_u32(buf, p+38)
        lfh_rel_off     = read_u32(buf, p+42)
        p += 46
        name = buf[p:p+name_len]
        p += name_len
        extra = buf[p:p+extra_len]
        p += extra_len
        comment = buf[p:p+comment_len]
        p += comment_len
        try:
            name_str = name.decode('utf-8') if (gpf & GPF_UTF8) else name.decode('cp437')
        except Exception:
            name_str = name.decode('utf-8', 'replace')
        yield {
            'name': name_str,
            'name_raw': name,
            'gpf': gpf,
            'method': method,
            'dos_time': dos_time,
            'dos_date': dos_date,
            'crc32': crc32,
            'comp_size': comp_size,
            'uncomp_size': uncomp_size,
            'version_made': version_made,
            'version_needed': version_needed,
            'disk_start': disk_start,
            'internal_attr': internal_attr,
            'external_attr': external_attr,
            'lfh_rel_off': lfh_rel_off,
            'extra_raw': extra,
            'comment_raw': comment,
        }


def parse_lfh(buf: bytes, off: int) -> Dict:
    """
    Extract Local File Header bytes and parse them.
    """
    if read_u32(buf, off) != SIG_LFH:
        raise ValueError(f'Invalid LFH signature at 0x{off:X}')
    version_needed  = read_u16(buf, off+4)
    gpf             = read_u16(buf, off+6)
    method          = read_u16(buf, off+8)
    dos_time        = read_u16(buf, off+10)
    dos_date        = read_u16(buf, off+12)
    crc32           = read_u32(buf, off+14)
    comp_size       = read_u32(buf, off+18)
    uncomp_size     = read_u32(buf, off+22)
    name_len        = read_u16(buf, off+26)
    extra_len       = read_u16(buf, off+28)
    name = buf[off+30: off+30+name_len]
    extra = buf[off+30+name_len: off+30+name_len+extra_len]
    try:
        name_str = name.decode('utf-8') if (gpf & GPF_UTF8) else name.decode('cp437')
    except Exception:
        name_str = name.decode('utf-8', 'replace')
    return {
        'version_needed': version_needed,
        'gpf': gpf,
        'method': method,
        'dos_time': dos_time,
        'dos_date': dos_date,
        'crc32': crc32,
        'comp_size': comp_size,
        'uncomp_size': uncomp_size,
        'name_len': name_len,
        'extra_len': extra_len,
        'name_raw': name,
        'name': name_str,
        'extra_raw': extra,
        'data_off': off + 30 + name_len + extra_len,
        'lfh_off': off,
    }

def _collect_entries(buf: bytes, cd_off: int, cd_size: int) -> List[Dict]:
    """
    Parse every entry once, keeping both the metadata record and the bytes a
    codec search needs. Reading the archive twice would be wasteful on the large
    documents where the search matters most.
    """
    items: List[Dict] = []
    for c in iterate_cd_entries(buf, cd_off, cd_size):
        lfh = parse_lfh(buf, c['lfh_rel_off'])
        # data descriptor policy detection
        use_dd = 1 if (lfh['gpf'] & GPF_DATA_DESCRIPTOR) else 0
        comp_len = c['comp_size'] if lfh['comp_size'] == 0 else lfh['comp_size']
        dd_has_sig = 0
        if use_dd:
            data_end = lfh['data_off'] + comp_len
            if data_end + 4 <= len(buf) and read_u32(buf, data_end) == SIG_DD:
                dd_has_sig = 1
        name = c['name_raw']
        is_dir = 1 if name.endswith(b'/') else 0
        extra_lfh = lfh['extra_raw']
        extra_cd  = c['extra_raw']
        comment   = c['comment_raw']
        rec = [
            struct.pack('<H', len(name)), name,
            struct.pack('<B', is_dir),
            struct.pack('<HHHHH', lfh['version_needed'], lfh['gpf'], lfh['method'], lfh['dos_time'], lfh['dos_date']),
            struct.pack('<H', len(extra_lfh)), extra_lfh,
            struct.pack('<HHH', c['version_made'], c['version_needed'], c['internal_attr']),
            struct.pack('<I', c['external_attr']),
            struct.pack('<H', len(extra_cd)), extra_cd,
            struct.pack('<H', len(comment)), comment,
            struct.pack('<BB', use_dd, dd_has_sig),
        ]
        items.append({
            'name': c['name'],
            'rec': b''.join(rec),
            'method': lfh['method'],
            'is_dir': bool(is_dir),
            'comp': buf[lfh['data_off']:lfh['data_off'] + comp_len],
            'usize': c['uncomp_size'],
            'gpf': lfh['gpf'],
            'use_dd': use_dd,
            'dd_has_sig': dd_has_sig,
            'extra_lfh': extra_lfh,
            'extra_cd': extra_cd,
        })
    return items


def _flush_offsets(items: List[Dict]) -> List[Tuple[int, Tuple[int, ...]]]:
    """
    Word's Z_FULL_FLUSH positions, one list per entry.

    Each flush leaves an empty stored block behind, so if no stream anywhere in
    the archive contains an empty block, no entry can have flush offsets and the
    whole scan can be skipped. That check runs through libz and is ~300x faster
    than the Python bit-walker, which on a 17 MB document is 0.1s against 40s.
    """
    breaks: List[Tuple[int, Tuple[int, ...]]] = [
        (compression_profiles.BREAK_NONE, ())] * len(items)
    deflated = [i for i, it in enumerate(items)
                if it['method'] == METHOD_DEFLATE and not it['is_dir'] and it['comp']]
    if not deflated:
        return breaks

    if block_breaks.is_available():
        try:
            if not any(block_breaks.has_empty_blocks(items[i]['comp'], items[i]['usize'])
                       for i in deflated):
                logging.debug("No empty deflate blocks anywhere; skipping the flush scan")
                return breaks
        except Exception as e:
            logging.warning(f"empty-block pre-scan failed, falling back to full scan: {e}")

    for i in deflated:
        try:
            offs = tuple(msword_compressor.detect_flush_offsets(items[i]['comp']))
        except Exception as e:
            logging.warning(f"flush-offset scan failed for {items[i]['name']}: {e}")
            continue
        if offs:
            breaks[i] = (compression_profiles.BREAK_FULL, offs)
    return breaks


def _fit_block_breaks(items: List[Dict]):
    """
    Find a zlib profile plus per-entry block breaks that reproduces every
    deflated entry byte for byte. Returns (profile_name, breaks) or (None, None).

    Some packagers use stock zlib knobs but cut blocks early with Z_BLOCK, which
    leaves no marker in the stream. The LZ77 decisions are then plain zlib's, so
    no (level, memLevel, strategy) search can ever match the bytes - the only
    missing information is where the cuts were.

    Candidate profiles are tried closest-first by the size of their plain output
    against the original. That is only an ordering, never a filter: a profile
    that sorts badly still gets its turn, it just waits.
    """
    if not (block_breaks.is_available() and block_breaks.supports_z_block()):
        logging.debug("block-break fitting unavailable on this host; skipping")
        return None, None
    deflated = [i for i, it in enumerate(items)
                if it['method'] == METHOD_DEFLATE and not it['is_dir'] and it['comp']]
    if not deflated:
        return None, None

    raws: Dict[int, bytes] = {}
    for i in deflated:
        try:
            raws[i] = zlib.decompress(items[i]['comp'], -15)
        except Exception as e:
            logging.warning(f"cannot inflate {items[i]['name']}: {e}")
            return None, None

    # Probe on the largest entry: it discriminates best between near-neighbour
    # profiles, and a wrong profile is rejected there in a fraction of a second.
    probe = max(deflated, key=lambda i: len(items[i]['comp']))
    order = []
    for p in compression_profiles.ZLIB_PROFILES:
        try:
            plain = compression_profiles.compress_entry(raws[probe], p)
        except Exception:
            continue
        order.append((abs(len(plain) - len(items[probe]['comp'])), p))
    order.sort(key=lambda t: t[0])

    for _, profile in order:
        br = _fit_all(items, deflated, raws, profile, probe)
        if br is not None:
            return profile['name'], br
    logging.debug("no zlib profile reproduces this archive, with or without block breaks")
    return None, None


def _fit_all(items, deflated, raws, profile, probe):
    """Fit `profile` to the probe entry first, then to every entry. All or nothing."""
    level, ml = profile['level'], profile['memlevel']
    strat = profile.get('strategy', 0)

    def fit_one(i, rounds):
        comp = items[i]['comp']
        if compression_profiles.compress_entry(raws[i], profile) == comp:
            return (compression_profiles.BREAK_NONE, ())
        offs = block_breaks.fit_breaks(raws[i], comp, items[i]['usize'],
                                       level, ml, strat, rounds=rounds)
        if offs is None:
            return None
        return (compression_profiles.BREAK_BLOCK, tuple(offs))

    # The fitter rejects a wrong profile on its own, as soon as the agreeing
    # prefix stops growing, so the probe gets the full budget. Capping it lower
    # would reject a correct profile on a document with many breaks.
    if fit_one(probe, rounds=block_breaks.FIT_ROUNDS) is None:
        return None

    breaks = [(compression_profiles.BREAK_NONE, ())] * len(items)
    for i in deflated:
        got = fit_one(i, rounds=block_breaks.FIT_ROUNDS)
        if got is None:
            logging.debug(f"profile {profile['name']} fits the probe but not "
                          f"{items[i]['name']}; trying the next profile")
            return None
        breaks[i] = got
    return breaks


def _pack_entries(items: List[Dict], breaks) -> bytes:
    """
    Serialise the entry table, choosing the oldest magic that can carry it.

    DM3 has no break list, DM4 carries Word's flush offsets, DM5 carries a kind
    tag alongside them. Writing DM5 unconditionally would change the pointer of
    every already-committed document and make git report them all as modified,
    so the version only rises when a document actually needs it.
    """
    kinds = {k for k, offs in breaks if offs}
    if compression_profiles.BREAK_BLOCK in kinds:
        magic, version = META_MAGIC, 'DM5'
    elif compression_profiles.BREAK_FULL in kinds:
        magic, version = META_MAGIC_V4, 'DM4'
    else:
        magic, version = META_MAGIC_V3, 'DM3'

    for it, (kind, offs) in zip(items, breaks):
        logging.debug(
            f"entry {it['name']!r}: method={it['method']} dir={it['is_dir']} "
            f"gpf=0x{it['gpf']:04x} comp={len(it['comp'])} uncomp={it['usize']} "
            f"dd={it['use_dd']}/{it['dd_has_sig']} extra_lfh={len(it['extra_lfh'])} "
            f"extra_cd={len(it['extra_cd'])} "
            f"breaks={compression_profiles.BREAK_NAMES[kind]}:{offs or '-'}")

    n = sum(1 for _, offs in breaks if offs)
    logging.info(f"Packed {len(items)} entries, magic={version}, "
                 f"{n} entries carry block breaks")

    header = b''.join([magic, struct.pack('<I', len(items)), struct.pack('<I', 0)])
    body = []
    for it, (kind, offs) in zip(items, breaks):
        body.append(it['rec'])
        if version == 'DM5':
            body.append(struct.pack('<BB', kind, len(offs)))
            body.append(b''.join(struct.pack('<I', o) for o in offs))
        elif version == 'DM4':
            body.append(struct.pack('<B', len(offs)))
            body.append(b''.join(struct.pack('<I', o) for o in offs))
    return header + b''.join(body)

def dump_metadata(b: bytes) -> None:
    """
    Write xml metadata to a pointer file. Takes the document's bytes so it
    cannot disagree with the tree built from those same bytes.
    """
    cd_off, cd_size = find_eocd(b)
    logging.debug(f"EOCD: central directory at {cd_off}, {cd_size} bytes")
    items = _collect_entries(b, cd_off, cd_size)

    # Two producers, two mechanisms. Word splits a part into pieces and flushes
    # between them, leaving an empty block behind each time; other packagers cut
    # blocks with Z_BLOCK, which leaves nothing. Look for the visible one first,
    # because it is cheap to rule out and its absence is what makes the second
    # search worth running at all.
    breaks = _flush_offsets(items)
    profile_name = None
    if not any(offs for _, offs in breaks):
        profile_name, fitted = _fit_block_breaks(items)
        if fitted is not None:
            breaks = fitted
            if not any(offs for _, offs in breaks):
                # The profile reproduces the document as-is. Recording it would
                # change pointers that are currently correct, for no gain.
                profile_name = None
        else:
            profile_name = None

    entries_blob = _pack_entries(items, breaks)
    entries_b85 = encode_b85(entries_blob)
    entries_sha = calculate_sha256(entries_blob)
    logging.info(f"Entry table: {len(entries_blob)} bytes raw, {len(entries_b85)} base85, "
                 f"SHA256={entries_sha}")

    if profile_name:
        # Only written when the document needs block breaks, which are only
        # meaningful against the profile they were fitted to. Smudge reads this
        # by key, so older pointers without it still parse.
        logging.info(f"Recording compression profile: {profile_name}")
        sys.stdout.write(f'PROFILE:{profile_name}\n')
    sys.stdout.write(f'ENTRIES_BASE85 {entries_b85} SHA256 {entries_sha}\n')

def add_directory_to_tree(repo, base_path, tree_builder):
    """
    Create a git tree from a directory.
    """
    for entry in sorted(base_path.iterdir()):
        if entry.is_file():
            blob_oid = repo.create_blob(entry.read_bytes())
            tree_builder.insert(entry.name, blob_oid, pygit2.GIT_FILEMODE_BLOB)
        elif entry.is_dir():
            sub_builder = repo.TreeBuilder()
            add_directory_to_tree(repo, entry, sub_builder)
            subtree_oid = sub_builder.write()
            tree_builder.insert(entry.name, subtree_oid, pygit2.GIT_FILEMODE_TREE)

def save_docx_as_git_tree(repo, docx_bytes) -> pygit2.Oid:
    """
    Unzip a docx file and store its xml components in a git tree.
    Retruns git tree oid.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        docx_path = tmp_path / "file.docx"
        docx_path.write_bytes(docx_bytes)

        with zipfile.ZipFile(docx_path, "r") as zip_ref:
            names = zip_ref.namelist()
            zip_ref.extractall(tmp_path / "unzipped")
        logging.debug(f"Unpacked {len(names)} zip members: {', '.join(sorted(names))}")

        tree_builder = repo.TreeBuilder()
        add_directory_to_tree(repo, tmp_path / "unzipped", tree_builder)

        tree_oid = tree_builder.write()
        logging.info(f"Stored {len(names)} parts as tree {tree_oid}")
        return tree_oid

def main():
    logging.info("clean_filter.py started")
    if len(sys.argv) < 2:
        logging.error("No path argument; git passes one via %f in the filter definition.")
        sys.stderr.write("Usage: clean_filter.py <path_to_docx>\n")
        sys.exit(1)

    docx_path = Path(sys.argv[1])
    logging.info(f"Cleaning {docx_path} in {Path.cwd()}")

    # Everything below is derived from docx_bytes - the content git actually
    # handed us. Reading the path instead would let the tree and the entry table
    # come from different revisions whenever the worktree file is not what is
    # being cleaned (stash, checkout, re-add).
    docx_bytes = sys.stdin.buffer.read()
    logging.info(f"Read {len(docx_bytes)} bytes from stdin")
    if not docx_bytes:
        # An empty payload would otherwise be stored as a valid pointer to an
        # empty tree, which smudge cannot turn back into a document.
        logging.error(f"{docx_path}: git handed us 0 bytes; refusing to write a pointer")
        sys.stderr.write(f"clean_filter.py: {docx_path} is empty, refusing to clean\n")
        sys.exit(1)

    if docx_bytes[:len(POINTER_MAGIC)] == POINTER_MAGIC.encode():
        # The worktree holds a pointer rather than a document, so a checkout
        # wrote the stored bytes straight to disk - the smudge filter was not
        # configured, or it failed and filter.docx.required was not set.
        # Cleaning this would store a pointer to a pointer; the document is not
        # here to be stored. Say so, because the generic "not a zip file" sends
        # people to inspect a document that was never the problem.
        logging.error(f"{docx_path}: worktree file is a pointer, not a document")
        sys.stderr.write(
            f"clean_filter.py: {docx_path} contains pointer text, not a document."
            f"  A checkout wrote the pointer to disk, which means the smudge filter"
            f"  did not run.\nRestore the file with:\n"
            f"      rm -f {docx_path!s} && git checkout -- {docx_path!s}\n")
        sys.exit(1)

    repo = repo_from_cwd()
    tree_oid = save_docx_as_git_tree(repo, docx_bytes)
    docx_hash = calculate_sha256(docx_bytes)
    logging.info(f"Document SHA256={docx_hash}, parts tree {tree_oid}")

    # First line doubles as the magic the post-commit hook recognises and as a
    # message for whoever opens this file in a clone that has not run install.py
    # - without the filter configured, git writes these bytes into the worktree
    # under the document's own name, and a bare "DOCX-POINTER:" told them
    # nothing about what to do next.
    sys.stdout.write(f"{POINTER_MAGIC} {POINTER_NOTICE}\n")
    # The parts tree, named by content. Smudge resolves THIS, never a ref: a ref
    # always holds the newest version, so resolving by name silently returns the
    # wrong document for every commit but the latest.
    sys.stdout.write(f"TREE:{tree_oid}\n")
    sys.stdout.write(f"HASH:{docx_hash}\n")
    dump_metadata(docx_bytes)
    logging.info(f"Wrote pointer for {docx_path}: tree={tree_oid} hash={docx_hash}")

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        # Exit non-zero so git aborts instead of storing the half-written pointer
        # that is already on stdout. Staying silent here is how a document ends
        # up committed as an unreadable pointer.
        logging.exception(f"Unhandled exception: {e}")
        sys.stderr.write(f"clean_filter.py: failed to clean "
                         f"{sys.argv[1] if len(sys.argv) > 1 else '<no path>'}: {e}\n")
        sys.exit(1)