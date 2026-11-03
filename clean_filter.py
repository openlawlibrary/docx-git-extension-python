#!/usr/bin/env python3
"""
Clean filter: store a document as a git tree of its unpacked parts, and hand
git a small text pointer in its place.

The pointer format (VERSION, TREE, HASH, PROFILE, DEFAULTS, ENTRY lines) is
defined and documented in pointer_format.py, which the smudge filter reads with
the same code. TREE is authoritative: smudge resolves that oid directly and
never looks up a ref, because a ref holds whichever version is newest.

There is deliberately no refname in the pointer. It would only restate what the
ref naming already derives from the file's own path, and two sources for one
fact is how they drift apart.

Notes:
- ZIP64 is not built; we error if sizes exceed ZIP32. Typical DOCX is fine.
- Entry names are kept as stored bytes; for filesystem lookup they are decoded
  using GPF_UTF8 or CP437.
"""

from __future__ import annotations
import io
from pathlib import Path
import shutil
import sys
from typing import Dict, Iterable, List, Tuple
import tempfile
import zipfile
import pygit2
import logging
import zlib
import block_breaks
import compression_profiles
import msword_compressor
import lfs_parts
import pointer_format
import preflate_fallback
import zippy_setup
import zip_layout
from utils.utils import (read_u16, read_u32, calculate_sha256, repo_from_cwd)

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
# The pointer's first line. Defined in pointer_format, which smudge shares;
# the post-commit hook repeats the prefix because it must stay self-contained.
POINTER_MAGIC = pointer_format.POINTER_MAGIC

log_path = Path.cwd() / "zippy_clean.log"
logging.basicConfig(filename=log_path, level=logging.DEBUG, format="%(asctime)s %(levelname)s: %(message)s")

def _eocd_offset(buf: bytes) -> int:
    """Offset of the EOCD (End Of Central Directory) record, found by scanning backwards."""
    start = len(buf) - min(len(buf), 65557)
    for i in range(len(buf) - 22, start - 1, -1):
        if read_u32(buf, i) == SIG_EOCD and i + 22 + read_u16(buf, i + 20) <= len(buf):
            return i
    raise ValueError('EOCD not found')


def find_eocd(buf: bytes) -> Tuple[int, int]:
    """Central Directory offset and size, from the EOCD record."""
    i = _eocd_offset(buf)
    return read_u32(buf, i + 16), read_u32(buf, i + 12)


def archive_comment(buf: bytes) -> bytes:
    """The zip's own comment, stored in the EOCD record (usually empty)."""
    i = _eocd_offset(buf)
    return buf[i + 22:i + 22 + read_u16(buf, i + 20)]


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
        is_dir = name.endswith(b'/')
        extra_lfh = lfh['extra_raw']
        extra_cd  = c['extra_raw']
        # What the pointer records for this entry, in the structure
        # pointer_format writes and smudge rebuilds from.
        entry = {
            'name': c['name'],
            'name_raw': name,
            'is_dir': is_dir,
            'lfh': {'version_needed': lfh['version_needed'], 'flags': lfh['gpf'],
                    'method': lfh['method'], 'dos_time': lfh['dos_time'],
                    'dos_date': lfh['dos_date'], 'extra_lfh': extra_lfh},
            'cd': {'version_made_by': c['version_made'], 'version_needed': c['version_needed'],
                   'dos_time': c['dos_time'], 'dos_date': c['dos_date'],
                   'internal_attr': c['internal_attr'], 'external_attr': c['external_attr'],
                   'extra_cd': extra_cd, 'comment': c['comment_raw']},
            'policy': {'use_data_descriptor': bool(use_dd), 'dd_has_signature': bool(dd_has_sig),
                       'flush_offsets': (), 'break_kind': compression_profiles.BREAK_NONE,
                       'preflate': None},
        }
        items.append({
            'name': c['name'],
            'entry': entry,
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


def _choose_profile(items: List[Dict]):
    """
    Pick the one profile that reproduces every deflated entry, and the
    per-entry breaks it needs. Returns (profile_name, breaks), or (None, no
    breaks) when no profile does - the pointer then records `PROFILE fallback`,
    and smudge uses the fallback compression.

    Early exit everywhere a wrong answer can be recognised:
      * every comparison against the original streams the compressor's output
        and stops at the first block that differs;
      * a candidate is dropped at the first entry it cannot reproduce, and the
        largest entry is tried first because it tells candidates apart best;
      * empty blocks are read with libz in one pass per entry: Word's flush
        offsets come from that pass, and any empty block rules out the plain
        zlib profiles without compressing anything;
      * the break fitter resumes from its last confirmed break and stops each
        round at the first difference.
    """
    none = [(compression_profiles.BREAK_NONE, ())] * len(items)
    deflated = [i for i, it in enumerate(items)
                if it['method'] == METHOD_DEFLATE and not it['is_dir'] and it['comp']]
    if not deflated:
        # Nothing is compressed, so every profile rebuilds it; record the first.
        return compression_profiles.PROFILES[0]['name'], none
    deflated.sort(key=lambda i: -len(items[i]['comp']))     # probe = largest
    probe = deflated[0]

    raws: Dict[int, bytes] = {}
    for i in deflated:
        try:
            raws[i] = zlib.decompress(items[i]['comp'], -15)
        except Exception as e:
            logging.warning(f"cannot inflate {items[i]['name']}: {e}")
            return None, none

    can_scan = block_breaks.is_available()
    empty: Dict[int, bool] = {}
    flushes: Dict[int, Tuple[int, ...]] = {}
    for i in deflated:
        if can_scan:
            try:
                empty[i], flushes[i] = block_breaks.empty_blocks(items[i]['comp'], items[i]['usize'])
                continue
            except Exception as e:
                logging.warning(f"block scan failed for {items[i]['name']}: {e}")
        empty[i], flushes[i] = False, ()

    candidates = []
    # Word ends every part with a flush, so it is only a candidate when every
    # deflated entry has an empty block - and then it is the likely one.
    if all(empty[i] for i in deflated) and msword_compressor.is_available():
        candidates.append(compression_profiles.BY_NAME['msword'])
    # A plain zlib profile never writes an empty block: any entry that has one
    # rules all of them out. Otherwise try them in order of how much of the
    # largest entry each reproduces before it first differs (an early-exit
    # comparison, typically a block or two of work per candidate).
    if not any(empty[i] for i in deflated):
        ranked = []
        for p in compression_profiles.ZLIB_PROFILES:
            n = block_breaks.matching_prefix(
                compression_profiles.iter_compress_entry(raws[probe], p), items[probe]['comp'])
            ranked.append((-n, len(ranked), p))
        candidates += [p for _, _, p in sorted(ranked, key=lambda t: t[:2])]

    for profile in candidates:
        breaks = _fit_profile(items, deflated, raws, flushes, profile, can_scan)
        if breaks is not None:
            logging.info(f"Profile {profile['name']} reproduces every deflated entry")
            return profile['name'], breaks
        logging.debug(f"Profile {profile['name']} rejected")
    logging.warning("No profile reproduces this document; the pointer records "
                    "PROFILE fallback and checkout will use the fallback compression")
    return None, none


def _fit_profile(items, deflated, raws, flushes, profile, can_scan):
    """Per-entry breaks for `profile`, or None at the first entry it can't reproduce."""
    breaks = [(compression_profiles.BREAK_NONE, ())] * len(items)
    for i in deflated:                       # largest first: wrong candidates fail fast
        raw, comp = raws[i], items[i]['comp']
        if profile['kind'] == 'msword':
            kind = compression_profiles.BREAK_FULL if flushes[i] else compression_profiles.BREAK_NONE
            if not compression_profiles.entry_matches(raw, comp, profile, kind, flushes[i]):
                return None
            breaks[i] = (kind, flushes[i])
            continue
        if compression_profiles.entry_matches(raw, comp, profile):
            continue
        if not (can_scan and block_breaks.supports_z_block()):
            return None
        offs = block_breaks.fit_breaks(raw, comp, items[i]['usize'], profile['level'],
                                       profile['memlevel'], profile.get('strategy', 0))
        if offs is None:
            return None
        breaks[i] = (compression_profiles.BREAK_BLOCK, tuple(offs))
    return breaks


def _preflate_corrections(items: List[Dict]):
    """
    The fallback: preflate-rs corrections for every deflated entry, as
    (fallback tool/version or None, {item index: corrections}, {item index:
    why it has none}). The helper verifies each one by rebuilding the stream,
    so what is recorded does rebuild. Entries without corrections - preflate
    cannot model them, or there is no helper here - are stored raw instead.
    """
    deflated = [i for i, it in enumerate(items)
                if it['method'] == METHOD_DEFLATE and not it['is_dir'] and it['comp']]
    if not deflated:
        return None, {}, {}
    try:
        tool = preflate_fallback.version()
    except preflate_fallback.PreflateUnavailable as e:
        logging.warning(f"fallback unavailable: {e}")
        return None, {}, {i: f"no zippy-preflate helper here ({e})" for i in deflated}
    results = preflate_fallback.split([items[i]['comp'] for i in deflated])
    corrections, failed = {}, {}
    for i, (corr, why) in zip(deflated, results):
        if corr is None:
            failed[i] = f"preflate cannot model it: {why}"
            logging.warning(f"preflate cannot model {items[i]['name']}: {why}")
        else:
            corrections[i] = corr
    logging.info(f"Fallback {tool}: {len(corrections)} of {len(deflated)} deflated entries, "
                 f"{sum(map(len, corrections.values()))} bytes of corrections")
    return tool, corrections, failed


def pointer_entries(items: List[Dict], breaks, corrections=None, raw=()) -> List[Dict]:
    """The pointer's entry list: each entry with its breaks, fallback corrections or raw flag."""
    corrections = corrections or {}
    out = []
    for i, (it, (kind, offs)) in enumerate(zip(items, breaks)):
        e = dict(it['entry'])
        e['policy'] = dict(e['policy'], flush_offsets=tuple(offs),
                           break_kind=kind if offs else compression_profiles.BREAK_NONE,
                           preflate=corrections.get(i), raw=i in raw)
        logging.debug(
            f"entry {it['name']!r}: method={it['method']} dir={it['is_dir']} "
            f"gpf=0x{it['gpf']:04x} comp={len(it['comp'])} uncomp={it['usize']} "
            f"dd={it['use_dd']}/{it['dd_has_sig']} extra_lfh={len(it['extra_lfh'])} "
            f"extra_cd={len(it['extra_cd'])} "
            f"breaks={compression_profiles.BREAK_NAMES[kind]}:{offs or '-'}")
        out.append(e)
    return out


def _check_container(buf: bytes, items: List[Dict], parts_dir: Path, comment: bytes):
    """
    None when smudge's zip writer, given the original compressed bytes, writes
    exactly `buf`; otherwise why not. No compression - one pass over the bytes.
    """
    by_id = {id(it['entry']): it for it in items}

    def part(entry):
        it = by_id[id(entry)]
        if it['is_dir']:
            return zip_layout.dir_data(it['method']), 0, 0
        data = (parts_dir / entry['name']).read_bytes()
        return (data if it['method'] == METHOD_STORE else it['comp'],
                zlib.crc32(data) & 0xFFFFFFFF, len(data))
    try:
        rebuilt = zip_layout.write_archive([it['entry'] for it in items], part, comment)
    except Exception as e:
        return f"its zip layout cannot be written back ({e})"
    if rebuilt != buf:
        off = zip_layout.first_difference(rebuilt, buf)
        return (f"its zip layout differs from what the pointer can describe "
                f"(first difference at byte {off} of {len(buf)})")
    return None


def plan_document(buf: bytes, parts_dir: Path) -> Dict:
    """
    Unpack `buf` into `parts_dir` and decide how the document is stored:
    mode 'pointer' (profile or fallback, some entries possibly raw) or mode
    'original' (stored whole), with the reason.
    """
    def original(reason):
        return {'mode': 'original', 'reason': reason}
    try:
        cd_off, cd_size = find_eocd(buf)
        items = _collect_entries(buf, cd_off, cd_size)
        with zipfile.ZipFile(io.BytesIO(buf)) as z:
            z.extractall(parts_dir)
    except Exception as e:
        return original(f"it is not a zip this extension can read ({e})")
    if not items:
        return original("it has no zip entries")
    for it in items:
        if not zip_layout.safe_name(it['name']):
            return original(f"entry name {it['name']!r} cannot be stored as a part")
        if it['method'] not in (METHOD_STORE, METHOD_DEFLATE):
            return original(f"entry {it['name']!r} uses compression method {it['method']}")
        if it['gpf'] & GPF_ENCRYPTED:
            return original(f"entry {it['name']!r} is encrypted")
    comment = archive_comment(buf)
    why = _check_container(buf, items, parts_dir, comment)
    if why:
        return original(why)

    profile_name, breaks = _choose_profile(items)
    # A deflated entry with no compressed bytes at all is not a deflate stream
    # anything can reproduce; keep its (empty) bytes.
    raw = {i: "it has no deflate data" for i, it in enumerate(items)
           if it['method'] == METHOD_DEFLATE and not it['is_dir'] and not it['comp']}
    fallback, corrections = None, {}
    if profile_name:
        logging.info(f"Recording compression profile: {profile_name}")
    else:
        profile_name = pointer_format.FALLBACK_PROFILE
        fallback, corrections, failed = _preflate_corrections(items)
        raw.update(failed)
    return {'mode': 'pointer', 'items': items, 'profile': profile_name, 'breaks': breaks,
            'fallback': fallback if corrections else None, 'corrections': corrections,
            'raw': raw, 'comment': comment}


def add_directory_to_tree(repo, base_path, tree_builder, lfs_extensions=frozenset(), rel=""):
    """
    Create a git tree from a directory.

    Parts whose extension is in `lfs_extensions` go to the local LFS store and
    the tree holds their LFS pointer instead; see lfs_parts.py. So does a whole
    document stored at .zippy/original when the document uses LFS at all.
    """
    for entry in sorted(base_path.iterdir()):
        path = f"{rel}{entry.name}"
        if entry.is_file():
            data = entry.read_bytes()
            if path == zip_layout.ORIGINAL and lfs_extensions and data:
                data = lfs_parts.store(repo, data)
            else:
                data = lfs_parts.blob_for_part(repo, entry.name, data, lfs_extensions)
            blob_oid = repo.create_blob(data)
            tree_builder.insert(entry.name, blob_oid, pygit2.GIT_FILEMODE_BLOB)
        elif entry.is_dir():
            sub_builder = repo.TreeBuilder()
            add_directory_to_tree(repo, entry, sub_builder, lfs_extensions, path + "/")
            subtree_oid = sub_builder.write()
            tree_builder.insert(entry.name, subtree_oid, pygit2.GIT_FILEMODE_TREE)


def store_document(repo, buf: bytes, doc_hash: str, lfs_extensions=frozenset(),
                   display: str = "document") -> Tuple[str, str]:
    """
    Store the document's parts as a git tree and return (tree oid, pointer).
    Built completely before anything reaches stdout.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        parts_dir = Path(tmpdir) / "parts"
        parts_dir.mkdir()
        plan = plan_document(buf, parts_dir)
        if plan['mode'] == 'original':
            logging.warning(f"{display}: stored whole: {plan['reason']}")
            sys.stderr.write(f"[zippy] {display}: stored whole, not unpacked for rebuilding, "
                             f"because {plan['reason']}\n")
            if (parts_dir / zip_layout.RESERVED).exists():
                # The document has parts of its own under .zippy/: keep only the original.
                shutil.rmtree(parts_dir)
                parts_dir.mkdir()
            target = parts_dir / zip_layout.ORIGINAL
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(buf)
        else:
            items = plan['items']
            for i in plan['raw']:
                target = parts_dir / zip_layout.RAW_DIR / items[i]['name']
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(items[i]['comp'])
            if plan['raw']:
                size = sum(len(items[i]['comp']) for i in plan['raw'])
                reasons = sorted(set(plan['raw'].values()))
                sys.stderr.write(f"[zippy] {display}: {len(plan['raw'])} part(s) stored as their "
                                 f"original compressed bytes ({size:,} bytes): "
                                 f"{'; '.join(reasons)}\n")
        builder = repo.TreeBuilder()
        add_directory_to_tree(repo, parts_dir, builder, lfs_extensions)
        tree_oid = str(builder.write())

    if plan['mode'] == 'original':
        return tree_oid, pointer_format.write(tree_oid, doc_hash, pointer_format.ORIGINAL_PROFILE, [])
    entries = pointer_entries(plan['items'], plan['breaks'], plan['corrections'], plan['raw'])
    logging.info(f"{len(entries)} entries, profile {plan['profile']}, "
                 f"{len(plan['corrections'])} with preflate data, {len(plan['raw'])} raw")
    return tree_oid, pointer_format.write(tree_oid, doc_hash, plan['profile'], entries,
                                          plan['fallback'], plan['comment'])


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
    # First filter run in this repository: install its hooks and container
    # fetch refspec (once; see zippy_setup.py).
    zippy_setup.ensure_repo(repo.workdir or Path.cwd())
    # Which parts go to LFS is a property of the document's path, set in
    # .gitattributes (zippy-lfs=jpg,jpeg). Unset means none, as before.
    lfs_extensions = lfs_parts.extensions_for(repo, str(docx_path).replace("\\", "/"))
    if lfs_extensions:
        logging.info(f"Parts with extensions {sorted(lfs_extensions)} go to LFS")
    docx_hash = calculate_sha256(docx_bytes)
    # Built completely before anything reaches stdout, so a failure can never
    # leave git holding half a pointer.
    tree_oid, pointer = store_document(repo, docx_bytes, docx_hash, lfs_extensions, str(docx_path))
    logging.info(f"Document SHA256={docx_hash}, parts tree {tree_oid}")
    sys.stdout.write(pointer)
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