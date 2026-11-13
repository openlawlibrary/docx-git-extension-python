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
- Entry names are kept as stored bytes; for paths in the parts tree they are
  decoded using GPF_UTF8 or CP437.
- Everything happens in memory: the document is unpacked into {name: bytes}
  and the parts tree is written from that, without a scratch folder.
"""

from __future__ import annotations
from pathlib import Path
import struct
import sys
from typing import Dict, List, Optional, Tuple
import pygit2
import logging
import zlib
import block_breaks
import compression_profiles
import lfs_parts
import pointer_format
import preflate_fallback
import zippy_setup
import zip_layout
from zip_layout import (SIG_LFH, SIG_CFH, SIG_EOCD, SIG_DD, METHOD_STORE, METHOD_DEFLATE)
from utils.utils import (read_u16, read_u32, calculate_sha256, common_prefix, repo_from_cwd)

GPF_ENCRYPTED       = 0x0001
GPF_DATA_DESCRIPTOR = 0x0008
GPF_UTF8            = 0x0800

# The same record layouts zip_layout.write_archive packs.
_CFH = struct.Struct('<IHHHHHHIIIHHHHHII')     # central directory file header
_LFH = struct.Struct('<IHHHHHIIIHH')           # local file header

log_path = Path.cwd() / "zippy_clean.log"
logging.basicConfig(filename=log_path, level=logging.DEBUG, format="%(asctime)s %(levelname)s: %(message)s")

def read_eocd(buf: bytes) -> Tuple[int, int, bytes]:
    """(central directory offset, its size, the zip's own comment), from the
    EOCD (End Of Central Directory) record, found by scanning backwards."""
    start = len(buf) - min(len(buf), 65557)
    for i in range(len(buf) - 22, start - 1, -1):
        if read_u32(buf, i) == SIG_EOCD and i + 22 + read_u16(buf, i + 20) <= len(buf):
            return read_u32(buf, i + 16), read_u32(buf, i + 12), buf[i + 22:i + 22 + read_u16(buf, i + 20)]
    raise ValueError('EOCD not found')


def _decode_name(raw: bytes, gpf: int) -> str:
    try:
        return raw.decode('utf-8') if (gpf & GPF_UTF8) else raw.decode('cp437')
    except UnicodeDecodeError:
        return raw.decode('utf-8', 'replace')


def read_entries(buf: bytes, cd_off: int, cd_size: int) -> List[Dict]:
    """
    One item per zip entry, in central directory order: `entry` is what the
    pointer records (the structure pointer_format writes and smudge rebuilds
    from), `comp` the entry's bytes as stored.
    """
    items: List[Dict] = []
    p, end = cd_off, cd_off + cd_size
    while p < end:
        (sig, made, cd_ver, _gpf, _method, cd_time, cd_date, crc, csize, usize, nlen, xlen,
         clen, _disk, iattr, eattr, lfh_off) = _CFH.unpack_from(buf, p)
        if sig != SIG_CFH:
            raise ValueError(f'Invalid CFH signature at 0x{p:X}')
        p += _CFH.size
        name_raw = buf[p:p + nlen]
        extra_cd = buf[p + nlen:p + nlen + xlen]
        comment = buf[p + nlen + xlen:p + nlen + xlen + clen]
        p += nlen + xlen + clen

        (lsig, ver, gpf, method, dtime, ddate, _lcrc, lcsize, _lusize, lnlen,
         lxlen) = _LFH.unpack_from(buf, lfh_off)
        if lsig != SIG_LFH:
            raise ValueError(f'Invalid LFH signature at 0x{lfh_off:X}')
        extra_lfh = buf[lfh_off + 30 + lnlen:lfh_off + 30 + lnlen + lxlen]
        data_off = lfh_off + 30 + lnlen + lxlen
        comp_len = csize if lcsize == 0 else lcsize
        use_dd = bool(gpf & GPF_DATA_DESCRIPTOR)
        dd_has_sig = (use_dd and data_off + comp_len + 4 <= len(buf)
                      and read_u32(buf, data_off + comp_len) == SIG_DD)
        name = _decode_name(name_raw, gpf)
        is_dir = name_raw.endswith(b'/')
        entry = {
            'name': name,
            'name_raw': name_raw,
            'is_dir': is_dir,
            'lfh': {'version_needed': ver, 'flags': gpf, 'method': method,
                    'dos_time': dtime, 'dos_date': ddate, 'extra_lfh': extra_lfh},
            'cd': {'version_made_by': made, 'version_needed': cd_ver,
                   'dos_time': cd_time, 'dos_date': cd_date,
                   'internal_attr': iattr, 'external_attr': eattr,
                   'extra_cd': extra_cd, 'comment': comment},
            'policy': {'use_data_descriptor': use_dd, 'dd_has_signature': bool(dd_has_sig),
                       'flush_offsets': (), 'break_kind': compression_profiles.BREAK_NONE,
                       'preflate': None},
        }
        items.append({'name': name, 'entry': entry, 'method': method, 'is_dir': is_dir,
                      'comp': buf[data_off:data_off + comp_len], 'usize': usize, 'crc': crc})
    return items


def unpack(items: List[Dict]) -> Dict[str, bytes]:
    """
    The plain bytes of every file entry, {name: bytes}; also kept on each item
    as 'data'. Raises on what an unzip would refuse: an unknown method, a
    damaged stream, a size or CRC that does not match.
    """
    parts: Dict[str, bytes] = {}
    for it in items:
        if it['is_dir']:
            continue
        comp, method = it['comp'], it['method']
        if method == METHOD_STORE:
            data = comp
        elif method == METHOD_DEFLATE:
            data = zlib.decompress(comp, -15) if comp else b''
        else:
            raise ValueError(f"entry {it['name']!r} uses compression method {method}")
        if len(data) != it['usize'] or (zlib.crc32(data) & 0xFFFFFFFF) != it['crc']:
            raise ValueError(f"entry {it['name']!r} is damaged (size or CRC-32 does not match)")
        it['data'] = data
        parts[it['name']] = data
    return parts


def stream_shape(comp: bytes, empty: bool, flushes) -> str:
    """'plain' (no empty block), 'tail' (one, at the very end) or 'flushes'."""
    if not empty:
        return 'plain'
    if not flushes and comp.endswith(compression_profiles.SYNC_TAIL):
        return 'tail'
    return 'flushes'


def _fit_entry(raw: bytes, comp: bytes, usize: int, flushes, profile, can_scan: bool,
               allow_fit: bool = True):
    """(break kind, offsets) with which `profile` reproduces `comp`, or None."""
    if profile['kind'] == 'msword':
        kind = compression_profiles.BREAK_FULL if flushes else compression_profiles.BREAK_NONE
        if compression_profiles.entry_matches(raw, comp, profile, kind, flushes):
            return kind, tuple(flushes)
        return None
    if compression_profiles.entry_matches(raw, comp, profile):
        return compression_profiles.BREAK_NONE, ()
    if not (allow_fit and compression_profiles.fittable(profile)
            and can_scan and block_breaks.supports_z_block()):
        return None
    offs = block_breaks.fit_breaks(raw, comp, usize, profile['level'],
                                   profile['memlevel'], profile.get('strategy', 0))
    return None if offs is None else (compression_profiles.BREAK_BLOCK, tuple(offs))


# Per-entry search (mixed documents): how many block-break fits to attempt for
# an entry no profile reproduces as it is. Fitting is the expensive step.
FIT_ATTEMPTS = 3


def _choose_profile(items: List[Dict]):
    """
    Pick, for every deflated entry, the profile that reproduces it and the
    breaks it needs. Returns (default profile name or None, {item index:
    (profile name, break kind, offsets)}). Entries missing from the dict are
    reproduced by no profile: the fallback (preflate) takes them, or raw.

    The default is what the pointer's PROFILE line names; entries with another
    profile carry profile= on their ENTRY line.

    1. One profile for the whole document, as producers normally use one:
       msword when every part ends in or contains a flush, otherwise the
       plain profiles ranked by how much of the largest entry each
       reproduces; the first that reproduces every entry wins. Trying this
       before going part by part keeps single-producer documents on one
       profile even where a small part would match several, so the pointer is
       the same whatever order the per-part search would take.
    2. Otherwise, per entry, largest first: the profiles already used in this
       document first, then every profile the stream's shape allows; exact
       matches first, then up to FIT_ATTEMPTS block-break fits. The default is
       the profile most entries use, ties going to the one used first.

    Early exit everywhere a wrong answer can be recognised:
      * every comparison against the original streams the compressor's output
        and stops at the first block that differs;
      * a candidate is dropped at the first entry it cannot reproduce, and the
        largest entry is tried first because it tells candidates apart best;
      * empty blocks are read with libz in one pass per entry: Word's flush
        offsets come from that pass, and the stream's shape rules profiles out
        without compressing anything;
      * the break fitter resumes from its last confirmed break and stops each
        round at the first difference.
    """
    deflated = [i for i, it in enumerate(items)
                if it['method'] == METHOD_DEFLATE and not it['is_dir'] and it['comp']]
    if not deflated:
        # Nothing is compressed, so every profile rebuilds it; record the first.
        return compression_profiles.PROFILES[0]['name'], {}
    deflated.sort(key=lambda i: -len(items[i]['comp']))     # probe = largest
    raws = {i: items[i]['data'] for i in deflated}
    probe = deflated[0]

    can_scan = block_breaks.is_available()
    flushes: Dict[int, Tuple[int, ...]] = {}
    shape: Dict[int, str] = {}
    for i in deflated:
        empty, flushes[i] = False, ()
        if can_scan:
            try:
                empty, flushes[i] = block_breaks.empty_blocks(items[i]['comp'], items[i]['usize'])
            except Exception as e:
                logging.warning(f"block scan failed for {items[i]['name']}: {e}")
        shape[i] = stream_shape(items[i]['comp'], empty, flushes[i])

    usable = [p for p in compression_profiles.PROFILES if compression_profiles.is_available(p)]

    def ranked(profiles, i):
        """`profiles` by how much of entry i each reproduces before it first differs."""
        scored = []
        for n, p in enumerate(profiles):
            got = block_breaks.matching_prefix(
                compression_profiles.iter_compress_entry(raws[i], p), items[i]['comp'])
            scored.append((-got, n, p))
        return [p for _, _, p in sorted(scored, key=lambda t: t[:2])]

    # 1. one profile for every entry
    shapes = {shape[i] for i in deflated}
    candidates = []
    if 'plain' not in shapes:
        # Word ends every part with a flush: msword first, then the producers
        # that end with a sync flush (only when nothing has flushes inside).
        candidates += [p for p in usable if p['kind'] == 'msword']
        if shapes == {'tail'}:
            candidates += ranked([p for p in usable if p['kind'] != 'msword'
                                  and compression_profiles.accepts(p, 'tail')], probe)
    elif shapes == {'plain'}:
        candidates += ranked([p for p in usable if compression_profiles.accepts(p, 'plain')], probe)
    for profile in candidates:
        assign = {}
        for i in deflated:
            fit = _fit_entry(raws[i], items[i]['comp'], items[i]['usize'], flushes[i],
                             profile, can_scan)
            if fit is None:
                break
            assign[i] = (profile['name'],) + fit
        else:
            logging.info(f"Profile {profile['name']} reproduces every deflated entry")
            return profile['name'], assign
        logging.debug(f"Profile {profile['name']} rejected")

    # 2. per entry
    used: List[Dict] = []
    assign = {}
    for i in deflated:
        allowed = [p for p in usable if compression_profiles.accepts(p, shape[i])]
        order = [p for p in used if p in allowed] + [p for p in allowed if p not in used]
        hit = None
        for p in order:
            fit = _fit_entry(raws[i], items[i]['comp'], items[i]['usize'], flushes[i],
                             p, can_scan, allow_fit=False)
            if fit is not None:
                hit = (p, fit)
                break
        if hit is None and can_scan:
            fits = [p for p in used if p in allowed and compression_profiles.fittable(p)]
            fits += [p for p in ranked([p for p in allowed if compression_profiles.fittable(p)], i)
                     if p not in fits]
            for p in fits[:FIT_ATTEMPTS]:
                fit = _fit_entry(raws[i], items[i]['comp'], items[i]['usize'], flushes[i],
                                 p, can_scan)
                if fit is not None:
                    hit = (p, fit)
                    break
        if hit is None:
            logging.info(f"No profile reproduces {items[i]['name']}")
            continue
        p, fit = hit
        if p not in used:
            used.append(p)
        assign[i] = (p['name'],) + fit
    if not assign:
        logging.warning("No profile reproduces any entry; the pointer records PROFILE fallback")
        return None, {}
    counts = {p['name']: 0 for p in used}
    for name, _, _ in assign.values():
        counts[name] += 1
    default = max(counts, key=lambda n: counts[n])        # first used wins a tie
    logging.info("Profiles per entry: " + ", ".join(f"{n} x{c}" for n, c in counts.items())
                 + f"; {len(deflated) - len(assign)} for the fallback")
    return default, assign


def _preflate_corrections(items: List[Dict], only=None):
    """
    The fallback: preflate-rs corrections for every deflated entry, as
    (fallback tool/version or None, {item index: corrections}, {item index:
    why it has none}). The helper verifies each one by rebuilding the stream,
    so what is recorded does rebuild. Entries without corrections - preflate
    cannot model them, or there is no helper here - are stored raw instead.
    """
    deflated = [i for i, it in enumerate(items)
                if it['method'] == METHOD_DEFLATE and not it['is_dir'] and it['comp']
                and (only is None or i in only)]
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


def pointer_entries(items: List[Dict], assign, profile: str, corrections=None, raw=()) -> List[Dict]:
    """
    The pointer's entry list: each entry with its profile (when not the
    document's `profile`) and breaks, its fallback corrections, or its raw flag.
    `assign` is _choose_profile's {item index: (profile name, kind, offsets)}.
    """
    corrections = corrections or {}
    out = []
    for i, it in enumerate(items):
        name, kind, offs = assign.get(i, (None, compression_profiles.BREAK_NONE, ()))
        e = dict(it['entry'])
        e['policy'] = dict(e['policy'], flush_offsets=tuple(offs),
                           break_kind=kind if offs else compression_profiles.BREAK_NONE,
                           preflate=corrections.get(i), raw=i in raw,
                           profile=name if name and name != profile else None)
        logging.debug(
            f"entry {it['name']!r}: method={it['method']} dir={it['is_dir']} "
            f"comp={len(it['comp'])} uncomp={it['usize']} profile={name or '-'} "
            f"breaks={compression_profiles.BREAK_NAMES[kind]}:{offs or '-'}")
        out.append(e)
    return out


def _check_container(buf: bytes, items: List[Dict], comment: bytes) -> Optional[str]:
    """
    None when smudge's zip writer, given the original compressed bytes, writes
    exactly `buf`; otherwise why not. No compression - one pass over the bytes.
    """
    by_id = {id(it['entry']): it for it in items}

    def part(entry):
        it = by_id[id(entry)]
        if it['is_dir']:
            return zip_layout.dir_data(it['method']), 0, 0
        return it['comp'], zlib.crc32(it['data']) & 0xFFFFFFFF, len(it['data'])
    try:
        rebuilt = zip_layout.write_archive([it['entry'] for it in items], part, comment)
    except Exception as e:
        return f"its zip layout cannot be written back ({e})"
    if rebuilt != buf:
        off = common_prefix(rebuilt, buf)
        return (f"its zip layout differs from what the pointer can describe "
                f"(first difference at byte {off} of {len(buf)})")
    return None


def plan_document(buf: bytes) -> Dict:
    """
    Unpack `buf` and decide how the document is stored: mode 'pointer'
    (profile or fallback, some entries possibly raw) or mode 'original'
    (stored whole), with the reason. 'parts' is what goes into the parts tree
    besides git-zippy's own files ({path: bytes}), 'dirs' the directory
    entries, which stay in the tree even when empty.
    """
    def original(reason, parts=None, dirs=()):
        # Parts that could be unpacked stay next to the whole document, for diffs.
        return {'mode': 'original', 'reason': reason, 'parts': parts or {}, 'dirs': list(dirs)}
    try:
        cd_off, cd_size, comment = read_eocd(buf)
        items = read_entries(buf, cd_off, cd_size)
        parts = unpack(items)
    except Exception as e:
        return original(f"it is not a zip this extension can read ({e})")
    if not items:
        return original("it has no zip entries")
    for it in items:
        if not zip_layout.safe_name(it['name']):
            # Not usable as a path in the parts tree (or one of ours): the whole
            # document alone.
            return original(f"entry name {it['name']!r} cannot be stored as a part")
    dirs = [it['name'].rstrip('/') for it in items if it['is_dir']]
    for it in items:
        if it['entry']['lfh']['flags'] & GPF_ENCRYPTED:
            return original(f"entry {it['name']!r} is encrypted", parts, dirs)
    why = _check_container(buf, items, comment)
    if why:
        return original(why, parts, dirs)

    profile_name, assign = _choose_profile(items)
    # A deflated entry with no compressed bytes at all is not a deflate stream
    # anything can reproduce; keep its (empty) bytes.
    raw = {i: "it has no deflate data" for i, it in enumerate(items)
           if it['method'] == METHOD_DEFLATE and not it['is_dir'] and not it['comp']}
    # Every other deflated entry no profile reproduces goes to the fallback,
    # and what the fallback cannot model is kept raw.
    rest = {i for i, it in enumerate(items)
            if it['method'] == METHOD_DEFLATE and not it['is_dir'] and it['comp']
            and i not in assign}
    fallback, corrections = None, {}
    if rest:
        fallback, corrections, failed = _preflate_corrections(items, rest)
        raw.update(failed)
    if profile_name:
        logging.info(f"Recording compression profile: {profile_name}")
    else:
        profile_name = pointer_format.FALLBACK_PROFILE
    return {'mode': 'pointer', 'items': items, 'profile': profile_name, 'assign': assign,
            'fallback': fallback if corrections else None, 'corrections': corrections,
            'raw': raw, 'comment': comment, 'parts': parts, 'dirs': dirs}


def write_tree(repo, files: Dict[str, bytes], dirs=(), lfs_extensions=frozenset()) -> str:
    """
    Write a git tree from {path: bytes} (plus directories that must exist even
    when empty) and return its oid.

    Parts whose extension is in `lfs_extensions` go to the local LFS store and
    the tree holds their LFS pointer instead; see lfs_parts.py. So does a whole
    document stored at .zippy/original when the document uses LFS at all.
    """
    root: Dict = {}

    def node_for(components):
        node = root
        for c in components:
            node = node.setdefault(c, {})
            if not isinstance(node, dict):
                raise ValueError(f"{'/'.join(components)}: a part and a folder share a name")
        return node

    for d in dirs:
        node_for(d.split("/"))
    for path, data in files.items():
        *folders, leaf = path.split("/")
        node = node_for(folders)
        if isinstance(node.get(leaf), dict):
            raise ValueError(f"{path}: a part and a folder share a name")
        if path == zip_layout.ORIGINAL and lfs_extensions and data:
            node[leaf] = lfs_parts.store(repo, data)
        else:
            node[leaf] = lfs_parts.blob_for_part(repo, leaf, data, lfs_extensions)

    def write(node) -> pygit2.Oid:
        builder = repo.TreeBuilder()
        for name, value in node.items():
            if isinstance(value, dict):
                builder.insert(name, write(value), pygit2.GIT_FILEMODE_TREE)
            else:
                builder.insert(name, repo.create_blob(value), pygit2.GIT_FILEMODE_BLOB)
        return builder.write()

    return str(write(root))


def store_document(repo, buf: bytes, doc_hash: str, lfs_extensions=frozenset(),
                   display: str = "document") -> Tuple[str, str]:
    """
    Store the document's parts as a git tree and return (tree oid, pointer).
    Built completely before anything reaches stdout.
    """
    plan = plan_document(buf)
    files = dict(plan['parts'])
    if plan['mode'] == 'original':
        logging.warning(f"{display}: stored whole: {plan['reason']}")
        sys.stderr.write(f"[zippy] {display}: stored whole, not unpacked for rebuilding, "
                         f"because {plan['reason']}\n")
        files[zip_layout.ORIGINAL] = buf
    else:
        items = plan['items']
        for i in plan['raw']:
            files[f"{zip_layout.RAW_DIR}/{items[i]['name']}"] = items[i]['comp']
        if plan['raw']:
            size = sum(len(items[i]['comp']) for i in plan['raw'])
            reasons = sorted(set(plan['raw'].values()))
            sys.stderr.write(f"[zippy] {display}: {len(plan['raw'])} part(s) stored as their "
                             f"original compressed bytes ({size:,} bytes): "
                             f"{'; '.join(reasons)}\n")
    try:
        tree_oid = write_tree(repo, files, plan['dirs'], lfs_extensions)
    except ValueError as e:
        # A part and a folder with the same name: no tree can hold both.
        plan = {'mode': 'original', 'reason': str(e)}
        logging.warning(f"{display}: stored whole: {e}")
        sys.stderr.write(f"[zippy] {display}: stored whole, not unpacked for rebuilding, "
                         f"because {e}\n")
        tree_oid = write_tree(repo, {zip_layout.ORIGINAL: buf}, (), lfs_extensions)

    if plan['mode'] == 'original':
        return tree_oid, pointer_format.write(tree_oid, doc_hash, pointer_format.ORIGINAL_PROFILE, [])
    entries = pointer_entries(plan['items'], plan['assign'], plan['profile'],
                              plan['corrections'], plan['raw'])
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

    if pointer_format.is_pointer(docx_bytes):
        # The worktree holds a pointer rather than a document, so a checkout
        # wrote the stored bytes straight to disk - the smudge filter was not
        # configured, or it failed and filter.zippy.required was not set.
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
    # .gitattributes (zippy-lfs=jpg,jpeg,png,emf). Unset means none.
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