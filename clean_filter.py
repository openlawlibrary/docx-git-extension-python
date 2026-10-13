#!/usr/bin/env python3
"""
Format of pointer-file:
    DOCX-POINTER: <refname>
    TREE: <oid of the git tree holding the unpacked parts>
    HASH: SHA256 <hex>
    ENTRIES_BASE85 <b85> SHA256 <hex>

The header lines before ENTRIES_BASE85 are parsed by key, not by position, so
pointers written before TREE existed still smudge.

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
META_MAGIC_V3 = b"DM3\x00"   # no flush offsets; written when no entry needs them
META_MAGIC = b"DM4\x00"

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

def _pack_entries_from_original(buf: bytes, cd_off: int, cd_size: int) -> bytes:
    """
    Extract metadata for all xml entries.
    """
    recs: List[Tuple[bytes, Tuple[int, ...]]] = []
    for c in iterate_cd_entries(buf, cd_off, cd_size):
        lfh = parse_lfh(buf, c['lfh_rel_off'])
        # data descriptor policy detection
        use_dd = 1 if (lfh['gpf'] & GPF_DATA_DESCRIPTOR) else 0
        dd_has_sig = 0
        if use_dd:
            comp_size = c['comp_size'] if lfh['comp_size'] == 0 else lfh['comp_size']
            data_end = lfh['data_off'] + comp_size
            if data_end + 4 <= len(buf) and read_u32(buf, data_end) == SIG_DD:
                dd_has_sig = 1
        name = c['name_raw']
        is_dir = 1 if name.endswith(b'/') else 0
        extra_lfh = lfh['extra_raw']
        extra_cd  = c['extra_raw']
        comment   = c['comment_raw']
        # Word can hand the packager one part in several pieces, flushing between
        # them; the boundaries are content-dependent, so record rather than guess.
        flush_offsets = ()
        if lfh['method'] == METHOD_DEFLATE and not is_dir:
            comp_len = c['comp_size'] if lfh['comp_size'] == 0 else lfh['comp_size']
            try:
                flush_offsets = msword_compressor.detect_flush_offsets(
                    buf[lfh['data_off']:lfh['data_off'] + comp_len])
            except Exception as e:
                logging.warning(f"flush-offset scan failed for {c['name']}: {e}")
        logging.debug(
            f"entry {c['name']!r}: method={lfh['method']} dir={bool(is_dir)} "
            f"gpf=0x{lfh['gpf']:04x} comp={c['comp_size']} uncomp={c['uncomp_size']} "
            f"dd={use_dd}/{dd_has_sig} extra_lfh={len(extra_lfh)} extra_cd={len(extra_cd)} "
            f"flush={flush_offsets or '-'}")
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
        recs.append((b''.join(rec), tuple(flush_offsets)))

    # Only use DM4 when some entry actually has flush offsets. Otherwise keep
    # writing DM3, so pointers committed before DM4 existed re-clean to the same
    # bytes and git doesn't report every such docx as modified.
    has_flush = any(offsets for _, offsets in recs)
    n_flush = sum(1 for _, offsets in recs if offsets)
    logging.info(f"Packed {len(recs)} entries, magic={'DM4' if has_flush else 'DM3'}, "
                 f"{n_flush} entries carry flush offsets")
    header = b''.join([
        META_MAGIC if has_flush else META_MAGIC_V3,
        struct.pack('<I', len(recs)),
        struct.pack('<I', 0),  # global flags: zip64 bit0 = 0
    ])
    body = []
    for rec, offsets in recs:
        body.append(rec)
        if has_flush:
            body.append(struct.pack('<B', len(offsets)))
            body.append(b''.join(struct.pack('<I', o) for o in offsets))
    return header + b''.join(body)

def dump_metadata(b: bytes) -> None:
    """
    Write xml metadata to a pointer file. Takes the document's bytes so it
    cannot disagree with the tree built from those same bytes.
    """
    cd_off, cd_size = find_eocd(b)
    logging.debug(f"EOCD: central directory at {cd_off}, {cd_size} bytes")

    entries_blob = _pack_entries_from_original(b, cd_off, cd_size)
    entries_b85 = encode_b85(entries_blob)
    entries_sha = calculate_sha256(entries_blob)
    logging.info(f"Entry table: {len(entries_blob)} bytes raw, {len(entries_b85)} base85, "
                 f"SHA256={entries_sha}")

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
    base_name = str(docx_path.with_suffix(""))
    logging.info(f"Cleaning {docx_path} (base name {base_name!r}) in {Path.cwd()}")

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

    refname = f"refs/docx/{base_name}"
    logging.info(f"Pointer ref: {refname}")
    sys.stdout.write(f"DOCX-POINTER:{refname}\n")
    repo = repo_from_cwd()
    tree_oid = save_docx_as_git_tree(repo, docx_bytes)
    # Carry the tree id in the pointer: it is per-document and committed, so it
    # cannot be raced or overwritten the way a single $GIT_DIR slot can.
    sys.stdout.write(f"TREE:{tree_oid}\n")
    docx_hash = calculate_sha256(docx_bytes)
    logging.info(f"Document SHA256={docx_hash}")
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
