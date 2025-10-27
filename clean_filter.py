#!/usr/bin/env python3
"""
Format of pointer-file:
    DOCX-POINTER: <refname>
    HASH: SHA256 <hex>
    ENTRIES_BASE85 <b85> SHA256 <hex>

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
META_MAGIC = b"DM3\x00"

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
    recs: List[bytes] = []
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
        recs.append(b''.join(rec))
    header = b''.join([
        META_MAGIC,
        struct.pack('<I', len(recs)),
        struct.pack('<I', 0),  # global flags: zip64 bit0 = 0
    ])
    return header + b''.join(recs)

def dump_metadata(original: Path) -> None:
    """
    Write xml metadata to a pointer file.
    """
    b = original.read_bytes()
    cd_off, cd_size = find_eocd(b)

    entries_blob = _pack_entries_from_original(b, cd_off, cd_size)
    entries_b85 = encode_b85(entries_blob)
    entries_sha = calculate_sha256(entries_blob)

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
            zip_ref.extractall(tmp_path / "unzipped")

        tree_builder = repo.TreeBuilder()
        add_directory_to_tree(repo, tmp_path / "unzipped", tree_builder)
        
        return tree_builder.write()

def main():
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: clean_filter.py <path_to_docx>\n")
        sys.exit(1)

    docx_path = Path(sys.argv[1])
    base_name = str(docx_path.with_suffix(""))

    docx_bytes = sys.stdin.buffer.read()
    refname = f"refs/docx/{base_name}"
    sys.stdout.write(f"DOCX-POINTER:{refname}\n")
    repo = repo_from_cwd()
    tree_oid = save_docx_as_git_tree(repo, docx_bytes)
    try:
        tree_oid_file = Path(repo.path) / "docx-tree-oid"
        tree_oid_file.write_text(str(tree_oid) + "\n", encoding="utf-8")
    except Exception as e:
        logging.warning(e)
    docx_hash = calculate_file_sha256(docx_path)
    sys.stdout.write(f"HASH:{docx_hash}\n")
    dump_metadata(docx_path)

if __name__ == "__main__":
    main()
