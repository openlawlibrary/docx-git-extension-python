#!/usr/bin/env python3
"""
zip_layout.py - the one place that lays out a zip archive from a pointer.

Smudge writes documents with it. Clean runs the same code on the original
document - with the original compressed bytes standing in for the ones smudge
will produce - and compares the result with the original byte for byte. That
check costs one pass over the bytes, no compression, and it catches every
difference in the zip around the compressed data that the pointer cannot
express: bytes between entries or after the archive, zip64 records, local and
central headers that disagree, unusual sizes, duplicate or renamed parts. A
document that fails it is stored whole instead (PROFILE original), so it
always checks out.

Paths in the parts tree that are git-zippy's own, never a document's:

    .zippy/raw/<entry name>   original compressed bytes of an entry that no
                              profile and no fallback reproduces (ENTRY raw=1)
    .zippy/original           the whole document, for PROFILE original
"""

from __future__ import annotations

import io
import struct
from typing import Callable, Dict, List, Tuple

SIG_LFH, SIG_CFH, SIG_EOCD, SIG_DD = 0x04034B50, 0x02014B50, 0x06054B50, 0x08074B50
METHOD_STORE, METHOD_DEFLATE = 0, 8

RESERVED = ".zippy"
RAW_DIR = ".zippy/raw"
ORIGINAL = ".zippy/original"

# What a directory entry holds: nothing when stored, the 2-byte empty deflate
# stream when "deflated". Anything else in a directory entry fails the check.
EMPTY_DEFLATE = b"\x03\x00"


def dir_data(method: int) -> bytes:
    return EMPTY_DEFLATE if method == METHOD_DEFLATE else b""


# part(entry) -> (compressed bytes as written, crc32 of the plain part, plain size)
PartFn = Callable[[Dict], Tuple[bytes, int, int]]


def write_archive(entries: List[Dict], part: PartFn, archive_comment: bytes = b"") -> bytes:
    out = io.BytesIO()
    cd_records: List[bytes] = []
    for ent in entries:
        name_raw, lfh, cd, pol = ent['name_raw'], ent['lfh'], ent['cd'], ent['policy']
        lfh_off = out.tell()
        comp, crc32, usize = part(ent)
        csize = len(comp)
        if csize >= 0xFFFFFFFF or usize >= 0xFFFFFFFF or lfh_off >= 0xFFFFFFFF:
            raise ValueError('zip64 is not supported (an entry or offset exceeds 4 GiB)')
        use_dd = bool(pol.get('use_data_descriptor'))
        out.write(struct.pack('<IHHHHHIIIHH', SIG_LFH, lfh['version_needed'], lfh['flags'],
                              lfh['method'], lfh['dos_time'], lfh['dos_date'],
                              0 if use_dd else crc32, 0 if use_dd else csize,
                              0 if use_dd else usize, len(name_raw), len(lfh['extra_lfh'])))
        out.write(name_raw)
        out.write(lfh['extra_lfh'])
        out.write(comp)
        if use_dd:
            if pol.get('dd_has_signature'):
                out.write(struct.pack('<I', SIG_DD))
            out.write(struct.pack('<III', crc32, csize, usize))
        cd_records.append(struct.pack(
            '<IHHHHHHIIIHHHHHII', SIG_CFH, cd['version_made_by'], cd['version_needed'],
            lfh['flags'], lfh['method'], cd['dos_time'], cd['dos_date'], crc32, csize, usize,
            len(name_raw), len(cd['extra_cd']), len(cd['comment']), 0, cd['internal_attr'],
            cd['external_attr'], lfh_off) + name_raw + cd['extra_cd'] + cd['comment'])
    cd_start = out.tell()
    for rec in cd_records:
        out.write(rec)
    cd_size = out.tell() - cd_start
    if cd_start >= 0xFFFFFFFF or len(cd_records) >= 0xFFFF:
        raise ValueError('zip64 is not supported (too many entries or too large)')
    out.write(struct.pack('<IHHHHIIH', SIG_EOCD, 0, 0, len(cd_records), len(cd_records),
                          cd_size, cd_start, len(archive_comment)))
    out.write(archive_comment)
    return out.getvalue()


def first_difference(a: bytes, b: bytes) -> int:
    """Offset of the first differing byte (or of the shorter end)."""
    n = min(len(a), len(b))
    lo, hi = 0, n
    while lo < hi:                       # binary search on slices: fast for large documents
        mid = (lo + hi) // 2
        if a[lo:mid + 1] == b[lo:mid + 1]:
            lo = mid + 1
        else:
            hi = mid
    return lo


def safe_name(name: str) -> bool:
    """A name smudge can use as a path inside its scratch folder, and not ours."""
    if not name or name.startswith("/") or "\\" in name or ":" in name or "\0" in name:
        return False
    parts = name.rstrip("/").split("/")
    if any(p in ("", ".", "..") for p in parts):
        return False
    return parts[0] != RESERVED
