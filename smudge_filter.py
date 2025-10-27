#!/usr/bin/env python3
"""
"""
from __future__ import annotations
import io
from pathlib import Path
import struct
import sys
import zlib
from typing import Dict, Iterable, List, Tuple
import tempfile
import pygit2
import logging
from utils.utils import (read_u16, read_u32, decode_b85, calculate_sha256)

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

log_path = Path.cwd() / "docx_smudge.log"
logging.basicConfig(filename=log_path, level=logging.DEBUG, format="%(asctime)s %(levelname)s: %(message)s")

def find_eocd(buf: bytes) -> Tuple[int, int, int, int]:
    """
    Locate EOCD by scanning backwards. Return (eocd_off, cd_off, cd_size, comment_len).
    """
    max_scan = min(len(buf), 65557)
    window = buf[len(buf)-max_scan:]
    for i in range(len(window) - 22, -1, -1):
        if read_u32(window, i) == SIG_EOCD:
            eocd_off = len(buf) - max_scan + i
            comment_len = read_u16(window, i + 20)
            if i + 22 + comment_len <= len(window):
                cd_size = read_u32(window, i + 12)
                cd_off  = read_u32(window, i + 16)
                return eocd_off, cd_off, cd_size, comment_len
    raise ValueError('EOCD not found')


def iterate_cd_entries(buf: bytes, cd_off: int, cd_size: int) -> Iterable[Dict]:
    """
    Parse and iterate central directory entries.
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
    Extract local file header data from byte array.
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

def _unpack_entries(b: bytes) -> List[Dict]:
    p = 0
    if b[p:p+4] != META_MAGIC:
        raise ValueError('Bad v3 meta magic')
    p += 4
    count = read_u32(b, p); p += 4
    entries: List[Dict] = []
    for _ in range(count):
        name_len = read_u16(b, p); p += 2
        name_raw = b[p:p+name_len]; p += name_len
        is_dir = b[p]; p += 1
        vn, gpf, method, dt, dd = struct.unpack_from('<HHHHH', b, p); p += 10
        el_len = read_u16(b, p); p += 2
        extra_lfh = b[p:p+el_len]; p += el_len
        vm, vn_cd, iattr = struct.unpack_from('<HHH', b, p); p += 6
        eattr = read_u32(b, p); p += 4
        ec_len = read_u16(b, p); p += 2
        extra_cd = b[p:p+ec_len]; p += ec_len
        cm_len = read_u16(b, p); p += 2
        comment = b[p:p+cm_len]; p += cm_len
        use_dd = b[p]; dd_sig = b[p+1]; p += 2
        try:
            name_str = name_raw.decode('utf-8') if (gpf & GPF_UTF8) else name_raw.decode('cp437')
        except Exception:
            name_str = name_raw.decode('utf-8', 'replace')
        entries.append({
            'name': name_str,
            'name_raw': name_raw,
            'is_dir': bool(is_dir),
            'lfh': {
                'version_needed': vn,
                'flags': gpf,
                'method': method,
                'dos_time': dt,
                'dos_date': dd,
                'extra_lfh': extra_lfh,
            },
            'cd': {
                'version_made_by': vm,
                'version_needed': vn_cd,
                'internal_attr': iattr,
                'external_attr': eattr,
                'extra_cd': extra_cd,
                'comment': comment,
            },
            'policy': {
                'use_data_descriptor': bool(use_dd),
                'dd_has_signature': bool(dd_sig),
            },
        })
    return entries

def _compress_raw_deflate(data: bytes, level: int, memlevel: int) -> bytes:
    co = zlib.compressobj(level=level, method=zlib.DEFLATED, wbits=-15,
                          memLevel=memlevel)
    return co.compress(data) + co.flush(zlib.Z_FINISH)

def _parse_metadata(metadata_line: str) -> List[Dict]:
    parts = metadata_line.split()
    if len(parts) < 4 or parts[0] != 'ENTRIES_BASE85' or parts[-2] != 'SHA256':
        raise ValueError('Malformed ENTRIES_BASE85 line')
    b85 = parts[1]
    sha = parts[-1]
    blob = decode_b85(b85)
    if calculate_sha256(blob) != sha:
        raise ValueError('ENTRIES_BASE85 SHA256 mismatch')
    return _unpack_entries(blob)

def build_docx_bytes(input_dir: Path, metadata_line: str,
                     level: int = 6, memlevel: int = 8) -> bytes:
    """
    Build a DOCX archive in-memory from uncompressed files and metadata,
    using the given zlib parameters for DEFLATE entries.
    """
    entries = _parse_metadata(metadata_line)

    out = io.BytesIO()
    cd_records: List[bytes] = []

    for ent in entries:
        name_raw: bytes = ent['name_raw']
        name_str: str = ent['name']
        is_dir: bool = ent['is_dir']
        lfh = ent['lfh']
        cd  = ent['cd']
        pol = ent['policy']

        lfh_off = out.tell()

        if is_dir:
            raw = b''
        else:
            src_path = (input_dir / name_str)
            if not src_path.is_file():
                raise FileNotFoundError(f'Missing input file for entry: {name_str}')
            raw = src_path.read_bytes()

        crc32 = zlib.crc32(raw) & 0xFFFFFFFF
        if lfh['method'] == METHOD_STORE:
            comp = raw
        elif lfh['method'] == METHOD_DEFLATE:
            comp = _compress_raw_deflate(raw, level=level, memlevel=memlevel)
        else:
            raise ValueError(f'Unsupported method {lfh["method"]} for {name_str}')

        uncomp_size = len(raw)
        comp_size   = len(comp)
        if comp_size >= 0xFFFFFFFF or uncomp_size >= 0xFFFFFFFF:
            raise ValueError('ZIP64 not supported in builder (sizes exceed 4 GiB)')

        use_dd = bool(pol.get('use_data_descriptor', False))
        dd_has_sig = bool(pol.get('dd_has_signature', False))

        l_crc32 = 0 if use_dd else crc32
        l_comp  = 0 if use_dd else comp_size
        l_uncomp= 0 if use_dd else uncomp_size

        lfh_hdr = struct.pack(
            '<IHHHHHIIIHH',
            SIG_LFH,
            lfh['version_needed'],
            lfh['flags'],
            lfh['method'],
            lfh['dos_time'],
            lfh['dos_date'],
            l_crc32,
            l_comp,
            l_uncomp,
            len(name_raw),
            len(lfh['extra_lfh']),
        )
        out.write(lfh_hdr)
        out.write(name_raw)
        out.write(lfh['extra_lfh'])

        out.write(comp)

        if use_dd:
            if dd_has_sig:
                out.write(struct.pack('<I', SIG_DD))
            out.write(struct.pack('<III', crc32, comp_size, uncomp_size))

        cfh = struct.pack(
            '<IHHHHHHIIIHHHHHII',
            SIG_CFH,
            cd['version_made_by'],
            cd.get('version_needed', lfh['version_needed']),
            lfh['flags'],
            lfh['method'],
            lfh['dos_time'],
            lfh['dos_date'],
            crc32,
            comp_size,
            uncomp_size,
            len(name_raw),
            len(cd['extra_cd']),
            len(cd['comment']),
            0,
            cd.get('internal_attr', 0),
            cd.get('external_attr', 0),
            lfh_off,
        )
        cd_records.append(cfh + name_raw + cd['extra_cd'] + cd['comment'])

    cd_start = out.tell()
    for rec in cd_records:
        out.write(rec)
    cd_size = out.tell() - cd_start

    total_entries = len(cd_records)
    eocd = struct.pack(
        '<IHHHHIIH',
        SIG_EOCD,
        0,
        0,
        total_entries,
        total_entries,
        cd_size,
        cd_start,
        0,
    )
    out.write(eocd)
    return out.getvalue()

def build_from_metadata(input_dir: Path, metadata_line: str, output_path: Path,
                        level: int = 6, memlevel: int = 8) -> None:
    """
    Wrapper that writes the in-memory archive to disk.
    """
    data = build_docx_bytes(input_dir, metadata_line, level=level, memlevel=memlevel)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(data)

def repo_from_cwd():
    """
    Find pyit2 repository on current path.
    """
    repo = pygit2.Repository(pygit2.discover_repository(Path.cwd()))
    logging.debug(f"Opened repo at {repo.path}")
    return repo

def extract_tree(repo, tree, path: Path):
    """
    Extract xml files from a git tree to a specified path.
    """
    path.mkdir(parents=True, exist_ok=True)
    logging.debug(f"Extracting tree to {path}")
    for entry in tree:
        full_path = path / entry.name
        obj = repo[entry.id]
        if entry.filemode == pygit2.GIT_FILEMODE_TREE:
            extract_tree(repo, obj, full_path)
        else:
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_bytes(obj.read_raw())
            logging.debug(f"Extracted file: {full_path}")

def recompress_docx(input_dir: Path, metadata_line: str, expected_hash: str) -> Tuple[bytes, str, dict]:
    """
    Deterministically recompress docx from pointer file metadata.
    Try default parameters first; if whole-archive SHA256 != expected, try Aspose-like fallback
    with level=5 and memLevel in 1..9. Return (docx_bytes, matched_profile, meta).
    matched_profile is "default", "aspose-ml#<n>", or "none".
    meta contains auxiliary info useful for logs.
    """
    # 1) Default - python-docx
    default_level, default_mem = 6, 8
    docx_bytes = build_docx_bytes(input_dir, metadata_line, level=default_level, memlevel=default_mem)
    sha = calculate_sha256(docx_bytes)
    logging.info(f"Default build SHA256={sha}")
    if expected_hash and sha == expected_hash:
        logging.info("Default build matched expected hash.")
        return docx_bytes, "default", {"level": default_level, "memLevel": default_mem, "sha": sha}

    # 2) Aspose-like fallback
    for ml in range(1, 10):
        docx_bytes_ml = build_docx_bytes(input_dir, metadata_line, level=5, memlevel=ml)
        sha_ml = calculate_sha256(docx_bytes_ml)
        logging.info(f"Aspose-like build memLevel={ml} SHA256={sha_ml}")
        if expected_hash and sha_ml == expected_hash:
            logging.info(f"Aspose-like memLevel={ml} matched expected hash.")
            return docx_bytes_ml, f"aspose-ml#{ml}", {"level": 5, "memLevel": ml, "sha": sha_ml}

    logging.warning("No recompression profile matched the expected hash; emitting default build.")
    return docx_bytes, "none", {"level": default_level, "memLevel": default_mem, "sha": sha}

def recreate_docx(repo, refname: str, expected_hash: str, metadata_line: str):
    """
    Recreate original docx from pointer file input data.
    1) Find git tree from refname.
    2) Extract git tree to a temp folder.
    3) Compress folder to recreate the original docx.
    """
    logging.info(f"Creating DOCX from ref '{refname}'")
    ref = repo.references[refname]
    obj = repo[ref.target]

    # Load git tree from custom ref:
    if isinstance(obj, pygit2.Commit):
        tree = obj.tree
        logging.debug(f"Resolved {refname} to commit {obj.id}")
    elif isinstance(obj, pygit2.Tree):
        tree = obj
        logging.debug(f"Resolved {refname} to tree {obj.id}")
    else:
        raise TypeError(f"Unsupported object type at {refname}: {type(obj)}")

    # Extract git tree to a temp folder and recompress it:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        extract_tree(repo, tree, tmp_path)

        # Compress folder to recreate the original docx:
        docx_bytes, profile, meta = recompress_docx(tmp_path, metadata_line, expected_hash)

        # Log outcome
        logging.info(f"Emit profile: {profile}, level={meta['level']}, memLevel={meta['memLevel']}, sha={meta['sha']}")

        # If expected hash provided and still mismatched, log an error explicitly
        if expected_hash and meta["sha"] != expected_hash:
            logging.error(f"Hash mismatch. Expected: {expected_hash}, Got: {meta['sha']} (profile={profile})")
            sys.stdout.buffer.write("")
        else:
            logging.info("Hash matched expected.")
            # Write result to stdout
            sys.stdout.buffer.write(docx_bytes)

def main():
    logging.info("docx_smudge_final.py started")
    # Extract refname from pointer file:
    pointer_line = sys.stdin.readline().strip()
    if not pointer_line.startswith("DOCX-POINTER:"):
        logging.warning("Missing DOCX-POINTER")
        sys.stdout.write(pointer_line + "\n")
        sys.stdout.write(sys.stdin.read())
        return
    refname = pointer_line.split(":", 1)[1].strip()

    # Extract original docx hash from pointer file:
    hash_line = sys.stdin.readline().strip()
    if not hash_line.startswith("HASH:"):
        logging.warning("Missing HASH")
        sys.stdout.write(hash_line + "\n")
        sys.stdout.write(sys.stdin.read())
        return
    expected_hash = hash_line.split(":", 1)[1].strip()

    # Extract metadata from pointer file:
    metadata_line = sys.stdin.readline().strip()
    if not metadata_line.startswith("ENTRIES_BASE85"):
        logging.warning("Missing ENTRIES_BASE85")
        logging.warning(f"{metadata_line}")
        sys.stdout.write(metadata_line + "\n")
        return

    try:
        repo = repo_from_cwd()
        recreate_docx(repo, refname, expected_hash, metadata_line)
    except Exception as e:
        logging.exception(f"Unhandled exception: {e}")

if __name__ == "__main__":
    main()
