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
import block_breaks
import compression_profiles
import msword_compressor
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
# Repeated from the clean filter rather than imported: the two halves of this
# format should not be able to break each other by one of them moving.
POINTER_MAGIC = "DOCX-POINTER"

META_MAGIC_V3 = b"DM3\x00"   # pointers written before flush offsets existed
META_MAGIC_V4 = b"DM4\x00"   # per-entry Z_FULL_FLUSH offsets (Word)
META_MAGIC = b"DM5\x00"      # per-entry (break kind, offsets)

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
    magic = b[p:p+4]
    if magic not in (META_MAGIC, META_MAGIC_V4, META_MAGIC_V3):
        raise ValueError('Bad meta magic')
    # DM4 carries a bare offset count and means Z_FULL_FLUSH; DM5 carries an
    # explicit kind first, so a stream cut with Z_BLOCK is not replayed as a
    # flush. Getting that wrong produces a plausible stream with the wrong bytes.
    has_kind = (magic == META_MAGIC)
    has_flush = (magic == META_MAGIC_V4)
    p += 4
    count = read_u32(b, p); p += 4
    _global_flags = read_u32(b, p); p += 4
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
        break_kind, flush_offsets = compression_profiles.BREAK_NONE, ()
        if has_kind:
            break_kind = b[p]; n_off = b[p+1]; p += 2
            flush_offsets = tuple(read_u32(b, p + 4*k) for k in range(n_off))
            p += 4*n_off
            if not flush_offsets:
                break_kind = compression_profiles.BREAK_NONE
        elif has_flush:
            n_off = b[p]; p += 1
            flush_offsets = tuple(read_u32(b, p + 4*k) for k in range(n_off))
            p += 4*n_off
            if flush_offsets:
                break_kind = compression_profiles.BREAK_FULL
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
                'flush_offsets': flush_offsets,
                'break_kind': break_kind,
            },
        })
    return entries

# Single source of truth, shared with the clean filter so the two cannot drift.
COMPRESSION_PROFILES: List[Dict] = compression_profiles.PROFILES


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
                     profile: Dict = None) -> bytes:
    """
    Build a DOCX archive in-memory from uncompressed files and metadata,
    using the given zlib parameters for DEFLATE entries.
    """
    entries = _parse_metadata(metadata_line)
    profile = profile or COMPRESSION_PROFILES[0]

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
            comp = _compress_raw_deflate(raw, profile, pol.get('flush_offsets', ()),
                                         pol.get('break_kind', compression_profiles.BREAK_NONE))
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

def _profile_order(profile_name):
    """
    Try the profile the clean filter recorded first, then the rest.

    The recorded one is not merely a hint: block breaks are fitted against a
    specific profile and mean nothing against another, so for a DM5 pointer this
    is the only candidate that can work. The others still follow, because a
    pointer naming an unknown profile should degrade to a search rather than
    fail outright.
    """
    if not profile_name:
        return COMPRESSION_PROFILES
    named = compression_profiles.BY_NAME.get(profile_name)
    if named is None:
        logging.warning(f"Pointer names unknown profile {profile_name!r}; searching instead")
        return COMPRESSION_PROFILES
    logging.info(f"Pointer records profile {compression_profiles.describe(named)}")
    return [named] + [p for p in COMPRESSION_PROFILES if p['name'] != profile_name]


def recompress_docx(input_dir: Path, metadata_line: str, expected_hash: str,
                    profile_name: str = None) -> Tuple[bytes, str, dict]:
    """
    Deterministically recompress docx from pointer file metadata by trying each
    entry of COMPRESSION_PROFILES until the whole-archive SHA256 matches.
    Return (docx_bytes, matched_profile_name, meta); the name is "none" when
    nothing reproduced the original, in which case the bytes are best-effort.
    """
    fallback = None
    for profile in _profile_order(profile_name):
        try:
            docx_bytes = build_docx_bytes(input_dir, metadata_line, profile=profile)
        except Exception as e:
            logging.warning(f"Profile {profile['name']} raised: {e}")
            continue
        sha = calculate_sha256(docx_bytes)
        logging.info(f"Profile {profile['name']} SHA256={sha}")
        meta = {"profile": profile, "level": profile.get("level"),
                "memLevel": profile.get("memlevel"), "sha": sha}
        if expected_hash and sha == expected_hash:
            logging.info(f"Profile {profile['name']} matched expected hash.")
            return docx_bytes, profile["name"], meta
        if fallback is None:
            fallback = (docx_bytes, meta)

    logging.warning("No recompression profile matched the expected hash; emitting best effort.")
    if fallback is None:
        return b"", "none", {"profile": None, "level": None, "memLevel": None, "sha": ""}
    return fallback[0], "none", fallback[1]


def recreate_docx(repo, tree_oid: str, expected_hash: str, metadata_line: str,
                  profile_name: str = None, path: str = "<unknown>"):
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
    logging.info(f"Creating document from parts tree {tree_oid}")
    try:
        obj = repo[tree_oid]
    except (KeyError, ValueError) as e:
        raise LookupError(
            f"parts tree {tree_oid} is not in this repository ({e}). The clone may "
            f"be missing refs/docx/*; run install.py and 'git fetch'.") from e

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

        # Compress folder to recreate the original docx:
        docx_bytes, profile, meta = recompress_docx(tmp_path, metadata_line, expected_hash,
                                                    profile_name)

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
        sys.stderr.write(f"[docx smudge] {path}: profile={profile}\n")
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
    if not data.startswith(POINTER_MAGIC.encode("ascii")):
        logging.info("Not a docx pointer (%d bytes); passing through unchanged", len(data))
        sys.stdout.buffer.write(data)
        return

    headers, metadata_line = {}, None
    for raw in data.decode("utf-8", "replace").splitlines():
        line = raw.strip()
        if line.startswith("ENTRIES_BASE85"):
            metadata_line = line
            break
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()

    tree_oid = headers.get("TREE")
    expected_hash = headers.get("HASH")
    if not tree_oid or metadata_line is None:
        logging.error("Malformed pointer: %r", data[:120])
        sys.stderr.write("smudge_filter.py: pointer has no TREE or no entry table\n")
        sys.exit(1)

    try:
        repo = repo_from_cwd()
        recreate_docx(repo, tree_oid, expected_hash, metadata_line,
                      headers.get("PROFILE"), path)
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