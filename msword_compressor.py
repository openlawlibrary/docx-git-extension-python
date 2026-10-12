#!/usr/bin/env python3
"""
msword_compressor.py

Deterministic recompression profile for docx files written by Microsoft Word
(and by anything else built on OPC / System.IO.Packaging).

Word does use zlib, but it cannot be reproduced through `zlib.compressobj`,
for two independent reasons:

1. Word's build of zlib carries its own `configuration_table` row. It runs
   `deflate_slow`, but with max_lazy=4 / max_chain=32 / nice_length=258 and a
   16 KiB hash table (memLevel 7) - a combination none of zlib's nine stock
   levels uses. Those four values are only reachable through `deflateTune()`,
   which the Python zlib module does not expose, so this module binds libz
   directly through ctypes.

2. The OPC packager flushes every piece it is handed with `Z_FULL_FLUSH` and
   then closes with `Z_FINISH`. For the usual one-piece part that emits one
   dynamic block, an empty stored block (00 00 00 FF FF) and a final empty
   fixed block - three blocks where a plain `flush(Z_FINISH)` emits one. It
   costs 7 bytes per part and is the easiest way to recognise an OPC container.

   Word sometimes hands the packager a part in several pieces, flushing at a
   logical XML boundary (in one sample, `document.xml` split at 9941 bytes
   between `</v:shapetype>` and the following `<v:shape>`). Because
   `Z_FULL_FLUSH` also resets the dictionary, the later piece cannot reference
   the earlier one and the part compresses *worse* than a single pass would -
   4576 bytes where one pass gives 4207. The boundaries are content-dependent
   and unpredictable, so read them off the original with
   detect_flush_offsets() and carry them in metadata.

Verified byte-for-byte against Word output on all 11 parts of a reference
document. Each of memLevel 7, max_lazy 4, nice_length 258 and max_chain 32 is
required: the neighbouring value in either direction diverges. `level` may be
anything in 4..9 (all of them select `deflate_slow`, and `deflateTune` replaces
the rest of the row); `good_length` is unreachable while max_lazy is 4, because
a match search only runs when the previous match is shorter than max_lazy.
"""

from __future__ import annotations
import ctypes
import ctypes.util
import logging
import zlib
from typing import Optional

# === MS Word / OPC deflate configuration ===
MSWORD_LEVEL        = 6      # any of 4..9 selects deflate_slow
MSWORD_WINDOW_BITS  = -15    # raw deflate, no zlib wrapper
MSWORD_MEM_LEVEL    = 7      # 16 KiB hash table, not zlib's default 8
MSWORD_GOOD_LENGTH  = 8      # unreachable while MAX_LAZY == 4
MSWORD_MAX_LAZY     = 4      # take any match of 4+ bytes immediately
MSWORD_NICE_LENGTH  = 258
MSWORD_MAX_CHAIN    = 32     # inspect only 32 candidates per hash bucket

Z_OK, Z_STREAM_END = 0, 1   # not exported by the Python zlib module
_CHUNK = 1 << 16


class _ZStream(ctypes.Structure):
    """zlib's z_stream, as laid out by the platform C compiler."""
    _fields_ = [
        ('next_in',   ctypes.c_void_p), ('avail_in',  ctypes.c_uint),
        ('total_in',  ctypes.c_ulong),  ('next_out',  ctypes.c_void_p),
        ('avail_out', ctypes.c_uint),   ('total_out', ctypes.c_ulong),
        ('msg',       ctypes.c_char_p), ('state',     ctypes.c_void_p),
        ('zalloc',    ctypes.c_void_p), ('zfree',     ctypes.c_void_p),
        ('opaque',    ctypes.c_void_p), ('data_type', ctypes.c_int),
        ('adler',     ctypes.c_ulong),  ('reserved',  ctypes.c_ulong),
    ]


_libz: Optional[ctypes.CDLL] = None
_libz_loaded = False


def _load_libz() -> Optional[ctypes.CDLL]:
    """
    Bind libz once, lazily. Returns None when no shared zlib is reachable, so
    callers can skip this profile instead of failing the whole smudge.
    """
    global _libz, _libz_loaded
    if _libz_loaded:
        return _libz
    _libz_loaded = True
    for name in (ctypes.util.find_library('z'), 'libz.so.1', 'libz.dylib', 'zlib1.dll'):
        if not name:
            continue
        try:
            lib = ctypes.CDLL(name)
        except OSError:
            continue
        lib.deflateInit2_.argtypes = [ctypes.POINTER(_ZStream)] + [ctypes.c_int] * 5 + \
                                     [ctypes.c_char_p, ctypes.c_int]
        lib.deflateTune.argtypes   = [ctypes.POINTER(_ZStream)] + [ctypes.c_int] * 4
        lib.deflate.argtypes       = [ctypes.POINTER(_ZStream), ctypes.c_int]
        lib.deflateEnd.argtypes    = [ctypes.POINTER(_ZStream)]
        lib.zlibVersion.restype    = ctypes.c_char_p
        if not hasattr(lib, 'deflateTune'):
            continue
        _libz = lib
        logging.debug(f'msword_compressor: bound {name}, zlib {lib.zlibVersion().decode()}')
        return _libz
    logging.warning('msword_compressor: no shared zlib found; MS Word profile unavailable')
    return None


def is_available() -> bool:
    """True when this profile can run on the current host."""
    return _load_libz() is not None


def compress_raw_deflate_msword(data: bytes, flush_offsets: tuple = ()) -> bytes:
    """
    Raw DEFLATE stream for one OPC part, byte-identical to Microsoft Word's.

    `flush_offsets` are byte positions in `data` where Word's writer issued an
    extra Z_FULL_FLUSH because it handed the packager the part in more than one
    piece. They are content-dependent (Word flushes at logical XML boundaries,
    not at round buffer sizes), so they cannot be predicted - read them off the
    original stream with detect_flush_offsets() and carry them in metadata.

    Raises RuntimeError when no shared zlib is available; guard with
    is_available() if you want to skip the profile instead.
    """
    lib = _load_libz()
    if lib is None:
        raise RuntimeError('MS Word profile needs a shared zlib (Windows: zlib1.dll)')

    z = _ZStream()
    rc = lib.deflateInit2_(ctypes.byref(z), MSWORD_LEVEL, zlib.DEFLATED,
                           MSWORD_WINDOW_BITS, MSWORD_MEM_LEVEL, zlib.Z_DEFAULT_STRATEGY,
                           lib.zlibVersion(), ctypes.sizeof(_ZStream))
    if rc != 0:
        raise RuntimeError(f'deflateInit2 failed: {rc}')
    try:
        rc = lib.deflateTune(ctypes.byref(z), MSWORD_GOOD_LENGTH, MSWORD_MAX_LAZY,
                             MSWORD_NICE_LENGTH, MSWORD_MAX_CHAIN)
        if rc != 0:
            raise RuntimeError(f'deflateTune failed: {rc}')

        # one FULL_FLUSH per piece, then FINISH. FULL_FLUSH (not SYNC_FLUSH):
        # it also resets the dictionary, so a piece cannot reference the piece
        # before it. Indistinguishable from SYNC_FLUSH for a single-piece part,
        # but it is what Word does, and it costs real ratio on split parts.
        bounds = list(flush_offsets) + [len(data)]
        pieces = [data[a:b] for a, b in zip([0] + bounds, bounds)]

        dst = ctypes.create_string_buffer(_CHUNK)
        out = bytearray()
        held = []          # keep buffers alive while zlib holds pointers into them
        plan = [(pc, zlib.Z_FULL_FLUSH) for pc in pieces] + [(b'', zlib.Z_FINISH)]
        for piece, flush in plan:
            src = ctypes.create_string_buffer(piece, max(len(piece), 1))
            held.append(src)
            z.next_in, z.avail_in = ctypes.cast(src, ctypes.c_void_p), len(piece)
            while True:
                z.next_out, z.avail_out = ctypes.cast(dst, ctypes.c_void_p), _CHUNK
                rc = lib.deflate(ctypes.byref(z), flush)
                if rc < 0:
                    raise RuntimeError(f'deflate failed: {rc} ({z.msg})')
                out += dst.raw[:_CHUNK - z.avail_out]
                # SYNC_FLUSH is done when it stops filling the buffer;
                # FINISH is done when it returns Z_STREAM_END.
                if (rc == Z_STREAM_END) if flush == zlib.Z_FINISH else (z.avail_out != 0):
                    break
        return bytes(out)
    finally:
        lib.deflateEnd(ctypes.byref(z))


def looks_like_opc(entries: list) -> bool:
    """
    Cheap pre-check on the unpacked pointer-file entries: OPC writers stamp
    every member with a 1980-01-01 DOS date, GPF 0x0006 and "version made by"
    45, and reserve growth-hint padding (extra field 0xA220) on the content
    types stream. Use it to try this profile first and skip it fast.
    """
    if not entries:
        return False
    for ent in entries:
        lfh, cd = ent['lfh'], ent['cd']
        if lfh['dos_date'] != 0x0021 or lfh['dos_time'] != 0x0000:
            return False
        if lfh['flags'] != 0x0006 or cd['version_made_by'] != 45:
            return False
    return any(ent['lfh']['extra_lfh'][:2] == b'\x20\xa2' for ent in entries)


# --- reading Word's piece boundaries back off an existing stream ---------------
_LEN_BASE  = (3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258)
_LEN_EXTRA = (0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0)
_DIST_EXTRA= (0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13)
_CL_ORDER  = (16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15)


class _Bits:
    __slots__ = ('b', 'p')

    def __init__(self, b):
        self.b, self.p = b, 0

    def bit(self):
        v = (self.b[self.p >> 3] >> (self.p & 7)) & 1
        self.p += 1
        return v

    def bits(self, n):
        v = 0
        for i in range(n):
            v |= self.bit() << i
        return v


def _canonical(lengths):
    """Map (bit-length, code) -> symbol for a canonical Huffman code."""
    table, code = {}, 0
    for ln in range(1, (max(lengths) if lengths else 0) + 1):
        for sym, l in enumerate(lengths):
            if l == ln:
                table[(ln, code)] = sym
                code += 1
        code <<= 1
    return table


def _decode(br, table):
    code = length = 0
    while length <= 15:
        code = (code << 1) | br.bit()
        length += 1
        if (length, code) in table:
            return table[(length, code)]
    raise ValueError('bad Huffman code')


def detect_flush_offsets(comp: bytes) -> tuple:
    """
    Read Word's mid-part Z_FULL_FLUSH positions off an existing raw DEFLATE
    stream, so the clean/extract side can record them.

    An OPC stream ends `empty stored block, empty final fixed block`. Any
    *earlier* empty stored block is a piece boundary. Returns byte offsets into
    the uncompressed data, excluding the trailing flush - so `()` for the usual
    single-piece part.
    """
    br = _Bits(comp)
    produced = 0
    offsets: list = []
    while True:
        final = br.bit()
        btype = br.bits(2)
        if btype == 0:
            br.p = (br.p + 7) & ~7
            i = br.p >> 3
            ln = comp[i] | (comp[i + 1] << 8)
            br.p += 32 + ln * 8
            if ln == 0 and not final:
                offsets.append(produced)
            produced += ln
        else:
            if btype == 1:
                lit = _canonical([8] * 144 + [9] * 112 + [7] * 24 + [8] * 8)
                dist = _canonical([5] * 30)
            elif btype == 2:
                hlit, hdist, hclen = br.bits(5) + 257, br.bits(5) + 1, br.bits(4) + 4
                cl = [0] * 19
                for k in range(hclen):
                    cl[_CL_ORDER[k]] = br.bits(3)
                clt = _canonical(cl)
                lens: list = []
                while len(lens) < hlit + hdist:
                    s = _decode(br, clt)
                    if s < 16:
                        lens.append(s)
                    elif s == 16:
                        lens += [lens[-1]] * (br.bits(2) + 3)
                    elif s == 17:
                        lens += [0] * (br.bits(3) + 3)
                    else:
                        lens += [0] * (br.bits(7) + 11)
                lit, dist = _canonical(lens[:hlit]), _canonical(lens[hlit:])
            else:
                raise ValueError('reserved DEFLATE block type')
            while True:
                sym = _decode(br, lit)
                if sym == 256:
                    break
                if sym < 256:
                    produced += 1
                else:
                    i = sym - 257
                    produced += _LEN_BASE[i] + br.bits(_LEN_EXTRA[i])
                    d = _decode(br, dist)
                    br.bits(_DIST_EXTRA[d])
        if final:
            break
    # the flush that precedes the final empty block is structural, not a piece
    return tuple(o for o in offsets if o != produced)
