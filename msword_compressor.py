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
   and unpredictable, so clean reads them off the original
   (block_breaks.empty_blocks) and the pointer carries them.

Verified byte-for-byte against Word output on all 11 parts of a reference
document. Each of memLevel 7, max_lazy 4, nice_length 258 and max_chain 32 is
required: the neighbouring value in either direction diverges. `level` may be
anything in 4..9 (all of them select `deflate_slow`, and `deflateTune` replaces
the rest of the row); `good_length` is unreachable while max_lazy is 4, because
a match search only runs when the previous match is shorter than max_lazy.
"""

from __future__ import annotations
import ctypes
import zlib
from typing import Optional

import block_breaks
from block_breaks import STREAM_CHUNK, ZStream

# === MS Word / OPC deflate configuration ===
MSWORD_LEVEL        = 6      # any of 4..9 selects deflate_slow
MSWORD_WINDOW_BITS  = -15    # raw deflate, no zlib wrapper
MSWORD_MEM_LEVEL    = 7      # 16 KiB hash table, not zlib's default 8
MSWORD_GOOD_LENGTH  = 8      # unreachable while MAX_LAZY == 4
MSWORD_MAX_LAZY     = 4      # take any match of 4+ bytes immediately
MSWORD_NICE_LENGTH  = 258
MSWORD_MAX_CHAIN    = 32     # inspect only 32 candidates per hash bucket

Z_OK, Z_STREAM_END = 0, 1   # not exported by the Python zlib module
_CHUNK = 1 << 16            # output buffer size


def _load_libz() -> Optional[ctypes.CDLL]:
    """The shared zlib (block_breaks.load_libz), when it has deflateTune."""
    lib = block_breaks.load_libz()
    return lib if lib is not None and hasattr(lib, 'deflateTune') else None


def is_available() -> bool:
    """True when this profile can run on the current host."""
    return _load_libz() is not None


def iter_compress_msword(data: bytes, flush_offsets: tuple = ()):
    """
    Raw DEFLATE stream for one OPC part, byte-identical to Microsoft Word's,
    yielded as it is produced, so a comparison against the original can stop
    at the first block that differs.

    `flush_offsets` are byte positions in `data` where Word's writer issued an
    extra Z_FULL_FLUSH because it handed the packager the part in more than one
    piece. They are content-dependent (Word flushes at logical XML boundaries,
    not at round buffer sizes), so they cannot be predicted - clean reads them
    off the original stream (block_breaks.empty_blocks) and the pointer carries
    them (ENTRY flush=).

    Each piece is fed in STREAM_CHUNK slices with Z_NO_FLUSH and then flushed;
    deflate's output does not depend on how its input is sliced.
    """
    lib = _load_libz()
    if lib is None:
        raise RuntimeError('MS Word profile needs a shared zlib (Windows: zlib1.dll)')

    z = ZStream()
    rc = lib.deflateInit2_(ctypes.byref(z), MSWORD_LEVEL, zlib.DEFLATED,
                           MSWORD_WINDOW_BITS, MSWORD_MEM_LEVEL, zlib.Z_DEFAULT_STRATEGY,
                           lib.zlibVersion(), ctypes.sizeof(ZStream))
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
        plan = []
        for pc in pieces:
            for i in range(0, len(pc), STREAM_CHUNK):
                plan.append((pc[i:i + STREAM_CHUNK], 0))          # Z_NO_FLUSH
            plan.append((b'', zlib.Z_FULL_FLUSH))
        plan.append((b'', zlib.Z_FINISH))

        dst = ctypes.create_string_buffer(_CHUNK)
        for piece, flush in plan:
            src = ctypes.create_string_buffer(piece, max(len(piece), 1))
            z.next_in, z.avail_in = ctypes.cast(src, ctypes.c_void_p), len(piece)
            while True:
                z.next_out, z.avail_out = ctypes.cast(dst, ctypes.c_void_p), _CHUNK
                rc = lib.deflate(ctypes.byref(z), flush)
                if rc < 0 and not (rc == -5 and flush == 0):   # Z_BUF_ERROR: nothing to do yet
                    raise RuntimeError(f'deflate failed: {rc} ({z.msg})')
                produced = _CHUNK - z.avail_out
                if produced:
                    yield dst.raw[:produced]
                if flush == zlib.Z_FINISH:
                    if rc == Z_STREAM_END:
                        break
                elif z.avail_out != 0:
                    # NO_FLUSH: input consumed; FULL_FLUSH: done when the
                    # buffer stopped filling.
                    break
    finally:
        lib.deflateEnd(ctypes.byref(z))
