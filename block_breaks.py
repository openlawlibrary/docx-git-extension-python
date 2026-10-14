#!/usr/bin/env python3
"""
block_breaks.py - reproduce deflate streams whose block boundaries are not zlib's.

WHY THIS EXISTS

Some packagers drive zlib with the stock knobs but cut deflate blocks early.
The LZ77 decisions are then identical to plain zlib - same literals, same
matches, same distances - and only the framing differs, so no (level, memLevel,
strategy) combination reproduces the bytes however long you search for one.

The tell is a block that ends at a symbol count other than zlib's own
`lit_bufsize - 1` (16383 at memLevel 8), with no empty stored or fixed block
anywhere in the stream. An empty block is the footprint of Z_SYNC_FLUSH,
Z_FULL_FLUSH or Z_PARTIAL_FLUSH; Z_BLOCK is the one flush that ends a block and
leaves nothing behind. Replaying Z_BLOCK at the recorded offsets restores the
original framing exactly.

WHAT IT COSTS

A handful of integers per entry. A 17 MB document with 46 entries needed 58
offsets - 220 bytes delta-encoded, 0.0013% of the archive.

TWO HALVES, DIFFERENT REQUIREMENTS

  fit_breaks()  runs in the CLEAN filter, where the original bytes are still in
                hand. It needs libz, because it finds boundaries by driving
                inflate() with Z_BLOCK. Without libz it returns None and the
                caller falls back to the existing behaviour.

  compress_with_breaks()  runs in the SMUDGE filter. It uses only the Python
                zlib module, so a rebuild works on hosts with no shared libz.
                That asymmetry is deliberate: checkout must not depend on a
                library that packing happened to have.

NEVER RECORD WHAT YOU HAVE NOT VERIFIED. fit_breaks() rebuilds and compares
before returning; a near miss comes back as None, not as a recipe.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import zlib
from typing import Optional, Tuple

Z_OK, Z_STREAM_END, Z_BLOCK = 0, 1, 5

# How many rounds the fitter may take before giving up on an entry. Each round
# pins down one forced break; real producers need a few per megabyte.
FIT_ROUNDS = 256


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
    Bind libz once, lazily. Only the inflate side is needed here; this is kept
    separate from msword_compressor's binding on purpose, because that one
    insists on deflateTune and this one must work without it.
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
        try:
            lib.inflateInit2_.argtypes = [ctypes.POINTER(_ZStream), ctypes.c_int,
                                          ctypes.c_char_p, ctypes.c_int]
            lib.inflate.argtypes = [ctypes.POINTER(_ZStream), ctypes.c_int]
            lib.inflateEnd.argtypes = [ctypes.POINTER(_ZStream)]
            lib.zlibVersion.restype = ctypes.c_char_p
        except AttributeError:
            continue
        _libz = lib
        logging.debug(f'block_breaks: bound {name}, zlib {lib.zlibVersion().decode()}')
        return _libz
    logging.warning('block_breaks: no shared zlib found; block-break fitting unavailable')
    return None


def is_available() -> bool:
    """True when boundaries can be scanned on this host (clean side only)."""
    return _load_libz() is not None


def supports_z_block() -> bool:
    """
    True when this Python's zlib accepts Z_BLOCK in compressobj.flush(). Checked
    rather than assumed: without it a rebuild silently produces natural framing,
    which fails the hash at checkout instead of at pack time.
    """
    try:
        co = zlib.compressobj(6, zlib.DEFLATED, -15, 8, 0)
        co.compress(b'probe')
        co.flush(zlib.Z_BLOCK)
        co.flush(zlib.Z_FINISH)
        return True
    except Exception as e:                       # pragma: no cover - host dependent
        logging.warning(f'block_breaks: Z_BLOCK unusable in this Python: {e}')
        return False


def scan_boundaries(comp: bytes, usize: int) -> Tuple[int, ...]:
    """
    Uncompressed offset of EVERY deflate block end in the stream, in order,
    duplicates included.

    inflate() with Z_BLOCK stops at every block boundary and reports how much it
    has produced, which is exactly the number wanted, at C speed. Walking the
    Huffman symbols in Python gives the same answer about 300x slower.

    Duplicates are information, not noise: a block that produces no output is an
    empty block, which is the footprint Z_SYNC_FLUSH and Z_FULL_FLUSH leave
    behind. `has_empty_blocks` reads them.
    """
    if usize <= 0 or not comp:
        return ()
    lib = _load_libz()
    if lib is None:
        return ()

    s = _ZStream()
    rc = lib.inflateInit2_(ctypes.byref(s), -15, b'1.2.11', ctypes.sizeof(_ZStream))
    if rc != Z_OK:
        raise RuntimeError(f'inflateInit2 failed: {rc}')
    try:
        src = (ctypes.c_ubyte * len(comp)).from_buffer_copy(comp)
        dst = (ctypes.c_ubyte * usize)()
        s.next_in = ctypes.cast(src, ctypes.c_void_p)
        s.avail_in = len(comp)
        s.next_out = ctypes.cast(dst, ctypes.c_void_p)
        s.avail_out = usize

        offs = []
        last = (-1, -1)
        while True:
            rc = lib.inflate(ctypes.byref(s), Z_BLOCK)
            if rc == Z_STREAM_END:
                break
            if rc != Z_OK:
                raise RuntimeError(f'inflate failed: {rc}')
            here = (int(s.total_in), int(s.total_out))
            if here == last:
                # Neither input consumed nor output produced: a truncated or
                # malformed stream. Bail rather than spin; the caller treats
                # this as "cannot model". An empty block still advances
                # total_in, so this does not fire on a legitimate flush.
                raise RuntimeError('inflate made no progress')
            last = here
            offs.append(here[1])
        return tuple(offs)
    finally:
        lib.inflateEnd(ctypes.byref(s))


def block_ends(comp: bytes, usize: int) -> Tuple[int, ...]:
    """Distinct interior block boundaries - what the break fitter compares on."""
    seen, out = set(), []
    for o in scan_boundaries(comp, usize):
        if 0 < o < usize and o not in seen:
            seen.add(o)
            out.append(o)
    return tuple(out)


def has_empty_blocks(comp: bytes, usize: int) -> bool:
    """
    True when the stream contains a block that produced no output.

    Used to skip the expensive Python flush scan: no empty block anywhere means
    no Z_FULL_FLUSH anywhere, so the flush-offset list is necessarily empty.
    Equivalent to the slow answer, obtained roughly 300x faster.
    """
    offs = scan_boundaries(comp, usize)
    return any(offs[i] == offs[i - 1] for i in range(1, len(offs)))


def compress_with_breaks(data: bytes, breaks=(), level: int = 5,
                         memlevel: int = 8, strategy: int = 0) -> bytes:
    """
    Raw DEFLATE with a block forced to end at each offset in `breaks`.

    Z_BLOCK ends the block without emitting a marker, which is what makes this
    reproduce the original rather than merely resemble it. Uses only the Python
    zlib module, so the smudge side needs no libz.
    """
    co = zlib.compressobj(level, zlib.DEFLATED, -15, memlevel, strategy)
    out = []
    prev = 0
    for off in breaks:
        if off <= prev or off > len(data):
            raise ValueError(f'block break {off} out of order or past end of data')
        out.append(co.compress(data[prev:off]))
        out.append(co.flush(zlib.Z_BLOCK))
        prev = off
    out.append(co.compress(data[prev:]))
    out.append(co.flush(zlib.Z_FINISH))
    return b''.join(out)


def fit_breaks(data: bytes, target: bytes, usize: int, level: int = 5,
               memlevel: int = 8, strategy: int = 0,
               rounds: int = FIT_ROUNDS) -> Optional[Tuple[int, ...]]:
    """
    Find the minimal set of forced breaks that reproduces `target` byte for byte,
    or None when this profile cannot produce it at all.

    Only the breaks zlib would NOT have chosen are recorded. That matters:
    forcing a break where zlib already breaks is not a no-op - the flush resets
    the lazy-match state and shifts every later boundary - so recording all of
    them produces a different stream.

    The search compares the boundary list zlib currently yields against the one
    wanted, adds the first boundary where they diverge, and repeats. Each round
    pins down one forced break, so it converges in (number of breaks + 1) rounds
    rather than searching any kind of space.
    """
    if not is_available():
        return None
    try:
        want = block_ends(target, usize)
    except Exception as e:
        logging.debug(f'block_breaks: cannot scan target: {e}')
        return None

    breaks: Tuple[int, ...] = ()
    settled = 0          # bytes of output confirmed correct so far
    stalls = 0
    for _ in range(rounds):
        try:
            got = compress_with_breaks(data, breaks, level, memlevel, strategy)
        except Exception as e:
            logging.debug(f'block_breaks: emit failed: {e}')
            return None
        if got == target:
            return breaks                      # verified, not merely plausible
        try:
            here = block_ends(got, usize)
        except Exception:
            return None
        if here == want:
            # Same framing, different bytes: the knobs are wrong, not the breaks.
            return None

        # Each accepted break should lock one more block into place. With the
        # right knobs the agreeing prefix grows every round; with the wrong ones
        # it stalls immediately, which is what rejects a bad profile cheaply
        # rather than letting it run the full round budget.
        pref = _common_prefix(got, target)
        if pref > settled:
            settled, stalls = pref, 0
        else:
            stalls += 1
            if stalls >= 2:
                return None

        i = next((k for k in range(min(len(here), len(want))) if here[k] != want[k]),
                 min(len(here), len(want)))
        if i >= len(want) or want[i] in breaks:
            return None                        # cannot converge; give up cleanly
        breaks = tuple(sorted(breaks + (want[i],)))
    logging.debug(f'block_breaks: no fit after {rounds} rounds')
    return None


def _common_prefix(a: bytes, b: bytes) -> int:
    n = min(len(a), len(b))
    lo, hi = 0, n
    while lo < hi:                             # binary search; the streams are large
        mid = (lo + hi + 1) // 2
        if a[:mid] == b[:mid]:
            lo = mid
        else:
            hi = mid - 1
    return lo