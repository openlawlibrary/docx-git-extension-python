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

Z_OK, Z_STREAM_END, Z_BLOCK, Z_BUF_ERROR = 0, 1, 5, -5

# Input is fed to the compressor in pieces of this size, so output appears as
# blocks complete and a comparison against the original can stop at the first
# block that differs. Splitting the input does not change zlib's output: with
# Z_NO_FLUSH it waits for enough lookahead before every decision.
STREAM_CHUNK = 1 << 16

# Bit 7 of z_stream.data_type: inflate() stopped right after an end-of-block code.
_DATA_TYPE_BLOCK_END = 128


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
            lib.inflateCopy.argtypes = [ctypes.POINTER(_ZStream), ctypes.POINTER(_ZStream)]
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


def scan_boundaries(comp: bytes, usize: int, partial: bool = False) -> Tuple[int, ...]:
    """
    Uncompressed offset of EVERY deflate block end in the stream, in order,
    duplicates included.

    inflate() with Z_BLOCK stops at every block boundary and reports how much it
    has produced, which is exactly the number wanted, at C speed. Walking the
    Huffman symbols in Python gives the same answer about 300x slower.

    Duplicates are information, not noise: a block that produces no output is an
    empty block, which is the footprint Z_SYNC_FLUSH and Z_FULL_FLUSH leave
    behind. `has_empty_blocks` reads them.

    With `partial`, `comp` may be a prefix of a stream: scanning stops where the
    input runs out and returns the boundaries of the blocks that were complete.
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
            if partial and (rc == Z_BUF_ERROR or s.avail_in == 0):
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


def empty_blocks(comp: bytes, usize: int) -> Tuple[bool, Tuple[int, ...]]:
    """
    One scan, two answers: (any empty block at all, flush offsets as returned
    by flush_offsets()). An empty block anywhere - including the trailing one
    a sync flush leaves - rules out every plain zlib profile, which never
    writes one.
    """
    offs = scan_boundaries(comp, usize)
    dups = {offs[i] for i in range(1, len(offs)) if offs[i] == offs[i - 1]}
    return bool(dups), tuple(sorted(o for o in dups if o != usize))


def flush_offsets(comp: bytes, usize: int) -> Tuple[int, ...]:
    """
    Uncompressed offsets of the empty blocks inside a stream - Word's piece
    boundaries - excluding the structural flush at the very end.

    Same answer as msword_compressor.detect_flush_offsets() for Word streams,
    read with libz instead of a Python bit walker (that walker was most of a
    clean's time on documents with large deflated images).
    """
    offs = scan_boundaries(comp, usize)
    return tuple(sorted({offs[i] for i in range(1, len(offs))
                         if offs[i] == offs[i - 1] and offs[i] != usize}))


def iter_compress_with_breaks(data: bytes, breaks=(), level: int = 5,
                              memlevel: int = 8, strategy: int = 0):
    """compress_with_breaks(), yielding output as it is produced."""
    co = zlib.compressobj(level, zlib.DEFLATED, -15, memlevel, strategy)
    prev = 0
    for off in tuple(breaks) + (len(data),):
        if off < prev or off > len(data):
            raise ValueError(f'block break {off} out of order or past end of data')
        for i in range(prev, off, STREAM_CHUNK):
            out = co.compress(data[i:min(i + STREAM_CHUNK, off)])
            if out:
                yield out
        if off < len(data):
            yield co.flush(zlib.Z_BLOCK)
        prev = off
    yield co.flush(zlib.Z_FINISH)


def stream_matches(chunks, target: bytes) -> bool:
    """
    True when the chunks a compressor yields add up to exactly `target`.
    Stops at the first chunk that disagrees, so a wrong profile usually costs
    one block of compression instead of the whole entry.
    """
    pos = 0
    try:
        for c in chunks:
            if target[pos:pos + len(c)] != c:
                return False
            pos += len(c)
        return pos == len(target)
    finally:
        close = getattr(chunks, 'close', None)
        if close:
            close()


def matching_prefix(chunks, target: bytes) -> int:
    """How many leading bytes of `target` the compressor reproduces (early exit)."""
    pos = 0
    try:
        for c in chunks:
            n = len(c)
            if target[pos:pos + n] != c:
                return pos + _common_prefix(c, target[pos:pos + n])
            pos += n
        return pos
    finally:
        close = getattr(chunks, 'close', None)
        if close:
            close()


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


class _Inflater:
    """
    inflate() over a stream that arrives in pieces, reporting every block end.

    Fed bytes are consumed exactly once, and copy() snapshots the decoder
    (inflateCopy), so a caller can keep one decoder parked at a point it trusts
    and try different continuations from there without re-reading the prefix.
    That is what keeps the break fitter linear: re-reading the whole output on
    every round made it quadratic in the number of breaks.
    """

    def __init__(self, lib, usize: int, _copy_of: "_Inflater" = None):
        self.lib = lib
        self.s = _ZStream()
        if _copy_of is None:
            # One output buffer for a decoder and all its copies. inflate()
            # back-references its own window, not this buffer, across calls, so
            # copies writing over each other's later output is harmless.
            self.dst = (ctypes.c_ubyte * max(usize, 1))()
            rc = lib.inflateInit2_(ctypes.byref(self.s), -15, b'1.2.11', ctypes.sizeof(_ZStream))
            if rc != Z_OK:
                raise RuntimeError(f'inflateInit2 failed: {rc}')
            self.s.next_out = ctypes.cast(self.dst, ctypes.c_void_p)
            self.s.avail_out = usize
        else:
            self.dst = _copy_of.dst
            rc = lib.inflateCopy(ctypes.byref(self.s), ctypes.byref(_copy_of.s))
            if rc != Z_OK:
                raise RuntimeError(f'inflateCopy failed: {rc}')
        self.ended = False

    def copy(self) -> "_Inflater":
        return _Inflater(self.lib, 0, _copy_of=self)

    def feed(self, data) -> list:
        """Consume `data`; return the uncompressed offset of each block end seen."""
        ends = []
        if self.ended or not data:
            return ends
        src = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        self.s.next_in = ctypes.cast(src, ctypes.c_void_p)
        self.s.avail_in = len(data)
        while True:
            rc = self.lib.inflate(ctypes.byref(self.s), Z_BLOCK)
            if rc == Z_STREAM_END:
                self.ended = True
                break
            if rc == Z_BUF_ERROR:
                break                    # needs more input than it has
            if rc != Z_OK:
                raise RuntimeError(f'inflate failed: {rc}')
            if self.s.data_type & _DATA_TYPE_BLOCK_END:
                ends.append(int(self.s.total_out))
            if self.s.avail_in == 0:
                break
        self.s.next_in = None            # src goes away with this frame
        return ends

    def close(self):
        if self.s.state:
            self.lib.inflateEnd(ctypes.byref(self.s))


def fit_breaks(data: bytes, target: bytes, usize: int, level: int = 5,
               memlevel: int = 8, strategy: int = 0,
               rounds: Optional[int] = None) -> Optional[Tuple[int, ...]]:
    """
    Find the minimal set of forced breaks that reproduces `target` byte for byte,
    or None when this profile cannot produce it at all.

    Only the breaks zlib would NOT have chosen are recorded. That matters:
    forcing a break where zlib already breaks is not a no-op - the flush resets
    the lazy-match state and shifts every later boundary - so recording all of
    them produces a different stream.

    Each round confirms one break or rejects the profile, and the work of a
    round is proportional to the stretch since the last confirmed break:
      * the compressor state after the last confirmed break is kept, so a round
        never recompresses what is already settled;
      * a round stops compressing at the first byte that differs from the
        original, which is normally within one block;
      * our framing is read by a decoder parked at the last confirmed break
        (see _Inflater), never by re-reading the output from its start.

    No round limit is needed: every round either returns or confirms one of the
    original's block ends, in increasing order, so there are at most
    len(original block ends) + 1 rounds. `rounds` can still cap it.
    """
    lib = _load_libz()
    if lib is None:
        return None
    try:
        want = block_ends(target, usize)
    except Exception as e:
        logging.debug(f'block_breaks: cannot scan target: {e}')
        return None
    n = len(data)
    tv = memoryview(target)
    limit = len(want) + 1 if rounds is None else rounds

    breaks = []
    snap = zlib.compressobj(level, zlib.DEFLATED, -15, memlevel, strategy)
    snap_in = 0                  # input consumed up to the last confirmed break
    snap_len = 0                 # output produced up to it - equal to target[:snap_len]
    parked = _Inflater(lib, usize)   # has read exactly target[:snap_len]
    try:
        for _ in range(limit):
            # Resume after the last confirmed break and stop at the first difference.
            co = snap.copy()
            new = bytearray()        # output after target[:snap_len]
            pos = snap_in
            finished = False
            diverged = False
            while pos < n and not diverged:
                c = co.compress(data[pos:pos + STREAM_CHUNK])
                pos = min(pos + STREAM_CHUNK, n)
                if c:
                    at = snap_len + len(new)
                    diverged = tv[at:at + len(c)] != c
                    new += c
            if not diverged:
                new += co.flush(zlib.Z_FINISH)
                finished = True
                if snap_len + len(new) == len(target) and tv[snap_len:] == new:
                    return tuple(breaks)

            # Where does our framing first differ from the original's? zlib writes a
            # block out whole when it ends, but the last few bits of the newest block
            # can still be held back, so keep feeding input until that block's end is
            # visible (or the input runs out) before deciding.
            W = [w for w in want if w > snap_in]
            probe = parked.copy()
            try:
                seen, fed = set(), 0
                while True:
                    try:
                        seen.update(o for o in probe.feed(new[fed:]) if snap_in < o < usize)
                    except Exception:
                        return None
                    fed = len(new)
                    H = sorted(seen)
                    k = 0
                    while k < len(W) and k < len(H) and W[k] == H[k]:
                        k += 1
                    if k < len(H) or finished:
                        break
                    if pos < n:
                        new += co.compress(data[pos:pos + STREAM_CHUNK])
                        pos = min(pos + STREAM_CHUNK, n)
                    else:
                        new += co.flush(zlib.Z_FINISH)
                        finished = True
            finally:
                probe.close()

            if k >= len(W):
                return None              # zlib ends a block the original does not: can't fix
            if k < len(H) and H[k] < W[k]:
                return None              # zlib ends a block sooner than the original did;
                                         # forcing breaks can only make blocks shorter
            if k < len(H) and H[k] == W[k]:
                return None              # same framing, different bytes: the knobs are wrong
            nxt = W[k]

            # Force the original's block end and confirm the bytes up to it.
            co = snap.copy()
            piece = bytearray()
            for i in range(snap_in, nxt, STREAM_CHUNK):
                piece += co.compress(data[i:min(i + STREAM_CHUNK, nxt)])
            piece += co.flush(zlib.Z_BLOCK)
            if tv[snap_len:snap_len + len(piece)] != piece:
                return None              # even with the break the bytes differ: wrong profile
            breaks.append(nxt)
            parked.feed(piece)
            snap, snap_in, snap_len = co, nxt, snap_len + len(piece)
        logging.debug(f'block_breaks: no fit after {limit} rounds')
        return None
    finally:
        parked.close()


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