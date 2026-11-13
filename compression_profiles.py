#!/usr/bin/env python3
"""
compression_profiles.py - the one definition of how a DEFLATE entry is rebuilt.

A profile answers "which knobs" - level, memLevel, strategy, or the tuned set
Word uses. It does NOT answer "where were the blocks cut", which is per entry
and data-dependent; that is the break list carried alongside it.

Keeping the two apart is what lets one producer be described by one profile for
the whole archive while each entry carries its own handful of offsets.

The clean filter picks the profile, because only it has the original bytes to
check against. The smudge filter is told which one to use and rebuilds.

BREAK KINDS

  BREAK_NONE  - the entry is plain; zlib's own block boundaries are correct.
  BREAK_FULL  - Z_FULL_FLUSH at each offset. Word's packager hands one part to
                the compressor in pieces; each flush emits an empty stored block
                and resets the dictionary, so the bytes change and the offsets
                must be replayed.
  BREAK_BLOCK - Z_BLOCK at each offset. Ends a block without emitting anything.
                The LZ77 decisions are plain zlib's; only the framing differs,
                which is why no amount of knob-searching finds these.

KINDS

  zlib     the zlib in Python's zlib module; level, memLevel, strategy.
           `tail: sync` = the producer flushed (Z_SYNC_FLUSH) before it
           finished, so every stream ends in an empty stored block and an
           empty final block: 00 00 ff ff 03 00.
  zlib-ng  zlib-ng 2.2 (the zlib-ng Python package; .NET 9 and later use it),
           which compresses differently from zlib at the same level.
  msword   Word's own tuned zlib (msword_compressor.py).

Only plain zlib profiles (no tail) can be paired with block breaks.

WHERE THE PROFILES COME FROM

  python-docx      zlib 6/8: python-docx, Python's zipfile, LibreOffice, Java
                   (Apache POI, docx4j), JSZip (docx on npm), pandoc
  msword           desktop Word
  aspose-ml#1..9   Aspose.Words (zlib 5, memLevel 1..9)
  sharepoint       SharePoint rewriting package parts ([Content_Types].xml,
                   rels, docProps) - zlib 6/9, sync flush before the end
  sharepoint-fast  parts SharePoint adds (customXml/*, docProps/custom.xml,
                   general purpose flags 0x6) - zlib 1/9, sync flush
  word-web         Word for the web saving the document - zlib-ng 6/8
  word-web-fast    parts Word for the web adds (flags 0x6) - zlib-ng 1/8
  infozip-9        Info-ZIP `zip -9` (zlib 9/9, with block breaks); its
                   default -6 matches python-docx except on incompressible
                   parts (images), which go to the fallback

A document may mix them - SharePoint keeps the bytes of the parts it does not
touch - so the clean filter picks a profile per entry; the pointer records the
most used one on its PROFILE line and the others per ENTRY (profile=).

Names are part of the pointer format once written: never rename an entry, and
never change what an existing name produces; add a new name instead.
"""

from __future__ import annotations

import zlib
from typing import Dict, List, Optional, Tuple

import block_breaks
import msword_compressor
from pointer_format import BREAK_NONE, BREAK_FULL, BREAK_BLOCK

try:
    from zlib_ng import zlib_ng           # pip install zlib-ng
except ImportError:                       # word-web profiles unavailable
    zlib_ng = None

BREAK_NAMES = {BREAK_NONE: 'none', BREAK_FULL: 'full_flush', BREAK_BLOCK: 'block'}

PROFILES: List[Dict] = [
    {'name': 'python-docx', 'kind': 'zlib', 'level': 6, 'memlevel': 8, 'strategy': 0},
    {'name': 'msword',      'kind': 'msword'},
] + [
    {'name': f'aspose-ml#{ml}', 'kind': 'zlib', 'level': 5, 'memlevel': ml, 'strategy': 0}
    for ml in range(1, 10)
] + [
    {'name': 'sharepoint',      'kind': 'zlib', 'level': 6, 'memlevel': 9, 'strategy': 0, 'tail': 'sync'},
    {'name': 'sharepoint-fast', 'kind': 'zlib', 'level': 1, 'memlevel': 9, 'strategy': 0, 'tail': 'sync'},
    {'name': 'word-web',        'kind': 'zlib-ng', 'level': 6, 'memlevel': 8, 'strategy': 0},
    {'name': 'word-web-fast',   'kind': 'zlib-ng', 'level': 1, 'memlevel': 8, 'strategy': 0},
    {'name': 'infozip-9',       'kind': 'zlib', 'level': 9, 'memlevel': 9, 'strategy': 0},
]

# How a stream ends when its producer flushed before finishing: an empty stored
# block (00 00 ff ff) and an empty final fixed block (03 00). Word ends its
# parts the same way.
SYNC_TAIL = b'\x00\x00\xff\xff\x03\x00'

BY_NAME = {p['name']: p for p in PROFILES}

# Profiles the break fitter may pair with BREAK_BLOCK: plain zlib only. The
# msword profile has its own flush mechanism; a sync tail and zlib-ng are not
# what the libz-based fitter runs.
def fittable(profile: Dict) -> bool:
    return profile['kind'] == 'zlib' and not profile.get('tail')


def is_available(profile: Dict) -> bool:
    """Whether this machine can run the profile at all."""
    if profile['kind'] == 'msword':
        return msword_compressor.is_available()
    if profile['kind'] == 'zlib-ng':
        return zlib_ng is not None
    return True


def unavailable_reason(profile: Dict) -> Optional[str]:
    if is_available(profile):
        return None
    if profile['kind'] == 'msword':
        return ("the msword profile needs a shared zlib with deflateTune "
                "(Windows: zlib1.dll); none was found")
    return f"the {profile['name']} profile needs zlib-ng: pip install zlib-ng"


def accepts(profile: Dict, shape: str) -> bool:
    """
    Whether `profile` can have produced a stream of this shape (clean_filter's
    stream_shape): 'plain' (no empty block), 'tail' (one empty block, right at
    the end: SYNC_TAIL) or 'flushes' (empty blocks inside). Lets clean skip
    profiles without compressing anything.
    """
    if profile['kind'] == 'msword':
        return shape != 'plain'
    if profile.get('tail') == 'sync':
        return shape == 'tail'
    return shape == 'plain'


def compress_entry(data: bytes, profile: Dict, break_kind: int = BREAK_NONE,
                   breaks: Tuple[int, ...] = ()) -> bytes:
    """Raw DEFLATE for one entry under `profile`, replaying `breaks`."""
    return b''.join(iter_compress_entry(data, profile, break_kind, breaks))


def _iter_plain(module, data: bytes, profile: Dict):
    """One-shot compression with `module` (zlib or zlib_ng), optional sync tail."""
    co = module.compressobj(profile['level'], module.DEFLATED, -15, profile['memlevel'],
                            profile.get('strategy', 0))
    for i in range(0, len(data), block_breaks.STREAM_CHUNK):
        out = co.compress(data[i:i + block_breaks.STREAM_CHUNK])
        if out:
            yield out
    if profile.get('tail') == 'sync':
        yield co.flush(module.Z_SYNC_FLUSH)
    yield co.flush(module.Z_FINISH)


def iter_compress_entry(data: bytes, profile: Dict, break_kind: int = BREAK_NONE,
                        breaks: Tuple[int, ...] = ()):
    """compress_entry(), yielding output as it is produced (for early exit).
    The one place that turns a profile into a compressor: clean verifies with
    it and smudge rebuilds with it, so the two cannot drift apart."""
    kind = profile['kind']
    if kind == 'msword':
        return msword_compressor.iter_compress_msword(
            data, breaks if break_kind == BREAK_FULL else ())
    if kind in ('zlib', 'zlib-ng') and breaks and break_kind != BREAK_NONE and not fittable(profile):
        raise ValueError(f"profile {profile['name']} cannot replay block breaks")
    if kind == 'zlib' and fittable(profile):
        if break_kind == BREAK_FULL:
            raise ValueError('full-flush breaks are not supported by zlib profiles')
        return block_breaks.iter_compress_with_breaks(
            data, breaks if break_kind == BREAK_BLOCK else (),
            profile['level'], profile['memlevel'], profile.get('strategy', 0))
    if kind == 'zlib':
        return _iter_plain(zlib, data, profile)
    if kind == 'zlib-ng':
        if zlib_ng is None:
            raise RuntimeError(unavailable_reason(profile))
        return _iter_plain(zlib_ng, data, profile)
    raise ValueError(f'unknown compression profile kind: {kind}')


def entry_matches(data: bytes, target: bytes, profile: Dict, break_kind: int = BREAK_NONE,
                  breaks: Tuple[int, ...] = ()) -> bool:
    """
    True when `profile` reproduces `target` exactly. Stops compressing at the
    first block that differs, so a wrong profile costs about one block.
    """
    return block_breaks.stream_matches(
        iter_compress_entry(data, profile, break_kind, breaks), target)


def describe(profile: Dict) -> str:
    """Short human-readable form, for logs."""
    if profile['kind'] in ('zlib', 'zlib-ng'):
        return (f"{profile['name']} ({profile['kind']} level={profile['level']} "
                f"memLevel={profile['memlevel']} strategy={profile.get('strategy', 0)}"
                f"{' + sync flush' if profile.get('tail') else ''})")
    return f"{profile['name']} ({profile['kind']})"