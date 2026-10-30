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

The order of PROFILES is the order the smudge filter tries them in, so the
cheapest and most common producer comes first. Names are part of the pointer
format once a PROFILE line is written, so do not rename an existing entry.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

import block_breaks
import msword_compressor

BREAK_NONE, BREAK_FULL, BREAK_BLOCK = 0, 1, 2

BREAK_NAMES = {BREAK_NONE: 'none', BREAK_FULL: 'full_flush', BREAK_BLOCK: 'block'}

PROFILES: List[Dict] = [
    {'name': 'python-docx', 'kind': 'zlib', 'level': 6, 'memlevel': 8, 'strategy': 0},
    {'name': 'msword',      'kind': 'msword'},
] + [
    {'name': f'aspose-ml#{ml}', 'kind': 'zlib', 'level': 5, 'memlevel': ml, 'strategy': 0}
    for ml in range(1, 10)
]

BY_NAME = {p['name']: p for p in PROFILES}

# Profiles the break fitter may pair with BREAK_BLOCK. The msword profile is
# excluded: it has its own flush mechanism and its knobs are unreachable without
# deflateTune, so mixing the two would only produce confusing failures.
ZLIB_PROFILES = [p for p in PROFILES if p['kind'] == 'zlib']

# `PROFILE fallback` (pointer_format.FALLBACK_PROFILE) rebuilds entries from
# their preflate corrections (preflate_fallback.py). This profile only serves a
# deflated entry the fallback could not model, or a pointer written without the
# helper; the hash check at checkout decides whether that worked.
FALLBACK = BY_NAME['python-docx']


def compress_entry(data: bytes, profile: Dict, break_kind: int = BREAK_NONE,
                   breaks: Tuple[int, ...] = ()) -> bytes:
    """Raw DEFLATE for one entry under `profile`, replaying `breaks`."""
    kind = profile['kind']
    if kind == 'msword':
        # Word's offsets are full flushes; a block break means nothing here.
        return msword_compressor.compress_raw_deflate_msword(
            data, breaks if break_kind == BREAK_FULL else ())
    if kind == 'zlib':
        if break_kind == BREAK_FULL:
            raise ValueError('full-flush breaks are not supported by zlib profiles')
        return block_breaks.compress_with_breaks(
            data, breaks if break_kind == BREAK_BLOCK else (),
            profile['level'], profile['memlevel'], profile.get('strategy', 0))
    raise ValueError(f'unknown compression profile kind: {kind}')


def iter_compress_entry(data: bytes, profile: Dict, break_kind: int = BREAK_NONE,
                        breaks: Tuple[int, ...] = ()):
    """compress_entry(), yielding output as it is produced (for early exit)."""
    kind = profile['kind']
    if kind == 'msword':
        return msword_compressor.iter_compress_msword(
            data, breaks if break_kind == BREAK_FULL else ())
    if kind == 'zlib':
        if break_kind == BREAK_FULL:
            raise ValueError('full-flush breaks are not supported by zlib profiles')
        return block_breaks.iter_compress_with_breaks(
            data, breaks if break_kind == BREAK_BLOCK else (),
            profile['level'], profile['memlevel'], profile.get('strategy', 0))
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
    if profile['kind'] == 'zlib':
        return (f"{profile['name']} (zlib level={profile['level']} "
                f"memLevel={profile['memlevel']} strategy={profile.get('strategy', 0)})")
    return f"{profile['name']} ({profile['kind']})"