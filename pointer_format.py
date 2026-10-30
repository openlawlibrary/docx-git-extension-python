#!/usr/bin/env python3
"""
pointer_format.py - the pointer file git stores in place of a document.

Written by the clean filter, read by the smudge filter. Plain text, one fact
per line, so that `git diff` of a pointer says what changed and git can store
a new version as a small delta against the old one.

EXAMPLE

    DOCX-POINTER placeholder - this repository stores documents unpacked; ...
    VERSION 1.0
    TREE 4b825dc642cb6eb9a060e54bf8d69288fbee4904
    HASH 0608f403f1af4053b2769afb4f244948fef547dcf5c96221a01820412d797c91
    PROFILE msword
    DEFAULTS ver=20 flags=6 method=8 time=0 date=33 made=45 cdver=20 cdtime=0 cddate=33 iattr=0 eattr=0 dd=0 lextra= cextra= comment=
    ENTRY [Content_Types].xml lextra=20a2040228a00002(512)
    ENTRY word/document.xml flush=2232076
    ENTRY word/media/image1.emf breaks=350178,472030,28372

    A zip with its own comment carries it on an ARCHIVE line:

    ARCHIVE comment=6d61646520627920736f6d6520746f6f6c

    A document no profile reproduces uses the fallback instead:

    PROFILE fallback
    FALLBACK preflate-rs/0.7.6
    DEFAULTS ...
    ENTRY word/document.xml time=12106 date=23898 preflate=AAAEDAAEIAE+AP8DAQQAAAQQBAQDAA4AIDDw9zrPvwsT0D2gHJ4=

LINES

    DOCX-POINTER <notice>   Always the first line: identifies the file, and tells
                            whoever opens it in a clone without the extension
                            what to do. The post-commit hook and the clean
                            filter recognise pointers by this prefix.
    VERSION <major>.<minor> Always the second line; see VERSIONING.
    TREE <oid>              The git tree holding the unpacked parts. Smudge
                            resolves this oid directly, never a ref.
    HASH <sha256>           Of the original document. Checkout refuses any
                            rebuild that does not match it.
    PROFILE <name>          The compression profile that reproduces the
                            document (compression_profiles.py), or `fallback`
                            when none does. Always present: smudge never guesses.
    FALLBACK <tool>/<ver>   Only with PROFILE fallback: what made the entries'
                            `preflate=` corrections (preflate_fallback.py). Their
                            format changes between preflate-rs releases, so
                            smudge rebuilds only with exactly this version.
    ARCHIVE <k=v ...>       Only when the zip itself has something to record:
                            comment = the archive comment (EOCD record), as a
                            byte string like lextra. Room for other zip-level
                            fields later.
    DEFAULTS <k=v ...>      Every entry field, with the value most entries have.
    ENTRY <name> [k=v ...]  One per zip entry, in archive order, listing only the
                            fields that differ from DEFAULTS, plus its breaks.

ENTRY FIELDS (all decimal unless noted)

    ver      local header: version needed to extract
    flags    general purpose bit flags (same in local and central header)
    method   0 stored, 8 deflated
    time     DOS time          date   DOS date      (local header)
    made     central header: version made by
    cdver    central header: version needed to extract
    cdtime   central header: DOS time
    cddate   central header: DOS date. Usually equal to time/date; SharePoint
             restamps the central directory but keeps the local headers of
             parts it did not touch.
    iattr    internal attributes          eattr   external attributes
    dd       data descriptor: 0 none, 1 without signature, 2 with signature
    lextra   local extra field   } hex; a run of 4 or more zero bytes is
    cextra   central extra field } written (N), so Word's 1 KB padding
    comment  entry comment       } field stays short. Empty = none.
    flush    Word: uncompressed offsets of the full flushes inside the part
    breaks   other packagers: offsets of the blocks they cut early (Z_BLOCK)
    preflate fallback: base64 of the preflate-rs corrections that rebuild this
             deflated part from its plain bytes. Present on every deflated part
             of a PROFILE fallback pointer that has a FALLBACK line.

    flush and breaks are GAPS: the first number is the offset from the start
    of the part, every next one the distance from the previous. An edit in the
    middle of a part then changes one number instead of all that follow.

    A name is the entry's stored bytes, with every byte outside printable
    ASCII, space and % written as %XX. Whether it is a directory follows from
    the trailing slash.

    Which value goes in DEFAULTS is decided by count, ties going to the value
    that appears first in archive order. Clean must produce the same pointer
    for the same document every time, or git reports unchanged documents as
    modified - any reimplementation has to keep this rule.

VERSIONING

    A reader handles every pointer of its own major version:
      * a minor increase only ADDS information an older reader may ignore
        without rebuilding different bytes (a new line, a new ENTRY key). A
        reader therefore skips unknown keys in a pointer of a higher minor, and
        rejects them in a pointer of its own or a lower minor, where they can
        only mean corruption;
      * anything that changes how the document is rebuilt is a new major, and
        a reader refuses a major it does not know, asking for an update.
    Pointers without a VERSION line are from the pre-1.0 beta and are refused;
    re-adding the document (git add --renormalize) rewrites them.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Dict, List, Optional, Tuple

POINTER_MAGIC = "DOCX-POINTER"
POINTER_NOTICE = ("placeholder - this repository stores documents unpacked; "
                  "run the docx extension's install step here, then "
                  "'git checkout -- .' to get the real file")

VERSION = (1, 0)                 # what this code writes and the newest it fully understands
FALLBACK_PROFILE = "fallback"    # PROFILE value when no known profile reproduces the document

BREAK_NONE, BREAK_FULL, BREAK_BLOCK = 0, 1, 2   # same values as compression_profiles


class PointerError(ValueError):
    """The pointer cannot be read by this version of the extension."""


# --- versions -----------------------------------------------------------------

_VERSION_RE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


def format_version(v: Tuple[int, int] = VERSION) -> str:
    return f"{v[0]}.{v[1]}"


def parse_version(text: str) -> Tuple[int, int]:
    """'1.0' -> (1, 0). Strict: no leading zeros, no extra parts, no spaces."""
    m = _VERSION_RE.fullmatch(text)
    if not m:
        raise PointerError(f"malformed pointer version {text!r}")
    return int(m.group(1)), int(m.group(2))


def check_version(v: Tuple[int, int]) -> None:
    """Refuse a major version this reader does not implement."""
    if v[0] > VERSION[0]:
        raise PointerError(f"pointer format {format_version(v)} is newer than this extension "
                           f"understands ({format_version()}); update the extension")
    if v[0] < VERSION[0]:
        raise PointerError(f"pointer format {format_version(v)} is no longer supported; "
                           f"re-add the document with this extension (git add --renormalize)")


# --- field encodings ------------------------------------------------------------

_SAFE = frozenset(range(0x21, 0x7F)) - {ord("%")}


def encode_name(raw: bytes) -> str:
    if not raw:
        raise PointerError("zip entry with an empty name cannot be recorded")
    return "".join(chr(b) if b in _SAFE else f"%{b:02X}" for b in raw)


def decode_name(text: str) -> bytes:
    out, i = bytearray(), 0
    while i < len(text):
        c = text[i]
        if c == "%":
            h = text[i + 1:i + 3]
            if not re.fullmatch(r"[0-9A-F]{2}", h):
                raise PointerError(f"bad escape in entry name {text!r}")
            out.append(int(h, 16))
            i += 3
        elif ord(c) in _SAFE:
            out.append(ord(c))
            i += 1
        else:
            raise PointerError(f"unescaped character in entry name {text!r}")
    if not out:
        raise PointerError("empty entry name")
    return bytes(out)


def encode_bytes(b: bytes) -> str:
    """Lowercase hex; every run of 4+ zero bytes as (N)."""
    out, i, n = [], 0, len(b)
    while i < n:
        if b[i] == 0:
            j = i
            while j < n and b[j] == 0:
                j += 1
            if j - i >= 4:
                out.append(f"({j - i})")
                i = j
                continue
        out.append(f"{b[i]:02x}")
        i += 1
    return "".join(out)


_BYTES_TOKEN = re.compile(r"([0-9a-f]{2})|\(([1-9][0-9]*)\)")


def decode_bytes(text: str) -> bytes:
    out, pos = bytearray(), 0
    while pos < len(text):
        m = _BYTES_TOKEN.match(text, pos)
        if not m:
            raise PointerError(f"bad byte string {text!r}")
        out += bytes.fromhex(m.group(1)) if m.group(1) else bytes(int(m.group(2)))
        pos = m.end()
    return bytes(out)


def encode_gaps(offsets) -> str:
    prev, out = 0, []
    for o in offsets:
        if o <= prev:
            raise PointerError(f"break offsets must increase: {tuple(offsets)}")
        out.append(str(o - prev))
        prev = o
    return ",".join(out)


def decode_gaps(text: str) -> Tuple[int, ...]:
    if not re.fullmatch(r"[1-9][0-9]*(,[1-9][0-9]*)*", text):
        raise PointerError(f"bad break list {text!r}")
    total, out = 0, []
    for g in text.split(","):
        total += int(g)
        out.append(total)
    return tuple(out)


def _uint(bits):
    def parse(text):
        if not re.fullmatch(r"0|[1-9][0-9]*", text) or int(text) >= 1 << bits:
            raise PointerError(f"bad {bits}-bit value {text!r}")
        return int(text)
    return str, parse


_U16, _U32 = _uint(16), _uint(32)
_DD = (str, lambda t: _check_dd(_U16[1](t)))
_BYTES = (encode_bytes, decode_bytes)


def _check_dd(v):
    if v > 2:
        raise PointerError(f"bad dd value {v}")
    return v


# (key, where the value lives in an entry dict, (encode, decode))
FIELDS = [
    ("ver",     ("lfh", "version_needed"),  _U16),
    ("flags",   ("lfh", "flags"),           _U16),
    ("method",  ("lfh", "method"),          _U16),
    ("time",    ("lfh", "dos_time"),        _U16),
    ("date",    ("lfh", "dos_date"),        _U16),
    ("made",    ("cd", "version_made_by"),  _U16),
    ("cdver",   ("cd", "version_needed"),   _U16),
    ("cdtime",  ("cd", "dos_time"),         _U16),
    ("cddate",  ("cd", "dos_date"),         _U16),
    ("iattr",   ("cd", "internal_attr"),    _U16),
    ("eattr",   ("cd", "external_attr"),    _U32),
    ("dd",      None,                       _DD),
    ("lextra",  ("lfh", "extra_lfh"),       _BYTES),
    ("cextra",  ("cd", "extra_cd"),         _BYTES),
    ("comment", ("cd", "comment"),          _BYTES),
]
FIELD_KEYS = [k for k, _, _ in FIELDS]
BREAK_KEYS = {"flush": BREAK_FULL, "breaks": BREAK_BLOCK}
PREFLATE_KEY = "preflate"
_FALLBACK_RE = re.compile(r"[a-z0-9][a-z0-9.+-]*/[0-9A-Za-z][0-9A-Za-z.+-]*")


def encode_b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def decode_b64(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as e:
        raise PointerError(f"bad base64 value: {e}") from e


def _field_values(e: Dict) -> Dict[str, str]:
    vals = {}
    for key, path, (enc, _) in FIELDS:
        if key == "dd":
            pol = e["policy"]
            v = (2 if pol["dd_has_signature"] else 1) if pol["use_data_descriptor"] else 0
        else:
            v = e[path[0]][path[1]]
        vals[key] = enc(v)
    return vals


def _entry_from_values(name_raw: bytes, vals: Dict[str, str], kind: int, offs,
                       preflate: Optional[bytes] = None) -> Dict:
    p = {key: dec(vals[key]) for key, _, (_, dec) in FIELDS}
    flags = p["flags"]
    try:
        name = name_raw.decode("utf-8") if flags & 0x0800 else name_raw.decode("cp437")
    except UnicodeDecodeError:
        name = name_raw.decode("utf-8", "replace")
    return {
        "name": name,
        "name_raw": name_raw,
        "is_dir": name_raw.endswith(b"/"),
        "lfh": {"version_needed": p["ver"], "flags": flags, "method": p["method"],
                "dos_time": p["time"], "dos_date": p["date"], "extra_lfh": p["lextra"]},
        "cd": {"version_made_by": p["made"], "version_needed": p["cdver"],
               "dos_time": p["cdtime"], "dos_date": p["cddate"],
               "internal_attr": p["iattr"], "external_attr": p["eattr"],
               "extra_cd": p["cextra"], "comment": p["comment"]},
        "policy": {"use_data_descriptor": p["dd"] > 0, "dd_has_signature": p["dd"] == 2,
                   "flush_offsets": tuple(offs), "break_kind": kind if offs else BREAK_NONE,
                   "preflate": preflate},
    }


def _most_common(values: List[str]) -> str:
    """Highest count wins; a tie goes to the value seen first (archive order)."""
    counts: Dict[str, int] = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    best = values[0]
    for v in counts:                 # dict keeps first-seen order
        if counts[v] > counts[best]:
            best = v
    return best


# --- whole pointer ----------------------------------------------------------------

ARCHIVE_KEYS = {"comment": _BYTES}


def write(tree_oid: str, doc_hash: str, profile: str, entries: List[Dict],
          fallback: Optional[str] = None, archive_comment: bytes = b"") -> str:
    """
    The pointer text. `entries` use the structure parse() returns; `profile`
    is a profile name or FALLBACK_PROFILE. `fallback` names the tool and
    version that made the entries' preflate corrections (FALLBACK line).
    `archive_comment` is the zip's own comment (ARCHIVE line, only when set).
    """
    if fallback is not None and (profile != FALLBACK_PROFILE or not _FALLBACK_RE.fullmatch(fallback)):
        raise PointerError(f"bad FALLBACK {fallback!r} for PROFILE {profile!r}")
    if not entries:
        raise PointerError("a document without zip entries cannot be recorded")
    rows = [_field_values(e) for e in entries]
    defaults = {k: _most_common([r[k] for r in rows]) for k in FIELD_KEYS}
    lines = [f"{POINTER_MAGIC} {POINTER_NOTICE}",
             f"VERSION {format_version()}",
             f"TREE {tree_oid}",
             f"HASH {doc_hash}",
             f"PROFILE {profile}"] + ([f"FALLBACK {fallback}"] if fallback else []) + (
             [f"ARCHIVE comment={encode_bytes(archive_comment)}"] if archive_comment else []) + [
             "DEFAULTS " + " ".join(f"{k}={defaults[k]}" for k in FIELD_KEYS)]
    for e, r in zip(entries, rows):
        parts = [encode_name(e["name_raw"])]
        parts += [f"{k}={r[k]}" for k in FIELD_KEYS if r[k] != defaults[k]]
        pol = e["policy"]
        if pol["flush_offsets"]:
            key = "flush" if pol["break_kind"] == BREAK_FULL else "breaks"
            parts.append(f"{key}={encode_gaps(pol['flush_offsets'])}")
        if pol.get("preflate") is not None:
            if not fallback:
                raise PointerError("preflate corrections without a FALLBACK line")
            parts.append(f"{PREFLATE_KEY}={encode_b64(pol['preflate'])}")
        lines.append("ENTRY " + " ".join(parts))
    return "\n".join(lines) + "\n"


class Pointer:
    def __init__(self, version, tree, doc_hash, profile, entries, fallback=None, archive=None):
        self.version, self.tree, self.hash = version, tree, doc_hash
        self.profile, self.entries, self.fallback = profile, entries, fallback
        self.archive = archive or {}      # {'comment': bytes} when the zip has one


def is_pointer(data: bytes) -> bool:
    return data.startswith(POINTER_MAGIC.encode("ascii"))


def parse(text: str) -> Pointer:
    lines = [l.rstrip("\r") for l in text.split("\n")]
    if lines and lines[-1] == "":
        lines.pop()
    if not lines or not lines[0].startswith(POINTER_MAGIC):
        raise PointerError("not a docx pointer")
    if len(lines) < 2 or not lines[1].startswith("VERSION "):
        raise PointerError("pointer has no VERSION line: it was written by a pre-1.0 beta "
                           "of the extension; re-add the document (git add --renormalize)")
    version = parse_version(lines[1][len("VERSION "):])
    check_version(version)
    newer_minor = version[1] > VERSION[1]

    def unknown(what):
        if not newer_minor:
            raise PointerError(f"unknown {what} in a {format_version(version)} pointer")

    head: Dict[str, str] = {}
    defaults: Optional[Dict[str, str]] = None
    archive: Optional[Dict[str, bytes]] = None
    entries: List[Dict] = []
    for n, line in enumerate(lines[2:], start=3):
        key, sep, rest = line.partition(" ")
        if key in ("TREE", "HASH", "PROFILE", "FALLBACK"):
            if key in head or not sep or not rest:
                raise PointerError(f"line {n}: duplicate or empty {key}")
            head[key] = rest
        elif key == "ARCHIVE":
            if archive is not None or defaults is not None:
                raise PointerError(f"line {n}: ARCHIVE must come once, before DEFAULTS")
            archive = {}
            for kv in rest.split(" "):
                k, eq, v = kv.partition("=")
                if not eq or k in archive:
                    raise PointerError(f"line {n}: bad ARCHIVE item {kv!r}")
                if k in ARCHIVE_KEYS:
                    archive[k] = ARCHIVE_KEYS[k][1](v)
                else:
                    unknown(f"ARCHIVE key {k!r}")
        elif key == "DEFAULTS":
            if defaults is not None or entries:
                raise PointerError(f"line {n}: DEFAULTS must come once, before the entries")
            defaults = {}
            for kv in rest.split(" "):
                k, eq, v = kv.partition("=")
                if not eq or k in defaults:
                    raise PointerError(f"line {n}: bad DEFAULTS item {kv!r}")
                if k in FIELD_KEYS:
                    defaults[k] = v
                else:
                    unknown(f"DEFAULTS key {k!r}")
            missing = [k for k in FIELD_KEYS if k not in defaults]
            if missing:
                raise PointerError(f"line {n}: DEFAULTS lacks {', '.join(missing)}")
        elif key == "ENTRY":
            if defaults is None:
                raise PointerError(f"line {n}: ENTRY before DEFAULTS")
            name, *items = rest.split(" ")
            vals, kind, offs, seen, pre = dict(defaults), BREAK_NONE, (), set(), None
            for kv in items:
                k, eq, v = kv.partition("=")
                if not eq or k in seen:
                    raise PointerError(f"line {n}: bad ENTRY item {kv!r}")
                seen.add(k)
                if k in FIELD_KEYS:
                    vals[k] = v
                elif k in BREAK_KEYS:
                    if offs:
                        raise PointerError(f"line {n}: both flush and breaks")
                    kind, offs = BREAK_KEYS[k], decode_gaps(v)
                elif k == PREFLATE_KEY:
                    pre = decode_b64(v)
                else:
                    unknown(f"ENTRY key {k!r}")
            if pre is not None and offs:
                raise PointerError(f"line {n}: preflate together with {'flush' if kind == BREAK_FULL else 'breaks'}")
            entries.append(_entry_from_values(decode_name(name), vals, kind, offs, pre))
        else:
            unknown(f"line {key!r}")
    for key in ("TREE", "HASH", "PROFILE"):
        if key not in head:
            raise PointerError(f"pointer has no {key} line")
    if not re.fullmatch(r"[0-9a-f]{40}([0-9a-f]{24})?", head["TREE"]):
        raise PointerError(f"bad TREE {head['TREE']!r}")
    if not re.fullmatch(r"[0-9a-f]{64}", head["HASH"]):
        raise PointerError(f"bad HASH {head['HASH']!r}")
    if not entries:
        raise PointerError("pointer has no entries")
    fallback = head.get("FALLBACK")
    if fallback is not None:
        if head["PROFILE"] != FALLBACK_PROFILE or not _FALLBACK_RE.fullmatch(fallback):
            raise PointerError(f"bad FALLBACK {fallback!r} for PROFILE {head['PROFILE']!r}")
    elif any(e["policy"]["preflate"] is not None for e in entries):
        raise PointerError("preflate corrections without a FALLBACK line")
    return Pointer(version, head["TREE"], head["HASH"], head["PROFILE"], entries, fallback, archive)
