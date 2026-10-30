#!/usr/bin/env python3
"""
preflate_fallback.py - the fallback compression, for documents no profile reproduces.

Known profiles (compression_profiles.py) rebuild a deflate stream from the
plain part alone. When none of them reproduces a document - SharePoint and Word
for the web output, Info-ZIP, anything new - clean asks preflate-rs instead:
it models how each stream was compressed and records the difference from its
prediction, the "corrections" (typically 40-80 bytes per part). From the plain
part plus those corrections it rebuilds the original stream byte for byte.

preflate-rs is Rust, so it runs in a small helper, preflate-helper/
(docx-preflate). Build it once:

    cargo build --release --manifest-path preflate-helper/Cargo.toml

Found, in this order: $DOCX_PREFLATE, preflate-helper/target/release next to
this file, then docx-preflate on PATH. One helper process per document; it
works on the document's parts in parallel.

VERSIONS. The corrections format is not stable across preflate-rs releases, so
every pointer that uses them records the version that made them
(`FALLBACK preflate-rs/0.7.6`), and smudge refuses to rebuild with another.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

ENV_VAR = "DOCX_PREFLATE"
_EXE = "docx-preflate.exe" if os.name == "nt" else "docx-preflate"
_BUILT = Path(__file__).resolve().parent / "preflate-helper" / "target" / "release" / _EXE
BUILD_HINT = "cargo build --release --manifest-path preflate-helper/Cargo.toml"

_helper: Optional[str] = None
_helper_found = False
_version: Optional[str] = None


class PreflateUnavailable(RuntimeError):
    """No usable docx-preflate helper on this machine."""


def helper_path() -> Optional[str]:
    global _helper, _helper_found
    if not _helper_found:
        _helper_found = True
        env = os.environ.get(ENV_VAR)
        if env:
            _helper = env
        elif _BUILT.is_file():
            _helper = str(_BUILT)
        else:
            _helper = shutil.which("docx-preflate")
    return _helper


def version() -> str:
    """'preflate-rs/0.7.6' - what the installed helper writes and reads."""
    global _version
    if _version is None:
        exe = helper_path()
        if not exe:
            raise PreflateUnavailable(
                f"the fallback compression needs the docx-preflate helper; build it with "
                f"'{BUILD_HINT}' or point ${ENV_VAR} at it")
        try:
            out = subprocess.run([exe, "version"], capture_output=True, check=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as e:
            raise PreflateUnavailable(f"docx-preflate helper {exe} does not run: {e}") from e
        _version = out.stdout.decode("ascii", "replace").strip()
    return _version


def is_available() -> bool:
    try:
        version()
        return True
    except PreflateUnavailable:
        return False


def _run(cmd: str, frames: Sequence[bytes]) -> List[Tuple[bool, bytes]]:
    version()                                    # raises with a useful message when missing
    payload = b"".join(struct.pack("<I", len(f)) + bytes(f) for f in frames)
    proc = subprocess.run([helper_path(), cmd], input=payload, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(f"docx-preflate {cmd} failed ({proc.returncode}): "
                           f"{proc.stderr.decode('utf-8', 'replace').strip()}")
    out, p, replies = proc.stdout, 0, []
    while p < len(out):
        status, n = out[p], struct.unpack_from("<I", out, p + 1)[0]
        replies.append((status == 0, out[p + 5:p + 5 + n]))
        p += 5 + n
    return replies


def split(streams: Sequence[bytes]) -> List[Tuple[Optional[bytes], str]]:
    """
    Corrections for each raw deflate stream: (corrections, "") or (None, reason).
    Verified by the helper - corrections that would not rebuild the stream
    come back as a failure, never as data.
    """
    if not streams:
        return []
    replies = _run("split", streams)
    if len(replies) != len(streams):
        raise RuntimeError(f"docx-preflate split answered {len(replies)} of {len(streams)} streams")
    return [(body, "") if ok else (None, body.decode("utf-8", "replace")) for ok, body in replies]


def recreate(pairs: Sequence[Tuple[bytes, bytes]]) -> List[bytes]:
    """The original deflate stream for each (plain part, corrections) pair."""
    if not pairs:
        return []
    frames = [f for plain, corr in pairs for f in (plain, corr)]
    replies = _run("recreate", frames)
    if len(replies) != len(pairs):
        raise RuntimeError(f"docx-preflate recreate answered {len(replies)} of {len(pairs)} parts")
    out = []
    for ok, body in replies:
        if not ok:
            raise RuntimeError(body.decode("utf-8", "replace"))
        out.append(body)
    return out


if __name__ == "__main__":                      # `python preflate_fallback.py` - is it installed?
    try:
        print(f"{version()} at {helper_path()}")
    except PreflateUnavailable as e:
        print(e, file=sys.stderr)
        sys.exit(1)
