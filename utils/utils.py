import struct
import hashlib
import pygit2
from pathlib import Path

def read_u16(b: bytes, off: int) -> int:
    return struct.unpack_from('<H', b, off)[0]

def read_u32(b: bytes, off: int) -> int:
    return struct.unpack_from('<I', b, off)[0]

def repo_from_cwd() -> pygit2.Repository:
    return pygit2.Repository(pygit2.discover_repository(str(Path.cwd())))

def calculate_sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def common_prefix(a: bytes, b: bytes) -> int:
    """Length of the common prefix of `a` and `b` (binary search on slices:
    fast for large inputs)."""
    lo, hi = 0, min(len(a), len(b))
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if a[:mid] == b[:mid]:
            lo = mid
        else:
            hi = mid - 1
    return lo
