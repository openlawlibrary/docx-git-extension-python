import struct
import hashlib
import pygit2
from pathlib import Path

def read_u16(b: bytes, off: int) -> int:
    return struct.unpack_from('<H', b, off)[0]

def read_u32(b: bytes, off: int) -> int:
    return struct.unpack_from('<I', b, off)[0]

def repo_from_cwd():
    return pygit2.Repository(pygit2.discover_repository(Path.cwd()))

def calculate_sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def calculate_file_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    digest = sha256.hexdigest()
    return digest