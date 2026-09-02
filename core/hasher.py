"""Streaming SHA-256 hashing."""
import hashlib
import os
from pathlib import Path

class FileChangedDuringHashError(OSError):
    """The file changed while its digest was calculated."""

def calculate_hash(path: Path, chunk_size: int = 1024 * 1024) -> str:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    before, digest = path.stat(follow_symlinks=False), hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise FileChangedDuringHashError(f"file changed while hashing: {path}")
    return digest.hexdigest()
