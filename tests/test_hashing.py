import hashlib
from pathlib import Path
import pytest
from core.hasher import calculate_hash

@pytest.mark.parametrize("name,data", [
    ("empty.log", b""), ("file with spaces.log", b"log line\n"),
    ("large.log", b"x" * (2 * 1024 * 1024 + 17)),
])
def test_hashing_files(tmp_path: Path, name: str, data: bytes):
    path = tmp_path / name
    path.write_bytes(data)
    assert calculate_hash(path, chunk_size=4096) == hashlib.sha256(data).hexdigest()

def test_invalid_path(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        calculate_hash(tmp_path / "missing")
