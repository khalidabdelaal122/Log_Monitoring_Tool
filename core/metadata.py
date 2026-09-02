"""Safe file path handling and metadata collection."""
import stat
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FileMetadata:
    file_path: str
    file_size: int
    owner_uid: int
    group_gid: int
    permissions: int
    inode: int
    modification_time: int


def normalize_path(path: Path, require_exists: bool = True) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ValueError(f"symbolic links are not supported: {candidate}")
    try:
        normalized = candidate.resolve(strict=require_exists)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"invalid or inaccessible path: {candidate}") from exc
    if require_exists and not normalized.is_file():
        raise ValueError(f"not a regular file: {normalized}")
    return normalized


def collect_metadata(path: Path) -> FileMetadata:
    normalized = normalize_path(path)
    details = normalized.stat(follow_symlinks=False)
    if not stat.S_ISREG(details.st_mode):
        raise ValueError(f"not a regular file: {normalized}")
    return FileMetadata(str(normalized), details.st_size, details.st_uid, details.st_gid,
                        stat.S_IMODE(details.st_mode), details.st_ino, details.st_mtime_ns)
