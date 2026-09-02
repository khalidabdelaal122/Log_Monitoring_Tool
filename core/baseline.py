"""Trusted baseline lifecycle."""
from dataclasses import dataclass
from pathlib import Path
from core.hasher import calculate_hash
from core.metadata import collect_metadata, normalize_path
from database.database import Database
from database.models import MonitoredFile
from security.hmac_manager import HMACManager

@dataclass(frozen=True)
class UnsignedBaseline:
    file_path: str
    baseline_hash: str
    file_size: int
    owner_uid: int
    group_gid: int
    permissions: int
    inode: int

class BaselineManager:
    def __init__(self, database: Database, hmac_manager: HMACManager):
        self.database, self.hmac_manager = database, hmac_manager

    def add(self, path: Path) -> MonitoredFile:
        metadata = collect_metadata(path)
        digest = calculate_hash(Path(metadata.file_path))
        if metadata != collect_metadata(Path(metadata.file_path)):
            raise OSError(f"file changed while creating baseline: {path}")
        unsigned = UnsignedBaseline(metadata.file_path, digest, metadata.file_size,
                                    metadata.owner_uid, metadata.group_gid,
                                    metadata.permissions, metadata.inode)
        record = self.database.add_monitored_file(
            metadata, digest, self.hmac_manager.sign(unsigned))
        self.database.audit("BASELINE_CREATED", record.file_path, "SUCCESS")
        return record

    def remove(self, path: Path) -> bool:
        normalized = str(normalize_path(path, require_exists=False))
        removed = self.database.remove_monitored_file(normalized)
        self.database.audit("FILE_REMOVED", normalized,
                            "SUCCESS" if removed else "NOT_FOUND")
        return removed
