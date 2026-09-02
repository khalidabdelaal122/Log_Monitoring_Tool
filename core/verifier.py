"""Baseline integrity verification."""
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional
from alerts.alert_manager import AlertManager
from core.hasher import calculate_hash
from core.metadata import collect_metadata, normalize_path
from database.database import Database
from security.hmac_manager import HMACManager


class IntegrityStatus(str, Enum):
    SAFE = "SAFE"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    PERMISSION_CHANGED = "PERMISSION_CHANGED"
    OWNER_CHANGED = "OWNER_CHANGED"
    REPLACED = "REPLACED"
    BASELINE_TAMPERED = "BASELINE_TAMPERED"


@dataclass(frozen=True)
class VerificationResult:
    file_path: str
    status: IntegrityStatus
    expected_hash: str
    current_hash: Optional[str]
    severity: str
    message: str


class Verifier:
    def __init__(self, database: Database, hmac_manager: HMACManager,
                 alerts: AlertManager):
        self.database = database
        self.hmac_manager = hmac_manager
        self.alert_manager = alerts

    def verify(self, path: Path) -> VerificationResult:
        normalized = str(normalize_path(path, require_exists=False))
        baseline = self.database.get_monitored_file(normalized)
        if baseline is None:
            raise ValueError(f"file is not monitored: {normalized}")
        if not self.hmac_manager.verify(baseline, baseline.baseline_hmac):
            return self._finish(baseline, IntegrityStatus.BASELINE_TAMPERED, None,
                                "CRITICAL", "Baseline HMAC validation failed")
        candidate = Path(baseline.file_path)
        if not candidate.exists():
            return self._finish(baseline, IntegrityStatus.DELETED, None, "HIGH",
                                "Monitored file was deleted")
        if candidate.is_symlink() or not candidate.is_file():
            return self._finish(baseline, IntegrityStatus.REPLACED, None, "HIGH",
                                "Monitored file was replaced with an unsupported file type")
        metadata = collect_metadata(candidate)
        current_hash = calculate_hash(candidate)
        if metadata.inode != baseline.inode:
            status, severity, message = (IntegrityStatus.REPLACED, "HIGH",
                                         "File inode changed; the file was replaced")
        elif (metadata.owner_uid != baseline.owner_uid or
              metadata.group_gid != baseline.group_gid):
            status, severity, message = (IntegrityStatus.OWNER_CHANGED, "MEDIUM",
                                         "File owner or group changed")
        elif metadata.permissions != baseline.permissions:
            status, severity, message = (IntegrityStatus.PERMISSION_CHANGED, "MEDIUM",
                                         "File permissions changed")
        elif current_hash != baseline.baseline_hash:
            status, severity, message = (IntegrityStatus.MODIFIED, "HIGH",
                                         "File content differs from the trusted baseline")
        else:
            status, severity, message = (IntegrityStatus.SAFE, "INFO",
                                         "File matches the trusted baseline")
        return self._finish(baseline, status, current_hash, severity, message)

    def _finish(self, baseline, status: IntegrityStatus, current_hash: Optional[str],
                severity: str, message: str) -> VerificationResult:
        self.database.update_status(baseline.id, status.value)
        action = "FILE_VERIFIED" if status is IntegrityStatus.SAFE else "INTEGRITY_VIOLATION"
        self.database.audit(action, baseline.file_path, status.value)
        if status is not IntegrityStatus.SAFE:
            self.alert_manager.create(baseline.id, status.value, severity,
                                      baseline.baseline_hash, current_hash, message)
        return VerificationResult(baseline.file_path, status, baseline.baseline_hash,
                                  current_hash, severity, message)
