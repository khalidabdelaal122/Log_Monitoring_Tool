"""Persistence models."""
from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class MonitoredFile:
    id: int
    file_path: str
    baseline_hash: str
    file_size: int
    owner_uid: int
    group_gid: int
    permissions: int
    inode: int
    modification_time: int
    created_at: str
    last_checked: Optional[str]
    status: str
    baseline_hmac: str

@dataclass(frozen=True)
class Alert:
    id: int
    file_id: int
    file_path: str
    event_type: str
    severity: str
    old_hash: Optional[str]
    new_hash: Optional[str]
    message: str
    detected_at: str

@dataclass(frozen=True)
class AuditLog:
    id: int
    action: str
    target: str
    result: str
    timestamp: str
