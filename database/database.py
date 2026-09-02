"""Parameterized SQLite persistence."""
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional
from core.metadata import FileMetadata
from database.models import Alert, AuditLog, MonitoredFile

class Database:
    def __init__(self, path: Path):
        self.path = path

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS monitored_files (
                    id INTEGER PRIMARY KEY, file_path TEXT NOT NULL UNIQUE,
                    baseline_hash TEXT NOT NULL, file_size INTEGER NOT NULL,
                    owner_uid INTEGER NOT NULL, group_gid INTEGER NOT NULL,
                    permissions INTEGER NOT NULL, inode INTEGER NOT NULL,
                    modification_time INTEGER NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_checked TEXT, status TEXT NOT NULL DEFAULT 'SAFE',
                    baseline_hmac TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY, file_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL, severity TEXT NOT NULL,
                    old_hash TEXT, new_hash TEXT, message TEXT NOT NULL,
                    detected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(file_id) REFERENCES monitored_files(id) ON DELETE CASCADE);
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY, action TEXT NOT NULL, target TEXT NOT NULL,
                    result TEXT NOT NULL, timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
                CREATE INDEX IF NOT EXISTS idx_alerts_detected_at ON alerts(detected_at DESC);
            """)

    def add_monitored_file(self, metadata: FileMetadata, digest: str, signature: str) -> MonitoredFile:
        try:
            with self.connect() as db:
                cursor = db.execute("""INSERT INTO monitored_files
                    (file_path, baseline_hash, file_size, owner_uid, group_gid,
                     permissions, inode, modification_time, baseline_hmac)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (metadata.file_path, digest, metadata.file_size, metadata.owner_uid,
                     metadata.group_gid, metadata.permissions, metadata.inode,
                     metadata.modification_time, signature))
                row = db.execute("SELECT * FROM monitored_files WHERE id = ?", (cursor.lastrowid,)).fetchone()
            return MonitoredFile(**dict(row))
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"file is already monitored: {metadata.file_path}") from exc

    def get_monitored_file(self, path: str) -> Optional[MonitoredFile]:
        with self.connect() as db:
            row = db.execute("SELECT * FROM monitored_files WHERE file_path = ?", (path,)).fetchone()
        return MonitoredFile(**dict(row)) if row else None

    def list_monitored_files(self) -> list[MonitoredFile]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM monitored_files ORDER BY file_path").fetchall()
        return [MonitoredFile(**dict(row)) for row in rows]

    def remove_monitored_file(self, path: str) -> bool:
        with self.connect() as db:
            cursor = db.execute("DELETE FROM monitored_files WHERE file_path = ?", (path,))
        return cursor.rowcount > 0

    def update_status(self, file_id: int, status: str) -> None:
        with self.connect() as db:
            db.execute("UPDATE monitored_files SET status = ?, last_checked = CURRENT_TIMESTAMP WHERE id = ?",
                       (status, file_id))

    def add_alert(self, file_id: int, event_type: str, severity: str,
                  old_hash: Optional[str], new_hash: Optional[str], message: str) -> None:
        with self.connect() as db:
            db.execute("""INSERT INTO alerts
                (file_id, event_type, severity, old_hash, new_hash, message)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (file_id, event_type, severity, old_hash, new_hash, message))

    def list_alerts(self) -> list[Alert]:
        with self.connect() as db:
            rows = db.execute("""SELECT a.*, m.file_path FROM alerts a
                JOIN monitored_files m ON m.id = a.file_id
                ORDER BY a.detected_at DESC, a.id DESC""").fetchall()
        return [Alert(**dict(row)) for row in rows]

    def audit(self, action: str, target: str, result: str) -> None:
        with self.connect() as db:
            db.execute("INSERT INTO audit_logs (action, target, result) VALUES (?, ?, ?)",
                       (action, target, result))

    def list_audit_logs(self) -> list[AuditLog]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC, id DESC").fetchall()
        return [AuditLog(**dict(row)) for row in rows]
