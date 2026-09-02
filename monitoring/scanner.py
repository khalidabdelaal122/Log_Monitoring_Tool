"""Batch integrity scanner."""
from pathlib import Path
from core.verifier import VerificationResult, Verifier
from database.database import Database

class Scanner:
    def __init__(self, database: Database, verifier: Verifier):
        self.database, self.verifier = database, verifier

    def scan_all(self) -> list[VerificationResult]:
        return [self.verifier.verify(Path(item.file_path))
                for item in self.database.list_monitored_files()]
