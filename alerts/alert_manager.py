"""Alert recording and optional console notification."""
import logging
from typing import Optional
from database.database import Database

class AlertManager:
    def __init__(self, database: Database, console: bool = True):
        self.database, self.console = database, console

    def create(self, file_id: int, event: str, severity: str,
               old_hash: Optional[str], new_hash: Optional[str], message: str) -> None:
        self.database.add_alert(file_id, event, severity, old_hash, new_hash, message)
        logging.warning("%s [%s]: %s", event, severity, message)
        if self.console:
            print(f"[!] {severity}: {message}")
