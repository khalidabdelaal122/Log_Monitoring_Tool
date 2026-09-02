from pathlib import Path
import pytest
from alerts.alert_manager import AlertManager
from core.baseline import BaselineManager
from core.verifier import Verifier
from database.database import Database
from security.hmac_manager import HMACManager

@pytest.fixture
def services(tmp_path: Path):
    database = Database(tmp_path / "integrity.db")
    database.initialize()
    hmac_manager = HMACManager(b"x" * 32)
    return database, BaselineManager(database, hmac_manager), Verifier(
        database, hmac_manager, AlertManager(database, console=False))
