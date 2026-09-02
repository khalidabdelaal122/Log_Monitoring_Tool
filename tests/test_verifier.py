import os
from pathlib import Path
from core.verifier import IntegrityStatus

def register(services, path: Path):
    _, baseline, verifier = services
    baseline.add(path)
    return verifier

def test_safe_and_modified_create_expected_state_and_alert(services, tmp_path: Path):
    database, _, _ = services
    path = tmp_path / "test.log"
    path.write_text("original")
    verifier = register(services, path)
    assert verifier.verify(path).status is IntegrityStatus.SAFE
    path.write_text("modified")
    assert verifier.verify(path).status is IntegrityStatus.MODIFIED
    alerts = database.list_alerts()
    assert len(alerts) == 1
    assert alerts[0].event_type == "MODIFIED"
    assert alerts[0].severity == "HIGH"

def test_deleted(services, tmp_path: Path):
    path = tmp_path / "deleted.log"
    path.write_text("original")
    verifier = register(services, path)
    path.unlink()
    assert verifier.verify(path).status is IntegrityStatus.DELETED

def test_permission_changed(services, tmp_path: Path):
    path = tmp_path / "permissions.log"
    path.write_text("original")
    path.chmod(0o600)
    verifier = register(services, path)
    path.chmod(0o640)
    assert verifier.verify(path).status is IntegrityStatus.PERMISSION_CHANGED

def test_replaced_inode(services, tmp_path: Path):
    path = tmp_path / "replaced.log"
    path.write_text("original")
    verifier = register(services, path)
    replacement = tmp_path / "replacement"
    replacement.write_text("original")
    os.replace(replacement, path)
    assert verifier.verify(path).status is IntegrityStatus.REPLACED

def test_invalid_hmac_is_critical(services, tmp_path: Path):
    database, _, verifier = services
    path = tmp_path / "hmac.log"
    path.write_text("original")
    register(services, path)
    with database.connect() as connection:
        connection.execute("UPDATE monitored_files SET file_size = file_size + 1")
    result = verifier.verify(path)
    assert result.status is IntegrityStatus.BASELINE_TAMPERED
    assert result.severity == "CRITICAL"
