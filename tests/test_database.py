from pathlib import Path
from core.metadata import collect_metadata
from security.hmac_manager import HMACManager

def test_database_insert_update_read(services, tmp_path: Path):
    database, _, _ = services
    path = tmp_path / "db.log"
    path.write_text("abc")
    metadata = collect_metadata(path)
    manager = HMACManager(b"x" * 32)
    class Item:
        file_path = metadata.file_path
        baseline_hash = "a" * 64
        file_size = metadata.file_size
        owner_uid = metadata.owner_uid
        group_gid = metadata.group_gid
        permissions = metadata.permissions
        inode = metadata.inode
    record = database.add_monitored_file(metadata, Item.baseline_hash, manager.sign(Item))
    database.update_status(record.id, "MODIFIED")
    assert database.get_monitored_file(metadata.file_path).status == "MODIFIED"
    database.audit("TEST", metadata.file_path, "SUCCESS")
    assert database.list_audit_logs()[0].action == "TEST"

def test_remove_does_not_delete_file(services, tmp_path: Path):
    database, baseline, _ = services
    path = tmp_path / "keep.log"
    path.write_text("keep")
    baseline.add(path)
    assert baseline.remove(path)
    assert path.exists()
    assert database.list_monitored_files() == []
