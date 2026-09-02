from pathlib import Path
import pytest

def test_baseline_creation_and_duplicate(services, tmp_path: Path):
    database, baseline, _ = services
    path = tmp_path / "application log.log"
    path.write_text("entry", encoding="utf-8")
    record = baseline.add(path)
    assert record.file_path == str(path.resolve())
    assert len(record.baseline_hash) == 64
    assert database.get_monitored_file(str(path.resolve())) == record
    with pytest.raises(ValueError, match="already monitored"):
        baseline.add(path)

def test_baseline_rejects_missing_file(services, tmp_path: Path):
    _, baseline, _ = services
    with pytest.raises(ValueError):
        baseline.add(tmp_path / "missing.log")

def test_baseline_rejects_symbolic_link(services, tmp_path: Path):
    _, baseline, _ = services
    target = tmp_path / "target.log"
    target.write_text("data")
    link = tmp_path / "link.log"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symbolic"):
        baseline.add(link)
