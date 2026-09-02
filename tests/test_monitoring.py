from pathlib import Path
from core.verifier import IntegrityStatus
from monitoring.scanner import Scanner


def test_scan_all(services, tmp_path: Path):
    database, baseline, verifier = services
    safe = tmp_path / "safe.log"
    changed = tmp_path / "changed.log"
    safe.write_text("safe")
    changed.write_text("original")
    baseline.add(safe)
    baseline.add(changed)
    changed.write_text("changed")
    results = Scanner(database, verifier).scan_all()
    assert {result.status for result in results} == {
        IntegrityStatus.SAFE, IntegrityStatus.MODIFIED}
