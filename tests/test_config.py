from pathlib import Path
import pytest
from config import ConfigError, load_config

def test_safe_defaults_for_missing_config(tmp_path: Path):
    config = load_config(tmp_path / "missing.yaml")
    assert config.scan_interval == 60
    assert config.database_path == tmp_path / "database/integrity.db"

def test_malformed_config(tmp_path: Path):
    path = tmp_path / "bad.yaml"
    path.write_text("monitoring: [invalid]")
    with pytest.raises(ConfigError):
        load_config(path)
