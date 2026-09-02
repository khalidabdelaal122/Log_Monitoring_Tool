"""Configuration loading and validation."""
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import yaml

class ConfigError(ValueError):
    """Raised for invalid configuration."""

@dataclass(frozen=True)
class Config:
    database_path: Path
    log_path: Path
    scan_interval: float = 60.0
    realtime: bool = False
    console_alerts: bool = True

def load_config(path: Path) -> Config:
    base, data = path.resolve(strict=False).parent, {}
    if path.exists():
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigError(f"cannot read configuration: {exc}") from exc
        if loaded is not None and not isinstance(loaded, dict):
            raise ConfigError("configuration root must be a mapping")
        data = loaded or {}
    if data.get("hash_algorithm", "sha256") != "sha256":
        raise ConfigError("only SHA-256 is supported")
    monitoring, database = _mapping(data, "monitoring"), _mapping(data, "database")
    logging_cfg, alerts = _mapping(data, "logging"), _mapping(data, "alerts")
    interval = monitoring.get("scan_interval", 60)
    if not isinstance(interval, (int, float)) or isinstance(interval, bool) or interval <= 0:
        raise ConfigError("monitoring.scan_interval must be a positive number")
    return Config(_relative(base, database.get("path", "database/integrity.db")),
                  _relative(base, logging_cfg.get("path", "logs/logguard.log")),
                  float(interval), bool(monitoring.get("realtime", False)),
                  bool(alerts.get("console", True)))

def _mapping(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a mapping")
    return value

def _relative(base: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError("configured paths must be non-empty strings")
    result = Path(value).expanduser()
    return result if result.is_absolute() else base / result
