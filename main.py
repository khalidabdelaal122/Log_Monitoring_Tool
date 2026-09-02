"""LogGuard command-line entry point."""
from __future__ import annotations
import argparse
import logging
import sys
from pathlib import Path
from alerts.alert_manager import AlertManager
from config import ConfigError, load_config
from core.baseline import BaselineManager
from core.verifier import IntegrityStatus, Verifier
from database.database import Database
from monitoring.scanner import Scanner
from monitoring.watcher import WatcherUnavailable, run_monitor
from reports.reporter import Reporter
from security.hmac_manager import HMACConfigurationError, HMACManager


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="LogGuard — log file integrity monitoring")
    parser.add_argument("--config", default="config.yaml", help="configuration file (default: config.yaml)")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("add", "remove", "verify"):
        command = sub.add_parser(name, help=f"{name.capitalize()} a monitored file")
        command.add_argument("path", type=Path)
    for name, help_text in (
            ("scan", "Verify all monitored files"), ("status", "Show current known states"),
            ("alerts", "Show integrity alerts"), ("history", "Show audit history"),
            ("monitor", "Monitor registered files in real time"),
    ):
        sub.add_parser(name, help=help_text)
    return parser


def configure_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(filename=log_path, level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def run(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config))
    configure_logging(config.log_path)
    database = Database(config.database_path)
    database.initialize()
    hmac_manager = HMACManager.from_environment()
    alerts = AlertManager(database, console=config.console_alerts)
    baseline = BaselineManager(database, hmac_manager)
    verifier = Verifier(database, hmac_manager, alerts)
    reporter = Reporter()
    if args.command == "add":
        record = baseline.add(args.path)
        print("[+] File added successfully\n[+] Baseline created")
        print(f"File: {record.file_path}\nSHA256: {record.baseline_hash}")
    elif args.command == "remove":
        removed = baseline.remove(args.path)
        print("[+] File removed from monitoring" if removed else "[-] File is not monitored")
        return 0 if removed else 1
    elif args.command == "verify":
        result = verifier.verify(args.path)
        reporter.verification(result)
        return 0 if result.status is IntegrityStatus.SAFE else 2
    elif args.command == "scan":
        reporter.scan(Scanner(database, verifier).scan_all())
    elif args.command == "status":
        reporter.status(database.list_monitored_files())
    elif args.command == "alerts":
        reporter.alerts(database.list_alerts())
    elif args.command == "history":
        reporter.history(database.list_audit_logs())
    elif args.command == "monitor":
        run_monitor(database, verifier, config.scan_interval)
    return 0


def main() -> int:
    try:
        return run(build_parser().parse_args())
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
        return 130
    except (ConfigError, HMACConfigurationError, ValueError, OSError, WatcherUnavailable) as exc:
        logging.exception("Command failed")
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        logging.exception("Unexpected failure")
        print(f"Error: operation failed ({exc})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
