"""Debounced watchdog monitoring for registered files."""
import time
from pathlib import Path
from core.verifier import Verifier
from database.database import Database


class WatcherUnavailable(RuntimeError):
    """Raised when the optional watchdog dependency is unavailable."""


def run_monitor(database: Database, verifier: Verifier,
                debounce_seconds: float = 1.0) -> None:
    try:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError as exc:
        raise WatcherUnavailable(
            "watchdog is not installed; run pip install -r requirements.txt") from exc
    registered = {item.file_path for item in database.list_monitored_files()}
    if not registered:
        raise ValueError("no files are registered")
    last_event: dict[str, float] = {}

    class Handler(FileSystemEventHandler):
        def on_any_event(self, event) -> None:
            candidates = {str(Path(event.src_path).resolve(strict=False))}
            if getattr(event, "dest_path", None):
                candidates.add(str(Path(event.dest_path).resolve(strict=False)))
            now = time.monotonic()
            for path in candidates & registered:
                if now - last_event.get(path, 0.0) < debounce_seconds:
                    continue
                last_event[path] = now
                time.sleep(min(debounce_seconds, 1.0))
                try:
                    result = verifier.verify(Path(path))
                    print(f"{path}: {result.status.value}", flush=True)
                except OSError as exc:
                    print(f"{path}: verification error: {exc}", flush=True)

    observer, handler = Observer(), Handler()
    for directory in sorted({str(Path(path).parent) for path in registered}):
        observer.schedule(handler, directory, recursive=False)
    observer.start()
    print(f"Monitoring {len(registered)} file(s). Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    finally:
        observer.stop()
        observer.join()
