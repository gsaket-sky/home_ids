"""
alert_logger.py – Append-only JSON alert log with size cap.

Writes one JSON object per line (JSON Lines format) to alerts.jsonl in
the working directory. Capped at 1 GB: when the file would exceed the
cap, the oldest ~10% of lines are trimmed off the front before appending,
so the file self-prunes instead of growing forever or refusing to write.

Why JSON Lines instead of one big JSON array:
  • Appending a line is O(1) — never need to re-read/re-parse the whole
    file just to add one alert.
  • Trimming is a simple "drop first N lines" operation.
  • Tools like `jq`, `grep`, log shippers all handle JSONL natively.

Thread-safety: a single Lock guards read-trim-write so the size check
and the append can't race across the alert-sending thread and the main
scoring loop calling log_alert() concurrently.
"""

import json
import os
import threading
import time
from pathlib import Path

LOGGER_NAME = "home_ids.alert_log"

_MAX_BYTES   = 1 * 1024 * 1024 * 1024   # 1 GB hard cap
_TRIM_TARGET = 0.90                      # trim down to 90% of cap when exceeded


class AlertLogger:
    def __init__(self, path: str = "alerts.jsonl", max_bytes: int = _MAX_BYTES):
        self.path      = Path(path)
        self.max_bytes = max_bytes
        self._lock     = threading.Lock()

    def log_alert(self, alert: dict) -> None:
        """
        Append one alert record as a single JSON line.
        alert must be JSON-serialisable (floats/ints/str/list/dict only).
        """
        record = dict(alert)
        record.setdefault("logged_at", time.strftime("%Y-%m-%dT%H:%M:%S"))
        record.setdefault("logged_at_epoch", time.time())

        line = json.dumps(record, separators=(",", ":"), default=str) + "\n"

        with self._lock:
            try:
                if self.path.exists() and self.path.stat().st_size + len(line) > self.max_bytes:
                    self._trim_locked()
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line)
            except Exception:
                # Alert logging must never crash the scoring loop.
                import logging
                logging.getLogger(LOGGER_NAME).exception("Failed to write alert log")

    def _trim_locked(self) -> None:
        """
        Drop the oldest lines until the file is back under
        _TRIM_TARGET * max_bytes. Caller must hold self._lock.
        """
        try:
            target_size = int(self.max_bytes * _TRIM_TARGET)
            with open(self.path, "rb") as f:
                data = f.read()
            if len(data) <= target_size:
                return
            # Find a newline boundary at or after (len(data) - target_size)
            cut_at   = len(data) - target_size
            nl_index = data.find(b"\n", cut_at)
            if nl_index == -1:
                # No newline found after cut point — drop everything
                trimmed = b""
            else:
                trimmed = data[nl_index + 1:]
            tmp = self.path.with_suffix(".tmp")
            with open(tmp, "wb") as f:
                f.write(trimmed)
            os.replace(tmp, self.path)
        except Exception:
            import logging
            logging.getLogger(LOGGER_NAME).exception("Failed to trim alert log")
