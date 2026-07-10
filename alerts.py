"""
alerts.py - Telegram alert delivery plus capped JSON alert logging.

Codex changelog 2026-06-18:
  - Added AlertJSONWriter for newline-delimited JSON alert logs.
  - Active alert log is capped at 1 GB by default and rotates to .1 when full.
  - Telegram delivery remains asynchronous with retry/rate-limit handling.
"""
import json
import logging
import queue
import threading
import time
from pathlib import Path

import requests

LOGGER = logging.getLogger("home_ids.alerts")

_MAX_QUEUE = 50
_MAX_RETRIES = 2
_DEFAULT_ALERT_FILE_MAX_BYTES = 1024 * 1024 * 1024


class AlertJSONWriter:
    """
    Writes alerts to a proper JSON file: {"meta": {...}, "alerts": [...]}

    Strategy — atomic append via tmp-file rename:
      1. Read and parse the existing file (or start fresh).
      2. Append the new record to the in-memory list.
      3. If the resulting JSON would exceed max_bytes, trim the oldest
         entries from the front until it fits (keeps the most recent alerts).
      4. Write the full document to a .tmp file.
      5. Rename .tmp → .json  (atomic on Linux/POSIX).

    This means:
      • The file is always valid, pretty-printed JSON — open it in any
        viewer, jq, Python, or browser and it just works.
      • A crash during write never corrupts the existing file; the previous
        good version is preserved until the rename succeeds.
      • Rotation: when the file reaches max_bytes, oldest alerts are pruned
        automatically rather than being thrown away in a hard rotate.

    File format:
      {
        "meta": {
          "schema":       "home_ids_alerts_v2",
          "generated_at": "2026-06-19T12:00:00Z",
          "total_alerts": 42,
          "max_bytes":    1073741824
        },
        "alerts": [ { ... }, { ... }, ... ]
      }
    """

    _SCHEMA = "home_ids_alerts_v2"

    def __init__(self, path: str = "alerts.json",
                 max_bytes: int = _DEFAULT_ALERT_FILE_MAX_BYTES):
        self.path      = Path(path)
        self.max_bytes = max(1024 * 1024, int(max_bytes or _DEFAULT_ALERT_FILE_MAX_BYTES))
        self._lock     = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ── public interface ───────────────────────────────────────────────────

    def write(self, payload: dict) -> None:
        """Append one alert record to the JSON file atomically."""
        record = dict(payload)
        record.setdefault("schema",     self._SCHEMA)
        record.setdefault("created_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

        with self._lock:
            try:
                alerts = self._load()
                alerts.append(record)
                alerts = self._trim_to_fit(alerts)
                self._save(alerts)
            except Exception as exc:
                LOGGER.warning("Could not write alert JSON file %s: %s", self.path, exc)

    # ── internals ──────────────────────────────────────────────────────────

    def _load(self) -> list:
        """
        Read the existing file and return its alerts list.
        Returns [] if the file doesn't exist or is malformed.
        Handles both the old JSONL format and the new JSON format so that
        an existing alerts.jsonl can be migrated transparently on first write.
        """
        # Check for old JSONL file (migration path)
        old_jsonl = self.path.with_suffix(".jsonl")
        if not self.path.exists() and old_jsonl.exists():
            LOGGER.info("Migrating %s → %s", old_jsonl.name, self.path.name)
            return self._load_jsonl(old_jsonl)

        if not self.path.exists():
            return []

        try:
            text = self.path.read_text(encoding="utf-8")
            if not text.strip():
                return []
            doc = json.loads(text)
            if isinstance(doc, dict):
                return list(doc.get("alerts", []))
            # Fallback: bare JSON array
            if isinstance(doc, list):
                return doc
        except Exception as exc:
            LOGGER.warning("Could not parse %s (%s) — starting fresh", self.path, exc)
        return []

    @staticmethod
    def _load_jsonl(path: Path) -> list:
        """Read an old JSONL file and return its records as a list."""
        records = []
        try:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        except Exception:
            pass
        return records

    def _trim_to_fit(self, alerts: list) -> list:
        """
        Remove the oldest alerts from the front until the serialised document
        fits within max_bytes. Always keeps at least the most recent alert.
        """
        while len(alerts) > 1:
            candidate = self._serialise(alerts)
            if len(candidate.encode("utf-8")) <= self.max_bytes:
                break
            drop = max(1, len(alerts) // 10)   # drop 10% at a time
            alerts = alerts[drop:]
            LOGGER.info(
                "Alert log size cap reached — dropped %d oldest alerts (%d remain)",
                drop, len(alerts)
            )
        return alerts

    def _serialise(self, alerts: list) -> str:
        doc = {
            "meta": {
                "schema":       self._SCHEMA,
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "total_alerts": len(alerts),
                "max_bytes":    self.max_bytes,
            },
            "alerts": alerts,
        }
        return json.dumps(doc, indent=2, default=str)

    def _save(self, alerts: list) -> None:
        """Write to .tmp then rename → atomic, never corrupts the live file."""
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(self._serialise(alerts), encoding="utf-8")
        tmp.replace(self.path)   # atomic on Linux/POSIX


class AlertManager:
    def __init__(self, token: str, chat_id: str, enabled: bool = True):
        self.token = token
        self.chat_id = chat_id
        self.enabled = enabled
        self.q = queue.Queue(maxsize=_MAX_QUEUE)
        self._stop = threading.Event()

        threading.Thread(
            target=self._worker,
            daemon=True,
            name="alert-worker",
        ).start()

        if not enabled:
            LOGGER.info("Telegram alerts disabled")

    def send(self, message: str) -> None:
        if not self.enabled or self._stop.is_set():
            return
        try:
            self.q.put_nowait(message)
        except queue.Full:
            LOGGER.warning("alert queue full - message dropped")

    def stop(self, timeout: float = 12.0) -> None:
        self._stop.set()
        try:
            self.q.put_nowait(None)
        except queue.Full:
            pass

    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                msg = self.q.get(timeout=1.0)
            except queue.Empty:
                continue

            if msg is None:
                break
            if not self.enabled:
                self.q.task_done()
                continue

            for attempt in range(_MAX_RETRIES):
                try:
                    resp = requests.post(
                        f"https://api.telegram.org/bot{self.token}/sendMessage",
                        json={"chat_id": self.chat_id, "text": msg},
                        timeout=10,
                    )
                    if resp.status_code == 200:
                        break
                    if resp.status_code == 429:
                        retry_after = int(
                            resp.json().get("parameters", {}).get("retry_after", 5)
                        )
                        LOGGER.warning("Telegram rate-limited, sleeping %ds", retry_after)
                        self._stop.wait(timeout=min(retry_after, 30))
                        if self._stop.is_set():
                            break
                    else:
                        LOGGER.warning("Telegram returned HTTP %s", resp.status_code)
                except requests.RequestException as exc:
                    LOGGER.warning("Telegram attempt %d failed: %s", attempt + 1, exc)

            self.q.task_done()
