"""
alerts.py - Telegram alert delivery plus capped JSON alert logging.

Provides the alerting pipeline that streams data to Loki/Promtail in structured JSON format
while concurrently firing asynchronous alerts out to external API channels (Telegram).
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
    Writes alerts to a dual-format JSON store.
    1. A persistent history JSON block pruned safely at boundaries.
    2. An append-only JSONL stream optimized for Loki ingest parsing.
    """
    _SCHEMA = "home_ids_alerts_v2"

    def __init__(self, path: str = "alerts.json", max_bytes: int = _DEFAULT_ALERT_FILE_MAX_BYTES):
        self.path = Path(path)
        self.jsonl_path = self.path.with_name(self.path.with_suffix("").name + "_stream.jsonl")
        self.max_bytes = max(1024 * 1024, int(max_bytes or _DEFAULT_ALERT_FILE_MAX_BYTES))
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, payload: dict) -> None:
        """Saves a structured alert event concurrently across tracking files."""
        record = dict(payload)
        record.setdefault("schema", self._SCHEMA)
        record.setdefault("created_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

        with self._lock:
            try:
                alerts = self._load()
                alerts.append(record)
                alerts = self._trim_to_fit(alerts)
                self._save(alerts)
            except Exception as exc:
                LOGGER.warning("Could not write alert JSON: %s", exc)

            try:
                self._write_jsonl_stream(record)
            except Exception as exc:
                LOGGER.warning("Could not write streaming JSONL token: %s", exc)

    def _write_jsonl_stream(self, record: dict) -> None:
        """Fires single-line payloads that Grafana/Loki parse locally. Capped at 100MB."""
        try:
            if self.jsonl_path.exists() and self.jsonl_path.stat().st_size > 100 * 1024 * 1024:
                old_file = self.jsonl_path.with_suffix(".jsonl.old")
                if old_file.exists():
                    old_file.unlink()
                self.jsonl_path.rename(old_file)
        except Exception as exc:
            LOGGER.warning("Failed to rotate JSONL Loki file structure: %s", exc)
            
        with open(self.jsonl_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")

    def _load(self) -> list:
        old_jsonl = self.path.with_suffix(".jsonl")
        if not self.path.exists() and old_jsonl.exists():
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
            if isinstance(doc, list):
                return doc
        except Exception as exc:
            LOGGER.warning("Could not parse %s — starting fresh", self.path)
        return []

    @staticmethod
    def _load_jsonl(path: Path) -> list:
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
        while len(alerts) > 1:
            candidate = self._serialise(alerts)
            if len(candidate.encode("utf-8")) <= self.max_bytes:
                break
            drop = max(1, len(alerts) // 10)   
            alerts = alerts[drop:]
            LOGGER.info("Alert log size cap reached — dropped %d oldest alerts (%d remain)", drop, len(alerts))
        return alerts

    def _serialise(self, alerts: list) -> str:
        doc = {
            "meta": {
                "schema": self._SCHEMA,
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "total_alerts": len(alerts),
                "max_bytes": self.max_bytes,
            },
            "alerts": alerts,
        }
        return json.dumps(doc, indent=2, default=str)

    def _save(self, alerts: list) -> None:
        """Atomic append protection via OS file replacement hooks."""
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(self._serialise(alerts), encoding="utf-8")
        tmp.replace(self.path)   

class AlertManager:
    """Manages the remote delivery of alerts over Telegram via background queues."""
    def __init__(self, token: str, chat_id: str, enabled: bool = True):
        self.token = token
        self.chat_id = chat_id
        self.enabled = enabled
        self.q = queue.Queue(maxsize=_MAX_QUEUE)
        self._stop = threading.Event()
        threading.Thread(target=self._worker, daemon=True, name="alert-worker").start()

    def send(self, message: str) -> None:
        if not self.enabled or self._stop.is_set():
            return
        try:
            self.q.put_nowait(message)
        except queue.Full:
            LOGGER.warning("Alert queue full - message dropped")
            pass

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
                        LOGGER.debug("Telegram alert sent successfully.")
                        break
                    if resp.status_code == 429:
                        retry_after = int(resp.json().get("parameters", {}).get("retry_after", 5))
                        LOGGER.warning("Telegram rate-limited, sleeping %ds", retry_after)
                        self._stop.wait(timeout=min(retry_after, 30))
                        if self._stop.is_set():
                            break
                    else:
                        LOGGER.warning("Telegram returned HTTP %s", resp.status_code)
                except requests.RequestException as exc:
                    LOGGER.warning("Telegram attempt %d failed: %s", attempt + 1, exc)
                    pass
            self.q.task_done()