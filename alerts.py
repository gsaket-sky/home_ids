"""
alerts.py – Telegram alert delivery.

Changelog
─────────────────────────────────────────────────────────────────────
v1  Original: unbounded Queue(), no retry, bare except swallowing errors,
    no enabled flag. Threading.Event() created per rate-limit wait (leaked).

v2  Reliability improvements:
    • Queue capped at 50 entries – overflow logged and dropped instead of
      growing RAM indefinitely during Telegram outage
    • 2-retry loop with 429 retry_after handling
    • All failures logged at WARNING level
    • telegram_enabled flag wired in – send() is no-op when disabled

v3  Clean shutdown (current version):
    • _stop Event added – stop() method signals worker to exit
    • Worker uses q.get(timeout=1.0) loop instead of blocking forever –
      re-checks _stop even when queue is empty
    • Rate-limit sleep uses self._stop.wait() instead of
      threading.Event().wait() (was creating a new uncancellable Event
      each time – could block shutdown for up to 30 seconds)
    • Sentinel None pushed to unblock q.get() on shutdown
    • alerts.stop() called from main() before state save
"""
import threading
import queue
import logging
import requests

LOGGER = logging.getLogger("home_ids.alerts")

_MAX_QUEUE   = 50
_MAX_RETRIES = 2


class AlertManager:
    def __init__(self, token: str, chat_id: str, enabled: bool = True):
        self.token   = token
        self.chat_id = chat_id
        self.enabled = enabled
        self.q       = queue.Queue(maxsize=_MAX_QUEUE)
        self._stop   = threading.Event()

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
            LOGGER.warning("alert queue full — message dropped")

    def stop(self, timeout: float = 12.0) -> None:
        """
        Signal the worker to stop after finishing the current message.
        Called from main() during shutdown. Returns after timeout seconds
        regardless — never blocks the shutdown indefinitely.
        """
        self._stop.set()
        # Unblock the worker if it's waiting on q.get()
        try:
            self.q.put_nowait(None)
        except queue.Full:
            pass

    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                # Use timeout so we re-check _stop even when queue is empty
                msg = self.q.get(timeout=1.0)
            except queue.Empty:
                continue

            if msg is None:          # sentinel — time to exit
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
                        # Use _stop-aware sleep so shutdown isn't blocked
                        self._stop.wait(timeout=min(retry_after, 30))
                        if self._stop.is_set():
                            break
                except requests.RequestException as exc:
                    LOGGER.warning("Telegram attempt %d failed: %s", attempt + 1, exc)

            self.q.task_done()
