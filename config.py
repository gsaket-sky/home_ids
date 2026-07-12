"""
config.py – Configuration loading with hot-reload support and Environment Variable injections.

Changelog
─────────────────────────────────────────────────────────────────────
v1  Original: DEFAULT_CONFIG missing keys, no error handling.
v2  All keys added with defaults, try/except on JSON parse.
v3  New keys: zeek_log_dir, otx_api_key, ti_refresh_interval,
    safe_ips, device_type_overrides.
v4  Hot-reload: ConfigWatcher background thread polls config.json.
v5  Environment Variable Hardening (Current Version):
    • Intercepts configuration assembly to pull system environment variables
      (IDS_TELEGRAM_TOKEN, IDS_TELEGRAM_CHAT_ID, IDS_OTX_API_KEY).
    • Sanitizes and injects environment configurations transparently across workers.
    • IDS_ABUSEIPDB_KEY and IDS_VIRUSTOTAL_KEY for optional enrichment feeds.

Codex changelog 2026-06-18:
  - Added alert_json_path and alert_json_max_bytes defaults for capped alert file logging.
  - Added safe_host_patterns defaults for Pi-hole hostname exclusion.
  - safe_ips remains the direct IP allowlist for DNS servers and other infrastructure.
"""

import json
import logging
import os
import threading
import time
from pathlib import Path

LOGGER = logging.getLogger("home_ids.config")
CONFIG_FILE = Path(__file__).parent / "config.json"

DEFAULT_CONFIG = {
    "poll_interval": 2,
    "window_seconds": 300,
    "startup_lookback_seconds": 300,
    "alert_threshold": 6.0,
    "threshold_std_dev": 3.0,
    "per_device_thresholds": {},
    "ml_warmup_samples": 5000,
    "baseline_alpha": 0.05,
    "decay_factor": 0.995,
    "state_path": "state/ids_state.json",
    "model_path": "models/ids_model.pkl",
    "max_device_states": 5000,
    "geoip_db": "../geoiop/GeoLite2-City.mmdb",
    "telegram_enabled": True,
    "telegram_token": "",
    "telegram_chat_id": "",
    "metrics_port": 9105,
    "log_level": "INFO",
    "zeek_log_dir": "/opt/zeek/logs/current",
    "otx_api_key": "",
    "abuseipdb_api_key": "",
    "virustotal_api_key": "",
    "ti_refresh_interval": 3600,
    "safe_ips": ["127.0.0.1"],
    "safe_host_patterns": ["pihole", "pi-hole", "pi_hole", "pi.hole"],
    "device_type_overrides": {},
    "alert_json_path": "alerts.json",
    "alert_json_max_bytes": 1073741824,
}


class LiveConfig:
    def __init__(self, initial_config: dict):
        self._config = initial_config
        self._lock = threading.Lock()
        self._mtime = 0
        self._notify_cb = None

        if CONFIG_FILE.exists():
            self._mtime = CONFIG_FILE.stat().st_mtime

    def get(self, key: str, default=None):
        with self._lock:
            return self._config.get(key, default)

    def __getitem__(self, key: str):
        with self._lock:
            return self._config[key]

    def set_notify(self, callback) -> None:
        self._notify_cb = callback

    def reload(self) -> None:
        """Reloads config from JSON while maintaining environment variable overrides."""
        try:
            new_raw = _build_initial()
            changed = {}

            with self._lock:
                # Identify actual mutations for the logging/notification matrix
                for k, v in new_raw.items():
                    if k in self._config and self._config[k] != v:
                        changed[k] = v
                self._config = new_raw

            if changed and self._notify_cb:
                LOGGER.info("Configuration change detected dynamically: %s", changed)
                self._notify_cb(changed)

        except Exception:
            LOGGER.exception("Failed executing runtime hot-reload configuration pass")


    def start_watcher(self, interval: float = 5.0) -> None:
        t = threading.Thread(
            target=self._watcher_loop,
            args=(interval,),
            daemon=True,
            name="config-watcher",
        )
        t.start()
        LOGGER.info("Config watcher started (polling every %.0fs)", interval)

    def _watcher_loop(self, interval: float) -> None:
        while True:
            try:
                if CONFIG_FILE.exists():
                    mtime = CONFIG_FILE.stat().st_mtime
                    if mtime != self._mtime:
                        self._mtime = mtime
                        time.sleep(0.2)  # Short pause to prevent partial reads
                        self.reload()
            except Exception:
                LOGGER.exception("Config watcher tracking thread error")
            time.sleep(interval)


def _build_initial() -> dict:
    """Combines defaults, configuration JSON files, and active system environment values."""
    cfg = DEFAULT_CONFIG.copy()
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text())
            cfg.update(data)
        except Exception as e:
            print(f"[config] WARNING: could not parse config.json: {e} — using fallback stack")

    # Intercept configurations and overlay active environment variables
    env_token = os.environ.get("IDS_TELEGRAM_TOKEN")
    env_chat  = os.environ.get("IDS_TELEGRAM_CHAT_ID")
    env_otx   = os.environ.get("IDS_OTX_API_KEY")
    env_abuse = os.environ.get("IDS_ABUSEIPDB_KEY")
    env_vt    = os.environ.get("IDS_VIRUSTOTAL_KEY")

    if env_token:
        cfg["telegram_token"] = env_token.strip()
    if env_chat:
        cfg["telegram_chat_id"] = env_chat.strip()
    if env_otx:
        cfg["otx_api_key"] = env_otx.strip()
    if env_abuse:
        cfg["abuseipdb_api_key"] = env_abuse.strip()
    if env_vt:
        cfg["virustotal_api_key"] = env_vt.strip()

    return cfg


# Live configuration manager reference engine
CONFIG = LiveConfig(_build_initial())
