"""
config.py – Configuration management.
"""
import json
import os
import threading
import time
import logging
from pathlib import Path

LOGGER = logging.getLogger("home_ids.config")
CONFIG_FILE = Path(__file__).parent / "config.json"

# Fully Restored Default Configuration Dictionary
DEFAULT_CONFIG = {
    # Core Engine Timings & Limits
    "poll_interval": 2.0,
    "window_seconds": 300,
    "startup_lookback_seconds": 300,
    "max_device_states": 5000,
    "log_level": "INFO",

    # Threat Scoring & ML Engine
    "alert_threshold": 6.0,
    "threshold_std_dev": 3.0,
    "baseline_alpha": 0.05,
    "ml_warmup_samples": 5000,
    
    # State & Model Persistence
    "state_path": "state/ids_state.json",
    "model_path": "state/ids_model.pkl",
    "alert_json_path": "alerts.json",
    "alert_json_max_bytes": 1073741824,

    # Network Environment & Integration
    "pihole_db": "/etc/pihole/pihole-FTL.db",
    "zeek_log_dir": "/opt/zeek/logs/current",
    "home_subnet": "192.168.178.0/24",
    "metrics_port": 9105,

    # Geographic Intelligence
    "geoip_db": "GeoLite2-City.mmdb",
    "geoip_asn_db": "", 

    # Threat Intelligence Feeds
    "ti_refresh_interval": 3600,
    "otx_api_key": "",
    "abuseipdb_api_key": "",
    "virustotal_api_key": "",

    # Alert Delivery
    "telegram_enabled": False,
    "telegram_token": "",
    "telegram_chat_id": "",

    # Safelists & Overrides
    "safe_ips": ["127.0.0.1"],
    "safe_host_patterns": [],
    "device_type_overrides": {},
    "per_device_thresholds": {}
}

class LiveConfig:
    def __init__(self, default_config: dict, file_path: Path):
        self.file_path = file_path
        self._config = dict(default_config)
        self._lock = threading.Lock()
        self._notify_cb = None
        self._last_loaded = 0.0
        self._load()

    def _load(self) -> None:
        if not self.file_path.exists():
            try:
                self.file_path.write_text(json.dumps(self._config, indent=2))
                LOGGER.info("Created default configuration file at %s", self.file_path)
            except Exception as exc:
                LOGGER.error("Failed to create default config: %s", exc)
            return

        try:
            raw = json.loads(self.file_path.read_text())
            changed = {}
            with self._lock:
                for k, v in raw.items():
                    if k in self._config and self._config[k] != v:
                        changed[k] = v
                    self._config[k] = v
            
            self._last_loaded = time.time()
            if changed:
                LOGGER.info("Dynamic configuration reload detected changes: %s", list(changed.keys()))
                if self._notify_cb:
                    self._notify_cb(changed)
        except Exception as exc:
            LOGGER.error("Failed to parse configuration file %s: %s", self.file_path, exc)

    def start_watcher(self, interval: float = 5.0) -> None:
        def _watch():
            while True:
                time.sleep(interval)
                try:
                    mtime = self.file_path.stat().st_mtime
                    if mtime > self._last_loaded:
                        LOGGER.debug("Configuration file modification detected, triggering reload.")
                        self._load()
                except Exception:
                    pass
        t = threading.Thread(target=_watch, daemon=True, name="config-watcher")
        t.start()
        LOGGER.info("Configuration live-watcher started (interval=%.1fs)", interval)

    def set_notify(self, cb) -> None:
        self._notify_cb = cb

    def get(self, key: str, default=None):
        with self._lock:
            return self._config.get(key, default)

    def __getitem__(self, key: str):
        with self._lock:
            return self._config[key]

CONFIG = LiveConfig(DEFAULT_CONFIG, CONFIG_FILE)