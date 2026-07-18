"""
config.py – Configuration management engine.

Tracks and parses the config.json file, supplying safe defaults if the file 
does not exist, and incorporates a live background thread watcher to handle
dynamic config reloads on the fly without daemon disruption.

FIX: Fully enforces environment variable overrides natively inside the config engine.
Modules like main.py and ips.py no longer poll os.environ directly.
"""
import json
import os
import threading
import time
import logging
from pathlib import Path

LOGGER = logging.getLogger("home_ids.config")
CONFIG_FILE = Path(__file__).parent / "config.json"

# systemd Environment= overrides (see myscript.service) — env wins over config.json
_ENV_OVERRIDES = {
    "IDS_TELEGRAM_TOKEN":     "telegram_token",
    "IDS_TELEGRAM_CHAT_ID":   "telegram_chat_id",
    "IDS_OTX_API_KEY":        "otx_api_key",
    "IDS_ABUSEIPDB_KEY":      "abuseipdb_api_key",
    "IDS_VIRUSTOTAL_KEY":     "virustotal_api_key",
    "PIHOLE_API_PASSWORD":    "pihole_api_password",
    "PIHOLE_API_URL":         "pihole_api_url",
    "IDS_ROUTER_WEBHOOK_URL": "router_webhook_url",
}

def apply_env_overrides(config: dict) -> None:
    """Merge process environment into config (secrets stay out of config.json)."""
    for env_key, cfg_key in _ENV_OVERRIDES.items():
        val = os.environ.get(env_key)
        if val:
            config[cfg_key] = val
            
    # Auto-enable IPS if the environment flag is passed
    ips_flag = os.environ.get("IDS_IPS_ENABLED")
    if ips_flag is not None:
        config["ips_enabled"] = ips_flag.strip().lower() in ("1", "true", "yes", "on")

DEFAULT_CONFIG = {
    "poll_interval": 2.0,
    "window_seconds": 300,
    "startup_lookback_seconds": 300,
    "max_device_states": 5000,
    "log_level": "INFO",
    "alert_threshold": 6.0,
    "threshold_std_dev": 3.0,
    "baseline_alpha": 0.05,
    "ml_warmup_samples": 5000,
    "state_path": "state/ids_state.json",
    "model_path": "state/ids_model.pkl",
    "alert_json_path": "alerts.json",
    "alert_json_max_bytes": 1073741824,
    "pihole_db": "/etc/pihole/pihole-FTL.db",
    "zeek_log_dir": "/opt/zeek/logs/current",
    "home_subnet": "192.168.178.0/24",
    "metrics_port": 9105,
    "geoip_db": "GeoLite2-City.mmdb",
    "geoip_asn_db": "", 
    "ti_refresh_interval": 3600,
    "otx_api_key": "",
    "abuseipdb_api_key": "",
    "virustotal_api_key": "",
    "telegram_enabled": False,
    "telegram_token": "",
    "telegram_chat_id": "",
    "safe_ips": ["127.0.0.1"],
    "safe_host_patterns": [],
    "device_type_overrides": {},
    "per_device_thresholds": {},
    "ips_enabled": False,
    "pihole_api_url": "http://localhost",
    "pihole_api_password": "",
    "router_webhook_url": ""
}

class LiveConfig:
    """Provides thread-safe, dynamic configuration access."""
    def __init__(self, default_config: dict, file_path: Path):
        self.file_path = file_path
        self._config = dict(default_config)
        self._lock = threading.Lock()
        self._notify_cb = None
        self._last_loaded = 0.0
        # Ensure environment variables are loaded immediately on boot
        apply_env_overrides(self._config)
        self._load()

    def _load(self) -> None:
        """Loads configuration from disk, applying defaults and env overrides."""
        if not self.file_path.exists():
            try:
                self.file_path.parent.mkdir(parents=True, exist_ok=True)
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
                
                # Enforce environment overrides over any on-disk JSON modifications
                apply_env_overrides(self._config)
            
            self._last_loaded = time.time()
            if changed:
                LOGGER.info("Dynamic configuration reload detected changes: %s", list(changed.keys()))
                if self._notify_cb:
                    self._notify_cb(changed)
        except Exception as exc:
            LOGGER.error("Failed to parse configuration file %s: %s", self.file_path, exc)

    def start_watcher(self, interval: float = 5.0) -> None:
        """Spawns a daemon thread to monitor the configuration file for changes."""
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
        """Registers a callback function to fire when configuration values change."""
        self._notify_cb = cb

    def get(self, key: str, default=None):
        """Thread-safe retrieval of a configuration value."""
        with self._lock:
            return self._config.get(key, default)

    def __getitem__(self, key: str):
        with self._lock:
            return self._config[key]

CONFIG = LiveConfig(DEFAULT_CONFIG, CONFIG_FILE)