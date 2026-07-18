"""
ips.py - IPS Auto-Mitigation Engine
Handles dynamic Pi-hole API blocks and Router Webhook drops.

RECENT FIXES:
- Centralized environment variable checks into config.py.
- Corrected JSONL log pathing to match main engine, fixing Loki visibility.
- Intercepted Pi-hole HTTP 400 "already present" errors to stop infinite retry loops.
- Added strict memory caps (1000-20000 limits) on state dictionaries to prevent OOM DOS attacks.
- Removed strict MAC requirement for router isolation, allowing IP fallback for static devices.
"""
import json
import logging
import ssl
import threading
import time
import urllib.request
from pathlib import Path
from metrics import (
    ips_status_metric, ips_pihole_blocks_metric, 
    ips_isolations_metric, ips_errors_metric
)

LOGGER = logging.getLogger("home_ids.ips")

class IPSMitigator:
    def __init__(self, config):
        if config is None: 
            config = {}

        # Store a live reference to the config engine
        self.config = config

        self.enabled = config.get("ips_enabled", False)
        self.pihole_url = config.get("pihole_api_url", "http://localhost").rstrip("/")
        
        # Uses config engine directly (which has already processed environment overrides)
        self.pihole_pwd = config.get("pihole_api_password", "")
        self.webhook_url = config.get("router_webhook_url", "")
        
        # FIX: Dynamically construct the correct JSONL stream path to match alerts.py exactly
        # This ensures Loki ingest works and prevents corrupting the monolithic alerts.json file
        base_path = Path(config.get("alert_json_path", "alerts.json"))
        self.log_path = base_path.with_name(base_path.with_suffix("").name + "_stream.jsonl")
        
        # FIX: Load case-insensitive domain safe list cleanly
        self.safe_domains = {str(d).lower().strip() for d in config.get("safe_domains", [])}

        # Capped sets to prevent memory explosion
        self.blocked_domains = set()
        self.isolated_macs = set()
        
        # Background Retry Infrastructure
        self.failed_blocks_queue = set()
        self._queue_lock = threading.Lock()
        
        # Active Session ID Cache for v6
        self._v6_sid = None
        
        if self.enabled:
            threading.Thread(target=self._retry_loop, daemon=True, name="ips-retry-worker").start()

    def _log_to_jsonl(self, message: str, action: str, target: str, device_id: str, hostname: str):
        """Standardized JSON log to perfectly match the main engine for Loki indexing."""
        payload = {
            "timestamp": time.time(),
            "event_type": "ips_action",
            "device": {
                "id": device_id,
                "hostname": hostname
            },
            "action": action,
            "target": target,
            "message": message,
            "schema": "home_ids_alerts_v2"
        }
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload) + "\n")
        except Exception as e:
            LOGGER.error("Failed to write IPS action to JSONL file: %s", e)

    def mitigate(self, st, top_domain: str, risk_score: float, c2_hits: float, dga_burst: bool):
        ips_status_metric.set(1.0 if self.enabled else 0.0)
        if not self.enabled: 
            return

        # Fetch the latest array dynamically from the background watcher
        safe_domains = {str(d).lower().strip() for d in self.config.get("safe_domains", [])}

        # FIX: Instantly drop mitigation routine if target domain is safe-listed
        if top_domain and str(top_domain).lower().strip() in safe_domains:
            LOGGER.info("🛡️ IPS BYPASS: Anomaly detected against safe-listed domain: %s", top_domain)
            return
        
        str_dev_id = str(getattr(st, "device_id", "unknown"))
        str_host = str(getattr(st, "hostname", "unknown"))

        # =====================================================================
        # 1. PI-HOLE DOMAIN MITIGATION
        # =====================================================================
        if top_domain and top_domain not in self.blocked_domains:
            # Memory cap to prevent explosion if under extreme attack
            if len(self.blocked_domains) > 20000:
                self.blocked_domains.clear()

            if risk_score >= 8.0 or c2_hits > 0 or dga_burst:
                success = self._block_pihole_domain(top_domain)
                if success:
                    self.blocked_domains.add(top_domain)
                    ips_pihole_blocks_metric.labels(str_dev_id, str_host, str(top_domain)).inc()
                    
                    # SYNCED: Log to JSONL and Console only on absolute success
                    msg = f"Blacklisting malicious domain {top_domain} via Pi-hole v6 REST API"
                    LOGGER.critical("🚨 IPS ACTION: %s", msg)
                    self._log_to_jsonl(msg, "pihole_block", top_domain, str_dev_id, str_host)
                else:
                    ips_errors_metric.labels(target_type="pihole").inc()
                    with self._queue_lock:
                        # Cap the retry queue to 1000 to prevent memory leak
                        if len(self.failed_blocks_queue) < 1000:
                            self.failed_blocks_queue.add((str_dev_id, str_host, top_domain))

        # =====================================================================
        # 2. HARDWARE WEBHOOK DROP LOGIC
        # =====================================================================
        mac = getattr(st, "mac_address", None)
        client_ip = getattr(st, "client_ip", "unknown")
        
        # FIX: Do not skip isolation if MAC is missing (e.g. static IP or missed Zeek DHCP binding).
        # Fallback to the client IP address to ensure 10.0 risk threats are not given immunity.
        isolation_key = mac if mac else client_ip

        if risk_score >= 8.0 and isolation_key not in self.isolated_macs:
            # Memory cap tracking set to prevent OOM
            if len(self.isolated_macs) > 1000:
                self.isolated_macs.clear()

            # Pass 'unknown' if mac is None, relying on the router to use the IP address
            success = self._isolate_device_webhook(client_ip, mac or "unknown")
            if success:
                self.isolated_macs.add(isolation_key)
                ips_isolations_metric.labels(str_dev_id, str_host, str(isolation_key)).inc()
                
                msg = f"Transmitting hardware network drop request for Target: {isolation_key}"
                LOGGER.critical("🚨 IPS ACTION: %s", msg)
                self._log_to_jsonl(msg, "hardware_drop", isolation_key, str_dev_id, str_host)
            else:
                ips_errors_metric.labels(target_type="router_webhook").inc()

    def _authenticate_v6(self, ctx) -> bool:
        """Executes the Pi-hole v6 login handshake to obtain a Session ID."""
        if not self.pihole_pwd: return False
        
        auth_url = f"{self.pihole_url}/api/auth"
        auth_payload = json.dumps({"password": self.pihole_pwd}).encode('utf-8')
        req = urllib.request.Request(auth_url, data=auth_payload, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        
        try:
            with urllib.request.urlopen(req, timeout=5, context=ctx) as response:
                data = json.loads(response.read().decode('utf-8'))
                sid = data.get("session", {}).get("sid")
                if sid:
                    self._v6_sid = sid
                    return True
        except Exception as e:
            LOGGER.error("IPS Pi-hole v6 Authentication Failed: %s", e)
        return False

    def _block_pihole_domain(self, domain: str) -> bool:
        if not self.pihole_pwd and self.pihole_url != "mock": 
            return False
            
        try:
            if self.pihole_url == "mock": 
                return True
                
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            # If we don't have a session ID yet, login first
            if not self._v6_sid:
                if not self._authenticate_v6(ctx):
                    return False
            
            url = f"{self.pihole_url}/api/domains/deny/exact"
            payload = json.dumps({"domain": domain}).encode('utf-8')
            
            req = urllib.request.Request(url, data=payload, method="POST")
            req.add_header('Content-Type', 'application/json')
            req.add_header('Accept', 'application/json')
            req.add_header('X-FTL-SID', self._v6_sid) 
            
            with urllib.request.urlopen(req, timeout=5, context=ctx) as response:
                if response.status in [200, 201]:
                    return True
                return False
                    
        except urllib.error.HTTPError as e:
            if e.code == 401:
                # Session expired! Clear the SID so it re-authenticates on the next attempt
                LOGGER.warning("IPS Pi-hole v6 Session Expired. Forcing re-authentication.")
                self._v6_sid = None
            elif e.code == 400:
                # FIX: Catch 'already present' JSON body and treat as success to stop infinite retries
                error_body = e.read().decode('utf-8')
                if "already present" in error_body.lower() or "database_error" in error_body.lower():
                    LOGGER.debug("Pi-hole block skipped: Domain already present in gravity database.")
                    return True
                else:
                    LOGGER.error("IPS Pi-hole v6 API HTTP 400: %s", error_body)
            else:
                LOGGER.error("IPS Pi-hole v6 API HTTP %s: %s", e.code, e.read().decode('utf-8'))
            return False
        except Exception as e:
            LOGGER.error("IPS Pi-hole v6 API connection failed: %s", e)
            return False

    def _isolate_device_webhook(self, ip: str, mac: str) -> bool:
        """Transmits network drop instructions to core routing hardware."""
        if not self.webhook_url and self.webhook_url != "mock": 
            return False
        try:
            if self.webhook_url == "mock": 
                return True
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(self.webhook_url, method="POST")
            req.add_header('Content-Type', 'application/json')
            # The router endpoint receives both IP and MAC, allowing it to apply blocks via either metric.
            data = json.dumps({"action": "isolate", "ip": ip, "mac": mac, "reason": "Home IDS Severe Threat Ceiling Breach"})
            urllib.request.urlopen(req, data=data.encode('utf-8'), timeout=5, context=ctx)
            return True
        except Exception as e:
            # Fallback to identifying the device by IP in logs if MAC is 'unknown'
            LOGGER.error("IPS Router webhook isolation failed for %s (IP: %s): %s", mac, ip, e)
            return False

    def _retry_loop(self):
        """Background thread designed to enforce Pi-hole blocks if the API temporarily drops."""
        while True:
            time.sleep(30)
            with self._queue_lock:
                if not self.failed_blocks_queue:
                    continue
                # Snapshot the queue so we don't hold the lock during network I/O
                current_queue = list(self.failed_blocks_queue)
                
            for item in current_queue:
                str_dev_id, str_host, domain = item
                if domain in self.blocked_domains:
                    with self._queue_lock:
                        self.failed_blocks_queue.discard(item)
                    continue
                    
                success = self._block_pihole_domain(domain)
                if success:
                    self.blocked_domains.add(domain)
                    ips_pihole_blocks_metric.labels(str_dev_id, str_host, str(domain)).inc()
                    
                    msg = f"[RETRY SUCCESS] Blacklisting malicious domain {domain} via Pi-hole v6"
                    LOGGER.critical("✅ IPS ACTION: %s", msg)
                    self._log_to_jsonl(msg, "pihole_block", domain, str_dev_id, str_host)
                    
                    with self._queue_lock:
                        self.failed_blocks_queue.discard(item)
                else:
                    ips_errors_metric.labels(target_type="pihole_retry").inc()