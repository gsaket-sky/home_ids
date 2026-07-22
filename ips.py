"""
ips.py - IPS Auto-Mitigation Engine
Handles dynamic Pi-hole API blocks and Router Webhook drops.

RECENT FIXES:
- Centralized environment variable checks into config.py.
- Corrected JSONL log pathing to match main engine, fixing Loki visibility.
- Intercepted Pi-hole HTTP 400 "already present" errors to stop infinite retry loops.
- Added strict memory caps (1000-20000 limits) on state dictionaries to prevent OOM DOS attacks.
- Removed strict MAC requirement for router isolation, allowing IP fallback for static devices.
- FIXED: Moved safe_domains bypass inside the DNS mitigation scope to prevent hardware drop blindspots.
- FIXED: Converted all asset configurations to dynamic runtime evaluations via the configuration engine.
- FIXED: Added explicit initialization audit logs to warn users about missing execution targets.
- FIXED: Log routing relies explicitly on main's size-capped AlertJSONWriter instance.
- FIXED: Implemented a 5-minute deduplication cooldown on IPS BYPASS logs to prevent massive log spam from telemetry domains (e.g., Microsoft Teams).
- FIXED (PRODUCTION): Added _internet_verification() via Cloudflare Security DoH (1.1.1.2) with a 1-hour TTL verdict cache to prevent thread-blocking latency.
- FIXED (PRODUCTION): Decoupled DNS Veto from Hardware Router Isolation so network-level threats (SSH scans/exfiltration) are not masked by harmless DNS targets.
- FIXED (SYNTAX): Cleaned up stray conditional import syntax error on pathlib.
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
    def __init__(self, config, stream_writer=None):
        if config is None: 
            config = {}
        self.config = config
        self.stream_writer = stream_writer
        
        # Capped sets to prevent memory explosion
        self.blocked_domains = set()
        self.isolated_macs = set()
        
        # Background Retry Infrastructure
        self.failed_blocks_queue = set()
        self._queue_lock = threading.Lock()
        
        # Active Session ID Cache for v6
        self._v6_sid = None
        
        # Track bypass log timestamps to prevent syslog exhaustion from safe telemetry
        self._last_bypass_log = {}
        
        # TTL Verdict Cache for Internet DoH queries: domain -> (verdict_str, timestamp)
        self._verdict_cache = {}
        
        # Startup Validation Audit Log Engine
        enabled = self.config.get("ips_enabled", False)
        if not enabled:
            LOGGER.info("ℹ️ [IPS] Auto-Mitigation is explicitly disabled via configuration.")
        else:
            pihole_url = self.config.get("pihole_api_url", "http://localhost").rstrip("/")
            pihole_pwd = self.config.get("pihole_api_password", "")
            webhook_url = self.config.get("router_webhook_url", "")
            
            if pihole_url != "mock" and not pihole_pwd:
                LOGGER.error("❌ [IPS] MISCONFIGURATION: 'ips_enabled' is True, but 'pihole_api_password' is empty! Pi-hole domain blocks will fail.")
            if webhook_url != "mock" and not webhook_url:
                LOGGER.error("❌ [IPS] MISCONFIGURATION: 'ips_enabled' is True, but 'router_webhook_url' is empty! Hardware isolation drops will fail.")
            if (pihole_pwd or pihole_url == "mock") and (webhook_url or webhook_url == "mock"):
                LOGGER.info("🚀 [IPS] Auto-Mitigation Engine initialized successfully with active protection.")
                
            threading.Thread(target=self._retry_loop, daemon=True, name="ips-retry-worker").start()

    def _log_to_jsonl(self, message: str, action: str, target: str, device_id: str, hostname: str):
        """Standardized JSON log routing leveraging main's size-capped rotation interface."""
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
        if self.stream_writer:
            try:
                self.stream_writer.write(payload)
            except Exception as e:
                LOGGER.error("Failed to write IPS action via AlertJSONWriter: %s", e)
        else:
            LOGGER.warning("AlertJSONWriter instance absent in IPS environment; mitigation telemetry dropped.")

    def _prune_caches(self, now: float):
        """Centralized cache management to prevent OOM memory growth."""
        if len(self._last_bypass_log) > 5000:
            cutoff = now - 3600
            keys_to_delete = [k for k, v in self._last_bypass_log.items() if v < cutoff]
            for k in keys_to_delete:
                del self._last_bypass_log[k]

        if len(self._verdict_cache) > 5000:
            cutoff = now - 3600
            keys_to_delete = [k for k, (verdict, ts) in self._verdict_cache.items() if ts < cutoff]
            for k in keys_to_delete:
                del self._verdict_cache[k]

    def _internet_verification(self, domain: str) -> str:
        """
        Internet Second-Opinion: Queries Cloudflare's Global Malware-Blocking DNS (1.1.1.2) via DoH.
        Uses an internal 1-hour TTL cache to protect main loop performance.
        """
        now = time.time()
        
        # Check verdict cache first (1-hour TTL = 3600 seconds)
        if domain in self._verdict_cache:
            cached_verdict, ts = self._verdict_cache[domain]
            if now - ts < 3600:
                return cached_verdict

        try:
            url = f"https://security.cloudflare-dns.com/dns-query?name={domain}&type=A"
            req = urllib.request.Request(url, headers={'Accept': 'application/dns-json'})
            
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, timeout=2, context=ctx) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                # Status 3 is NXDOMAIN (Domain is dead or globally sinkholed)
                if data.get("Status") == 3:
                    verdict = "MALICIOUS"
                else:
                    verdict = "HARMLESS"
                    for ans in data.get("Answer", []):
                        # Cloudflare returns 0.0.0.0 for explicitly blocked malware domains
                        if ans.get("data") == "0.0.0.0":
                            verdict = "MALICIOUS"
                            break
                
                self._verdict_cache[domain] = (verdict, now)
                return verdict
        except Exception as e:
            LOGGER.debug("IPS Internet verification failed for %s: %s", domain, e)
            # Do not cache failures; allow retry on next cycle
            return "UNKNOWN"

    def mitigate(self, st, top_domain: str, risk_score: float, c2_hits: float, dga_burst: bool):
        enabled = self.config.get("ips_enabled", False)
        ips_status_metric.set(1.0 if enabled else 0.0)
        if not enabled: 
            return

        now = time.time()
        self._prune_caches(now)

        str_dev_id = str(getattr(st, "device_id", "unknown"))
        str_host = str(getattr(st, "hostname", "unknown"))
        
        # Load safe_domains dynamically from the active LiveConfig instance
        safe_domains = {str(d).lower().strip() for d in self.config.get("safe_domains", [])}

        # =====================================================================
        # 1. PI-HOLE DOMAIN MITIGATION
        # =====================================================================
        if top_domain and top_domain not in self.blocked_domains:
            if len(self.blocked_domains) > 20000:
                self.blocked_domains.clear()

            if risk_score >= 8.0 or c2_hits > 0 or dga_burst:
                clean_domain = str(top_domain).lower().strip()
                
                if clean_domain in safe_domains:
                    log_key = (str_dev_id, clean_domain)
                    last_logged = self._last_bypass_log.get(log_key, 0)
                    
                    if now - last_logged >= 300:
                        LOGGER.info("🛡️ IPS BYPASS: Pi-hole block skipped for safe-listed domain: %s (Device: %s)", top_domain, str_host)
                        self._last_bypass_log[log_key] = now
                else:
                    # INTERNET SECOND OPINION VETO
                    internet_verdict = self._internet_verification(clean_domain)
                    
                    # LOGICAL DECISION: Veto Pi-hole block if globally harmless, UNLESS a local DGA burst is active.
                    if internet_verdict == "HARMLESS" and not dga_burst:
                        log_key = (str_dev_id, clean_domain, "veto")
                        last_logged = self._last_bypass_log.get(log_key, 0)
                        
                        if now - last_logged >= 300:
                            LOGGER.warning("🛡️ IPS VETO: Local ML flagged %s, but Global Internet Threat Intel verified it as HARMLESS. Pi-hole block skipped.", top_domain)
                            self._last_bypass_log[log_key] = now
                    else:
                        success = self._block_pihole_domain(top_domain)
                        if success:
                            self.blocked_domains.add(top_domain)
                            ips_pihole_blocks_metric.labels(str_dev_id, str_host, str(top_domain)).inc()
                            
                            msg = f"Blacklisting malicious domain {top_domain} via Pi-hole v6 REST API"
                            LOGGER.critical("🚨 IPS ACTION: %s", msg)
                            self._log_to_jsonl(msg, "pihole_block", top_domain, str_dev_id, str_host)
                        else:
                            ips_errors_metric.labels(target_type="pihole").inc()
                            with self._queue_lock:
                                if len(self.failed_blocks_queue) < 1000:
                                    self.failed_blocks_queue.add((str_dev_id, str_host, top_domain))

        # =====================================================================
        # 2. HARDWARE WEBHOOK DROP LOGIC (Runs independently of DNS Veto)
        # =====================================================================
        mac = getattr(st, "mac_address", None)
        client_ip = getattr(st, "client_ip", "unknown")
        
        isolation_key = mac if mac else client_ip

        if risk_score >= 8.0 and isolation_key not in self.isolated_macs:
            if len(self.isolated_macs) > 1000:
                self.isolated_macs.clear()

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
        pihole_pwd = self.config.get("pihole_api_password", "")
        pihole_url = self.config.get("pihole_api_url", "http://localhost").rstrip("/")
        if not pihole_pwd: 
            return False
        
        auth_url = f"{pihole_url}/api/auth"
        auth_payload = json.dumps({"password": pihole_pwd}).encode('utf-8')
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
        pihole_pwd = self.config.get("pihole_api_password", "")
        pihole_url = self.config.get("pihole_api_url", "http://localhost").rstrip("/")
        if not pihole_pwd and pihole_url != "mock": 
            return False
            
        try:
            if pihole_url == "mock": 
                return True
                
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            if not self._v6_sid:
                if not self._authenticate_v6(ctx):
                    return False
            
            url = f"{pihole_url}/api/domains/deny/exact"
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
                LOGGER.warning("IPS Pi-hole v6 Session Expired. Forcing re-authentication.")
                self._v6_sid = None
            elif e.code == 400:
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
        webhook_url = self.config.get("router_webhook_url", "")
        if not webhook_url and webhook_url != "mock": 
            return False
        try:
            if webhook_url == "mock": 
                return True
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(webhook_url, method="POST")
            req.add_header('Content-Type', 'application/json')
            data = json.dumps({"action": "isolate", "ip": ip, "mac": mac, "reason": "Home IDS Severe Threat Ceiling Breach"})
            urllib.request.urlopen(req, data=data.encode('utf-8'), timeout=5, context=ctx)
            return True
        except Exception as e:
            LOGGER.error("IPS Router webhook isolation failed for %s (IP: %s): %s", mac, ip, e)
            return False

    def _retry_loop(self):
        """Background thread designed to enforce Pi-hole blocks if the API temporarily drops."""
        while True:
            time.sleep(30)
            with self._queue_lock:
                if not self.failed_blocks_queue:
                    continue
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