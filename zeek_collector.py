"""
zeek_collector.py – Zeek network security monitor integration.
Ingests multi-VLAN networks, tracks local pivots, monitors rogue raw encrypted 
transport configurations, and populates device mappings out of active lines.

RECENT FIXES:
- Silenced unhandled JSONDecodeErrors when Zeek defaults to TSV outputs.
- Tracked inbound lateral scans targeting internal devices accurately.
- Hardcoded maximum mapping sizes inside all state dicts to prevent memory explosion.
- FIXED: Wove GeoIP reverse_dns into the ingestion pipeline via a non-blocking 
  thread pool to enrich Zeek-only devices with hostnames.
- FIXED (ARCH): Converted all static integer counters to time-aware rolling deques to eliminate 
  the 5-minute Timing Cliff race condition between Pi-hole and Zeek events.
"""
import ipaddress
import json
import logging
import threading
import time
import concurrent.futures
from collections import defaultdict, deque
from pathlib import Path
from typing import Callable, Optional

LOGGER = logging.getLogger("home_ids.zeek")
ZEEK_LOG_DIR = Path("/opt/zeek/logs/current")

_LOG_FILES = {
    "conn.log": "conn",
    "dns.log": "dns",
    "http.log": "http",
    "ssl.log": "ssl",
    "notice.log": "notice",
    "weird.log": "weird",
    "dhcp.log": "dhcp"
}

DOH_IPS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"}
DOH_SNIS = {"cloudflare-dns.com", "dns.google", "dns.quad9.net"}
LATERAL_PORTS = frozenset([22, 445, 3389, 5900, 23])

class ZeekLogTailer:
    """Non-blocking log tailer tracking file inodes to survive rotations."""
    def __init__(self, path: Path, event_type: str, callback: Callable[[str, dict], None]):
        self.path = path
        self.event_type = event_type
        self.callback = callback
        self._pos = 0
        self._inode = None
        self._json_err_count = 0
        self._seek_to_end()

    def _seek_to_end(self) -> None:
        if self.path.exists():
            stat = self.path.stat()
            self._inode = stat.st_ino
            self._pos = stat.st_size

    def poll(self) -> int:
        count = 0
        if not self.path.exists():
            return 0
        try:
            stat = self.path.stat()
            if stat.st_ino != self._inode or stat.st_size < self._pos:
                self._pos = 0
                self._inode = stat.st_ino
            if stat.st_size <= self._pos:
                return 0
            with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self._pos)
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        self.callback(self.event_type, json.loads(line))
                        count += 1
                        self._json_err_count = 0
                    except json.JSONDecodeError:
                        self._json_err_count += 1
                        if self._json_err_count == 10:
                            LOGGER.error("Zeek parsing failure: Found TSV format but expecting JSON! " 
                                         "Ensure '@load policy/tuning/json-logs' is in your local.zeek")
                        pass
                self._pos = f.tell()
        except OSError:
            pass
        return count

class ZeekCollector:
    """Master orchestrator for individual file tailers."""
    def __init__(self, log_dir: str = str(ZEEK_LOG_DIR), poll_interval: float = 2.0):
        self.log_dir = Path(log_dir)
        self.poll_interval = poll_interval
        self._tailers = {}
        self._events = []
        self._lock = threading.Lock()
        self._available = False
        self._init_tailers()

    def _init_tailers(self) -> None:
        if not self.log_dir.exists():
            return
        for filename, etype in _LOG_FILES.items():
            self._tailers[filename] = ZeekLogTailer(self.log_dir / filename, etype, self._on_event)
        self._available = True
        LOGGER.info("Zeek integration active — tailing %d files", len(self._tailers))

    def _on_event(self, event_type: str, event: dict) -> None:
        event["_zeek_type"] = event_type
        with self._lock:
            if len(self._events) < 10000:
                self._events.append(event)

    def poll(self) -> list[dict]:
        if not self._available:
            return []
        for t in self._tailers.values():
            t.poll()
        with self._lock:
            e = self._events
            self._events = []
        return e

    @property
    def available(self) -> bool:
        return self._available

class ZeekFeatureExtractor:
    _MALICIOUS_JA3 = frozenset([
        "e7d705a3286e19ea42f587b6207263db", "6734f37431670b3ab4292b8f60f29984",
        "36f7277af969b30647d1de5e8c4e6b08", "a0e9f5d64349fb13191bc781f81f42e1",
        "72a589da586844d7f0818ce684948eea", "c12f54a3f91dc7bafd92cb59fe009a35",
        "a2fb5534f0b5a8de1c21d8fc4efb3f95", "3b5074b1b5d032e5620f69f9159a2983",
        "b386946a5a3b9a6e0f78f7c6b9d1c9a0"
    ])
    _SUSPICIOUS_PORTS = frozenset([4444, 4445, 8888, 9999, 1337, 31337, 6667, 6697, 1080, 3128])
    
    def __init__(self, home_subnets: list = None, ti_engine=None, geoip_engine=None, safe_ips: set = None):
        if home_subnets is None:
            home_subnets = ["192.168.178.0/24"]
            
        # FIX 1: Converted static int counters to time-aware rolling windows for smooth decay
        self._conn_ts = defaultdict(lambda: deque(maxlen=5000))
        self._new_ips = defaultdict(dict)
        self._ja3_hits = defaultdict(lambda: deque(maxlen=100))
        self._http_uas = defaultdict(dict)
        self._notices = defaultdict(lambda: deque(maxlen=100))
        self._susp_ports = defaultdict(lambda: deque(maxlen=500))
        self._http_reqs = defaultdict(dict)
        self._outbound_bytes = defaultdict(lambda: deque(maxlen=5000))
        self._doh_bypass_uids = defaultdict(dict)
        self._lateral_moves = defaultdict(lambda: deque(maxlen=500))
        
        self._wire_dns_resolutions = {}
        self._mac_bindings = {}
        self.ti_engine = ti_engine
        
        # FIX: Integrate GeoIP engine and background PTR resolution pool
        self.geoip_engine = geoip_engine
        self._reverse_dns_cache = {}
        self._ptr_pool = concurrent.futures.ThreadPoolExecutor(max_workers=3, thread_name_prefix="zeek_ptr")
        
        # ADDED: Store reference to safe_ips set for lateral movement exemption
        self.safe_ips = safe_ips if safe_ips is not None else set()

        self._home_nets = []
        for net in home_subnets:
            if net:
                try:
                    self._home_nets.append(ipaddress.ip_network(net, strict=False))
                except ValueError:
                    pass

    def _is_home_ip(self, ip: str) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self._home_nets)
        except ValueError:
            return False

    def _enrich_ptr(self, ip: str) -> None:
        """Asynchronously fetches reverse DNS for local Zeek IPs without stalling the ingest tailer."""
        if not ip or not self._is_home_ip(ip) or ip in self._reverse_dns_cache:
            return
            
        self._reverse_dns_cache[ip] = "pending"
        
        def _bg_lookup():
            if not self.geoip_engine:
                self._reverse_dns_cache[ip] = "unknown"
                return
            host = self.geoip_engine.reverse_dns(ip)
            self._reverse_dns_cache[ip] = host if host else "unknown"
            
        self._ptr_pool.submit(_bg_lookup)

    def get_hostname(self, ip: str) -> Optional[str]:
        """Provides Zeek-discovered hostnames for devices bypassing Pi-hole."""
        return self._reverse_dns_cache.get(ip) if self._reverse_dns_cache.get(ip) not in (None, "pending", "unknown") else None

    def prune(self, now_ts: float, window: int) -> None:
        """FIX 1: Dynamically ages out old Zeek events to prevent hard-reset timing cliffs."""
        cutoff = now_ts - window
        
        def prune_deque(dq):
            while dq and dq[0] < cutoff: dq.popleft()
            
        def prune_tuple_deque(dq):
            while dq and dq[0][0] < cutoff: dq.popleft()
            
        def prune_dict(d):
            for k in list(d.keys()):
                if d[k] < cutoff: del d[k]

        for src in list(self._conn_ts.keys()):
            prune_deque(self._conn_ts[src])
            if not self._conn_ts[src]: del self._conn_ts[src]

        for src in list(self._lateral_moves.keys()):
            prune_deque(self._lateral_moves[src])
            
        for src in list(self._susp_ports.keys()):
            prune_deque(self._susp_ports[src])
            
        for src in list(self._outbound_bytes.keys()):
            prune_tuple_deque(self._outbound_bytes[src])

        for src in list(self._new_ips.keys()):
            prune_dict(self._new_ips[src])

        for src in list(self._doh_bypass_uids.keys()):
            prune_dict(self._doh_bypass_uids[src])

        for src in list(self._http_uas.keys()):
            prune_dict(self._http_uas[src])

        for src in list(self._http_reqs.keys()):
            prune_dict(self._http_reqs[src])

        for src in list(self._ja3_hits.keys()):
            while self._ja3_hits[src] and self._ja3_hits[src][0].get("ts", 0) < cutoff:
                self._ja3_hits[src].popleft()

        for src in list(self._notices.keys()):
            while self._notices[src] and self._notices[src][0].get("ts", 0) < cutoff:
                self._notices[src].popleft()

    def ingest(self, event: dict) -> None:
        etype = event.get("_zeek_type", "")
        if etype == "dhcp":
            mac = event.get("mac")
            ip = event.get("client_addr")
            if mac and ip:
                self._mac_bindings[ip] = mac.lower()
                self._enrich_ptr(ip)
            return
            
        src = event.get("id.orig_h", event.get("orig_h", ""))
        if not src:
            return
            
        self._enrich_ptr(src)
            
        if etype == "conn":     
            self._process_conn(src, event)
        elif etype == "dns":    
            self._process_dns(event)
        elif etype == "ssl":    
            self._process_ssl(src, event)
        elif etype == "http":   
            self._process_http(src, event)
        elif etype == "notice": 
            self._process_notice(src, event)
        elif etype == "weird":  
            self._process_weird(src, event)

    def _process_conn(self, src: str, ev: dict) -> None:
        dst_port = int(ev.get("id.resp_p", ev.get("resp_p", 0)) or 0)
        dst_ip = ev.get("id.resp_h", ev.get("resp_h", ""))
        uid = ev.get("uid", "")
        ts = ev.get("ts", time.time())
        
        self._conn_ts[src].append(ts)
        
        if dst_ip:
            self._enrich_ptr(dst_ip)
            if self._is_home_ip(src) and self._is_home_ip(dst_ip):
                if dst_port in LATERAL_PORTS:
                    # Skip counting lateral moves if connecting to/from a whitelisted safe server IP
                    if dst_ip not in self.safe_ips and src not in self.safe_ips:
                        self._lateral_moves[src].append(ts)
            elif dst_ip and self._is_home_ip(dst_ip) and not self._is_home_ip(src):
                if dst_port in LATERAL_PORTS:
                    if dst_ip not in self.safe_ips:
                        self._lateral_moves[dst_ip].append(ts)

            if not self._is_home_ip(src) and not self._is_home_ip(dst_ip):
                if len(self._new_ips[src]) < 1000:
                    self._new_ips[src][dst_ip] = ts
                if (dst_ip in DOH_IPS and dst_port == 443) or dst_port == 853:
                    if len(self._doh_bypass_uids[src]) < 100:
                        self._doh_bypass_uids[src][uid] = ts
                    
        if dst_port in self._SUSPICIOUS_PORTS:
            self._susp_ports[src].append(ts)
            
        self._outbound_bytes[src].append((ts, int(ev.get("orig_bytes", 0) or 0)))

    def _process_dns(self, ev: dict) -> None:
        query = ev.get("query")
        answers = ev.get("answers", [])
        if query and answers:
            q = str(query).lower().strip(".")
            for a in answers:
                try:
                    ipaddress.ip_address(a)
                    if len(self._wire_dns_resolutions) < 20000:
                        self._wire_dns_resolutions[q] = a
                    break
                except ValueError:
                    pass

    def get_wire_ip(self, domain: str) -> Optional[str]:
        return self._wire_dns_resolutions.get(str(domain).lower().strip("."))

    def get_mac(self, ip: str) -> Optional[str]:
        return self._mac_bindings.get(ip)

    def get_http_reqs(self, device_ip: str) -> set:
        return set(self._http_reqs.get(device_ip, {}).keys())

    def get_dest_ips(self, device_ip: str) -> set:
        return set(self._new_ips.get(device_ip, {}).keys())

    def _process_ssl(self, src: str, ev: dict) -> None:
        ja3 = ev.get("ja3", "")
        ts = ev.get("ts", time.time())
        is_malicious = False
        if ja3:
            if ja3 in self._MALICIOUS_JA3:
                is_malicious = True
            elif self.ti_engine and hasattr(self.ti_engine, "dynamic_ja3") and ja3 in self.ti_engine.dynamic_ja3:
                is_malicious = True
                
        if is_malicious:
            dst_port = ev.get("id.resp_p", ev.get("resp_p", 0)) 
            self._ja3_hits[src].append({
                "ja3": ja3,
                "server": ev.get("server_name", ""),
                "ts": ts,
                "dest_port": dst_port 
            })
            
        if str(ev.get("server_name", "")).lower() in DOH_SNIS:
            if len(self._doh_bypass_uids[src]) < 100:
                self._doh_bypass_uids[src][ev.get("uid", "")] = ts

    def _process_http(self, src: str, ev: dict) -> None:
        ua = ev.get("user_agent", "")
        host = ev.get("host", "")
        uri = ev.get("uri", "")
        ts = ev.get("ts", time.time())
        if ua and len(self._http_uas[src]) < 500:
            self._http_uas[src][ua] = ts
        if host and uri and len(self._http_reqs[src]) < 1000:
            self._http_reqs[src][f"{host}{uri}"] = ts

    def _process_notice(self, src: str, ev: dict) -> None:
        dst_port = ev.get("id.resp_p", ev.get("resp_p", 0)) 
        self._notices[src].append({"note": ev.get("note", ""), "msg": ev.get("msg", ""), "ts": ev.get("ts"), "dest_port": dst_port})

    def _process_weird(self, src: str, ev: dict) -> None:
        dst_port = ev.get("id.resp_p", ev.get("resp_p", 0)) 
        self._notices[src].append({"note": f"weird:{ev.get('name', '')}", "msg": ev.get("addl", ""), "ts": ev.get("ts"), "dest_port": dst_port})

    def get_features(self, device_ip: str) -> dict:
        return {
            "zeek_conn_count": len(self._conn_ts.get(device_ip, [])),
            "zeek_new_ips": len(self._new_ips.get(device_ip, {})),
            "zeek_ja3_malicious": len(self._ja3_hits.get(device_ip, [])),
            "zeek_notices": len(self._notices.get(device_ip, [])),
            "zeek_susp_ports": len(self._susp_ports.get(device_ip, [])),
            "zeek_http_ua_count": len(self._http_uas.get(device_ip, {})),
            "zeek_outbound_bytes": sum(b for t, b in self._outbound_bytes.get(device_ip, [])),
            "zeek_doh_bypass": len(self._doh_bypass_uids.get(device_ip, {})),
            "zeek_lateral_moves": len(self._lateral_moves.get(device_ip, []))
        }

    def get_alerts(self, device_ip: str) -> list[dict]:
        alerts = []
        for h in self._ja3_hits.get(device_ip, []):
            alerts.append({"type": "malicious_ja3", "ja3": h["ja3"], "dest_port": h.get("dest_port", 0), "confidence": 0.95})
        for n in self._notices.get(device_ip, []):
            alerts.append({"type": "zeek_notice", "note": n["note"], "msg": n["msg"], "dest_port": n.get("dest_port", 0), "confidence": 0.75})
        return alerts

    def reset_all(self) -> None:
        for d in (self._conn_ts, self._new_ips, self._ja3_hits, self._notices, 
                  self._susp_ports, self._http_uas, self._http_reqs, self._outbound_bytes, 
                  self._doh_bypass_uids, self._lateral_moves):
            d.clear()
        if len(self._wire_dns_resolutions) > 10000:
            self._wire_dns_resolutions.clear()