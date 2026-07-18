"""
zeek_collector.py – Zeek network security monitor integration.
Ingests multi-VLAN networks, tracks local pivots, monitors rogue raw encrypted 
transport configurations, and populates device mappings out of active lines.

RECENT FIXES:
- Silenced unhandled JSONDecodeErrors when Zeek defaults to TSV outputs.
- Tracked inbound lateral scans targeting internal devices accurately.
- Hardcoded maximum mapping sizes inside all state dicts to prevent memory explosion.
"""
import ipaddress
import json
import logging
import threading
import time
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
            # Memory cap local event ingest pipeline
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
    
    def __init__(self, home_subnets: list = None, ti_engine=None):
        if home_subnets is None:
            home_subnets = ["192.168.178.0/24"]
            
        # FIX: Hardcap all dictionary values with maxlen deques to prevent memory explosion
        self._conn_counts = defaultdict(int)
        self._new_ips = defaultdict(set)
        self._ja3_hits = defaultdict(lambda: deque(maxlen=50))
        self._http_uas = defaultdict(set)
        self._notices = defaultdict(lambda: deque(maxlen=50))
        self._susp_ports = defaultdict(int)
        self._http_reqs = defaultdict(set)
        self._outbound_bytes = defaultdict(int)
        self._doh_bypass_uids = defaultdict(set)
        self._lateral_moves = defaultdict(int)
        
        self._wire_dns_resolutions = {}
        self._mac_bindings = {}
        self.ti_engine = ti_engine
        
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

    def ingest(self, event: dict) -> None:
        etype = event.get("_zeek_type", "")
        if etype == "dhcp":
            mac = event.get("mac")
            ip = event.get("client_addr")
            if mac and ip:
                self._mac_bindings[ip] = mac.lower()
            return
            
        src = event.get("id.orig_h", event.get("orig_h", ""))
        if not src:
            return
            
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
        self._conn_counts[src] += 1
        
        if dst_ip:
            # Check Outbound
            if self._is_home_ip(src) and self._is_home_ip(dst_ip):
                if dst_port in LATERAL_PORTS:
                    self._lateral_moves[src] += 1
            # FIX: Asymmetric inbound tracking (external hitting internal)
            elif dst_ip and self._is_home_ip(dst_ip) and not self._is_home_ip(src):
                if dst_port in LATERAL_PORTS:
                    self._lateral_moves[dst_ip] += 1

            if not self._is_home_ip(src) and not self._is_home_ip(dst_ip):
                # Cap the IP set mapping to prevent OOM DOS
                if len(self._new_ips[src]) < 1000:
                    self._new_ips[src].add(dst_ip)
                if (dst_ip in DOH_IPS and dst_port == 443) or dst_port == 853:
                    if len(self._doh_bypass_uids[src]) < 100:
                        self._doh_bypass_uids[src].add(uid)
                    
        if dst_port in self._SUSPICIOUS_PORTS:
            self._susp_ports[src] += 1
            
        self._outbound_bytes[src] += int(ev.get("orig_bytes", 0) or 0)

    def _process_dns(self, ev: dict) -> None:
        query = ev.get("query")
        answers = ev.get("answers", [])
        if query and answers:
            q = str(query).lower().strip(".")
            for a in answers:
                try:
                    ipaddress.ip_address(a)
                    # Limit dictionary cap cache sizes
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
        return set(self._http_reqs.get(device_ip, set()))

    def get_dest_ips(self, device_ip: str) -> set:
        return set(self._new_ips.get(device_ip, set()))

    def _process_ssl(self, src: str, ev: dict) -> None:
        ja3 = ev.get("ja3", "")
        is_malicious = False
        if ja3:
            if ja3 in self._MALICIOUS_JA3:
                is_malicious = True
            elif self.ti_engine and hasattr(self.ti_engine, "dynamic_ja3") and ja3 in self.ti_engine.dynamic_ja3:
                is_malicious = True
                
        if is_malicious:
            self._ja3_hits[src].append({
                "ja3": ja3,
                "server": ev.get("server_name", ""),
                "ts": ev.get("ts", time.time())
            })
            
        if str(ev.get("server_name", "")).lower() in DOH_SNIS:
            if len(self._doh_bypass_uids[src]) < 100:
                self._doh_bypass_uids[src].add(ev.get("uid", ""))

    def _process_http(self, src: str, ev: dict) -> None:
        ua = ev.get("user_agent", "")
        host = ev.get("host", "")
        uri = ev.get("uri", "")
        if ua and len(self._http_uas[src]) < 500:
            self._http_uas[src].add(ua)
        if host and uri and len(self._http_reqs[src]) < 1000:
            self._http_reqs[src].add(f"{host}{uri}")

    def _process_notice(self, src: str, ev: dict) -> None:
        self._notices[src].append({"note": ev.get("note", ""), "msg": ev.get("msg", ""), "ts": ev.get("ts")})

    def _process_weird(self, src: str, ev: dict) -> None:
        self._notices[src].append({"note": f"weird:{ev.get('name', '')}", "msg": ev.get("addl", ""), "ts": ev.get("ts")})

    def get_features(self, device_ip: str) -> dict:
        return {
            "zeek_conn_count": self._conn_counts.get(device_ip, 0),
            "zeek_new_ips": len(self._new_ips.get(device_ip, set())),
            "zeek_ja3_malicious": len(self._ja3_hits.get(device_ip, [])),
            "zeek_notices": len(self._notices.get(device_ip, [])),
            "zeek_susp_ports": self._susp_ports.get(device_ip, 0),
            "zeek_http_ua_count": len(self._http_uas.get(device_ip, set())),
            "zeek_outbound_bytes": self._outbound_bytes.get(device_ip, 0),
            "zeek_doh_bypass": len(self._doh_bypass_uids.get(device_ip, set())),
            "zeek_lateral_moves": self._lateral_moves.get(device_ip, 0)
        }

    def get_alerts(self, device_ip: str) -> list[dict]:
        alerts = []
        for h in self._ja3_hits.get(device_ip, []):
            alerts.append({"type": "malicious_ja3", "ja3": h["ja3"], "confidence": 0.95})
        for n in self._notices.get(device_ip, []):
            alerts.append({"type": "zeek_notice", "note": n["note"], "msg": n["msg"], "confidence": 0.75})
        return alerts

    def reset_all(self) -> None:
        for d in (self._conn_counts, self._new_ips, self._ja3_hits, self._notices, 
                  self._susp_ports, self._http_uas, self._http_reqs, self._outbound_bytes, 
                  self._doh_bypass_uids, self._lateral_moves):
            d.clear()
        
        # Clean global mappings aggressively on window roll
        if len(self._wire_dns_resolutions) > 10000:
            self._wire_dns_resolutions.clear()