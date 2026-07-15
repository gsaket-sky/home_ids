"""
zeek_collector.py – Zeek network security monitor integration.

v2 Advanced NDR Modifications (2026-07):
  • Direct DNS-over-HTTPS (DoH) IP/SNI tracking.
  • Subnet internal-to-internal pivot monitoring (Lateral Movement).
  • Network flow outbound volume accumulation (Exfiltration bytes).
  
MEMORY LEAK FIX:
  • Implemented reset_all() to instantly flush all metric dictionaries
    preventing orphaned IP states from exhausting RAM footprint.

Bugfix changelog (this version):
  BUG: HOME_SUBNET was a hardcoded "192.168.178." string prefix (a
      Fritz!Box default LAN). On any other home network, internal-to-internal
      traffic was never recognised as internal: lateral-movement detection
      (_lateral_moves) silently never fired, and every normal LAN connection
      was instead counted as a "new external IP" (_new_ips), inflating
      zeek_new_ips for completely benign traffic.
      Fix: ZeekFeatureExtractor now takes a `home_subnet` constructor argument
      (a CIDR string, e.g. "192.168.178.0/24", sourced from the new
      config.json `home_subnet` key) and uses ipaddress.ip_network
      containment checks instead of a hardcoded string prefix. HOME_SUBNET
      module constant is kept only as the default fallback value.

  BUG: DoH-bypass could be double-counted for a single connection: the same
      TLS session to e.g. 1.1.1.1:443 with SNI "cloudflare-dns.com" was
      incremented once in _process_conn() (IP match) and again in
      _process_ssl() (SNI match) — two Zeek log lines, one real event.
      Fix: DoH bypass hits are now tracked as a per-device *set* of Zeek
      connection UIDs (conn.log/ssl.log share the same "uid" for one
      connection) instead of a raw counter, so the same connection can only
      ever contribute once regardless of how many log lines matched it.
"""
import ipaddress
import json
import logging
import os
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Callable, Optional

LOGGER = logging.getLogger("home_ids.zeek")

# Default Zeek log directory
ZEEK_LOG_DIR = Path("/opt/zeek/logs/current")

# Which logs to tail and their event types
_LOG_FILES = {
    "conn.log":   "conn",
    "dns.log":    "dns",
    "http.log":   "http",
    "ssl.log":    "ssl",
    "notice.log": "notice",
    "weird.log":  "weird",
}

# NDR Signature matching fields targeting Fritz!Box context environment
DOH_IPS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"}
DOH_SNIS = {"cloudflare-dns.com", "dns.google", "dns.quad9.net"}
LATERAL_PORTS = frozenset([22, 445, 3389, 5900, 23]) # SSH, SMB, RDP, VNC, Telnet
# BUGFIX: kept only as a fallback default now — the real value is passed in
# via ZeekFeatureExtractor(home_subnet=...), sourced from config.json.
HOME_SUBNET = "192.168.178.0/24"


class ZeekLogTailer:
    def __init__(self, path: Path, event_type: str,
                 callback: Callable[[str, dict], None]):
        self.path       = path
        self.event_type = event_type
        self.callback   = callback
        self._pos       = 0
        self._inode     = None
        self._seek_to_end()

    def _seek_to_end(self) -> None:
        if self.path.exists():
            stat         = self.path.stat()
            self._inode  = stat.st_ino
            self._pos    = stat.st_size

    def poll(self) -> int:
        count = 0
        if not self.path.exists():
            return 0
        try:
            stat = self.path.stat()
            if stat.st_ino != self._inode or stat.st_size < self._pos:
                LOGGER.info("Zeek log rotated: %s", self.path.name)
                self._pos   = 0
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
                        event = json.loads(line)
                        self.callback(self.event_type, event)
                        count += 1
                    except json.JSONDecodeError:
                        pass
                self._pos = f.tell()
        except OSError:
            pass
        return count


class ZeekCollector:
    def __init__(self, log_dir: str = str(ZEEK_LOG_DIR),
                 poll_interval: float = 2.0):
        self.log_dir       = Path(log_dir)
        self.poll_interval = poll_interval
        self._tailers:  dict[str, ZeekLogTailer] = {}
        self._events:   list[dict]                = []
        self._lock      = threading.Lock()
        self._available = False

        self._init_tailers()

    def _init_tailers(self) -> None:
        if not self.log_dir.exists():
            return

        for filename, etype in _LOG_FILES.items():
            path = self.log_dir / filename
            self._tailers[filename] = ZeekLogTailer(
                path, etype, self._on_event
            )
        self._available = True
        LOGGER.info("Zeek integration active — tailing %d log files from %s", len(self._tailers), self.log_dir)

    def _on_event(self, event_type: str, event: dict) -> None:
        event["_zeek_type"] = event_type
        with self._lock:
            self._events.append(event)

    def poll(self) -> list[dict]:
        if not self._available:
            return []
        for tailer in self._tailers.values():
            tailer.poll()
        with self._lock:
            events       = self._events
            self._events = []
        return events

    @property
    def available(self) -> bool:
        return self._available


class ZeekFeatureExtractor:
    _MALICIOUS_JA3 = frozenset([
        "e7d705a3286e19ea42f587b6207263db", "6734f37431670b3ab4292b8f60f29984",
        "36f7277af969b30647d1de5e8c4e6b08", "a0e9f5d64349fb13191bc781f81f42e1",
        "72a589da586844d7f0818ce684948eea", "c12f54a3f91dc7bafd92cb59fe009a35",
        "a2fb5534f0b5a8de1c21d8fc4efb3f95", "3b5074b1b5d032e5620f69f9159a2983",
        "b386946a5a3b9a6e0f78f7c6b9d1c9a0",
    ])

    _SUSPICIOUS_PORTS = frozenset([
        4444, 4445, 8888, 9999, 1337, 31337, 6667, 6697, 1080, 3128,
    ])

    def __init__(self, home_subnet: str = HOME_SUBNET):
        self._conn_counts:   defaultdict[str, int]   = defaultdict(int)
        self._new_ips:       defaultdict[str, set]   = defaultdict(set)
        self._ja3_hits:      defaultdict[str, list]  = defaultdict(list)
        self._http_uas:      defaultdict[str, set]   = defaultdict(set)
        self._notices:       defaultdict[str, list]  = defaultdict(list)
        self._susp_ports:    defaultdict[str, int]   = defaultdict(int)
        self._http_reqs:     defaultdict[str, set]   = defaultdict(set)
        
        self._outbound_bytes: defaultdict[str, int]   = defaultdict(int)
        # BUGFIX: DoH bypass is now a set of connection UIDs per device rather
        # than a raw counter, so a connection matched by both conn.log (IP)
        # and ssl.log (SNI) only counts once. See module docstring.
        self._doh_bypass_uids: defaultdict[str, set]  = defaultdict(set)
        self._lateral_moves:  defaultdict[str, int]   = defaultdict(int)

        # BUGFIX: home_subnet is now configurable (was a hardcoded string
        # prefix). Falls back to a permissive "no match" network if the
        # configured CIDR is invalid, so a bad config value degrades to
        # "everything looks external" rather than crashing the collector.
        try:
            self._home_net = ipaddress.ip_network(home_subnet, strict=False)
        except ValueError:
            LOGGER.error(
                "Invalid home_subnet %r — lateral-movement detection disabled",
                home_subnet,
            )
            self._home_net = None

    def _is_home_ip(self, ip: str) -> bool:
        if not self._home_net or not ip:
            return False
        try:
            return ipaddress.ip_address(ip) in self._home_net
        except ValueError:
            return False

    def ingest(self, event: dict) -> None:
        etype = event.get("_zeek_type", "")
        src   = event.get("id.orig_h", event.get("orig_h", ""))
        if not src:
            return

        if etype == "conn":
            self._process_conn(src, event)
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
        dst_ip   = ev.get("id.resp_h", ev.get("resp_h", ""))
        # Used to dedupe DoH hits against the matching ssl.log line for the
        # same connection — see _process_ssl().
        uid      = ev.get("uid") or f"no-uid-{ev.get('ts', time.time())}"

        self._conn_counts[src] += 1

        if dst_ip:
            # BUGFIX: was `src.startswith(HOME_SUBNET) and dst_ip.startswith(HOME_SUBNET)`
            # with HOME_SUBNET hardcoded to "192.168.178." — now a proper CIDR
            # containment check against the configured home_subnet.
            if self._is_home_ip(src) and self._is_home_ip(dst_ip):
                if dst_port in LATERAL_PORTS:
                    self._lateral_moves[src] += 1
            else:
                self._new_ips[src].add(dst_ip)

            if dst_ip in DOH_IPS and dst_port == 443:
                # BUGFIX: add the connection UID instead of incrementing a
                # counter, so a matching ssl.log line for the same
                # connection (see _process_ssl) doesn't double-count it.
                self._doh_bypass_uids[src].add(uid)

        if dst_port in self._SUSPICIOUS_PORTS:
            self._susp_ports[src] += 1
            
        orig_bytes = ev.get("orig_bytes", 0)
        if isinstance(orig_bytes, (int, float)):
            self._outbound_bytes[src] += int(orig_bytes)
        elif isinstance(orig_bytes, str) and orig_bytes.isdigit():
            self._outbound_bytes[src] += int(orig_bytes)

    def _process_ssl(self, src: str, ev: dict) -> None:
        ja3 = ev.get("ja3", "") or ""
        if ja3 and ja3 in self._MALICIOUS_JA3:
            self._ja3_hits[src].append({
                "ja3":     ja3,
                "server":  ev.get("server_name", ""),
                "subject": ev.get("subject", ""),
                "ts":      ev.get("ts", time.time()),
            })
            LOGGER.warning("Malicious JA3 fingerprint detected from %s: %s", src, ja3)
            
        sni = (ev.get("server_name", "") or "").lower()
        if sni in DOH_SNIS:
            # BUGFIX: same UID-set dedup as the conn.log IP match above — a
            # connection to a DoH IP with a DoH SNI is one event, not two.
            uid = ev.get("uid") or f"no-uid-{ev.get('ts', time.time())}"
            self._doh_bypass_uids[src].add(uid)

    def _process_http(self, src: str, ev: dict) -> None:
        ua = ev.get("user_agent", "")
        if ua: self._http_uas[src].add(ua)
        
        host = ev.get("host", "")
        uri = ev.get("uri", "")
        if host and uri:
            self._http_reqs[src].add(f"{host}{uri}")

    def get_http_reqs(self, device_ip: str) -> set:
        return set(self._http_reqs.get(device_ip, set()))

    def _process_notice(self, src: str, ev: dict) -> None:
        note = ev.get("note", "")
        msg  = ev.get("msg", "")
        if note or msg:
            self._notices[src].append({"note": note, "msg": msg, "ts": ev.get("ts")})

    def _process_weird(self, src: str, ev: dict) -> None:
        name = ev.get("name", "")
        if name:
            self._notices[src].append({"note": f"weird:{name}", "msg": ev.get("addl",""), "ts": ev.get("ts")})

    def get_features(self, device_ip: str) -> dict:
        return {
            "zeek_conn_count":      self._conn_counts.get(device_ip, 0),
            "zeek_new_ips":         len(self._new_ips.get(device_ip, set())),
            "zeek_ja3_malicious":   len(self._ja3_hits.get(device_ip, [])),
            "zeek_notices":         len(self._notices.get(device_ip, [])),
            "zeek_susp_ports":      self._susp_ports.get(device_ip, 0),
            "zeek_http_ua_count":   len(self._http_uas.get(device_ip, set())),
            "zeek_outbound_bytes":  self._outbound_bytes.get(device_ip, 0), 
            # BUGFIX: count unique connection UIDs, not raw increments —
            # see module docstring / _process_conn / _process_ssl.
            "zeek_doh_bypass":      len(self._doh_bypass_uids.get(device_ip, set())),
            "zeek_lateral_moves":   self._lateral_moves.get(device_ip, 0),   
        }

    def get_dest_ips(self, device_ip: str) -> set:
        return set(self._new_ips.get(device_ip, set()))

    def get_alerts(self, device_ip: str) -> list[dict]:
        alerts = []
        for hit in self._ja3_hits.get(device_ip, []):
            alerts.append({
                "type": "malicious_ja3",
                "ja3":  hit["ja3"],
                "server": hit.get("server", ""),
                "confidence": 0.95,
            })
        for notice in self._notices.get(device_ip, []):
            alerts.append({
                "type":    "zeek_notice",
                "note":    notice.get("note", ""),
                "msg":     notice.get("msg", ""),
                "confidence": 0.75,
            })
        return alerts

    def reset_all(self) -> None:
        """
        MEMORY LEAK FIX: 
        Instantly clears ALL dictionaries. Guarantees external IPs or devices
        bypassing DNS do not indefinitely expand the memory payload over time.
        """
        self._conn_counts.clear()
        self._new_ips.clear()
        self._ja3_hits.clear()
        self._notices.clear()
        self._susp_ports.clear()
        self._http_uas.clear()
        self._http_reqs.clear()
        self._outbound_bytes.clear()
        self._doh_bypass_uids.clear()
        self._lateral_moves.clear()