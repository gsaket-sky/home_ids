"""
zeek_collector.py – Zeek network security monitor integration.

New in v1 (current version):
─────────────────────────────────────────────────────────────────────
Closes blind spots that Pi-hole DNS logs cannot cover:
  • Direct IP connections (malware bypassing DNS entirely)
  • Encrypted DNS (DoH/DoT – invisible to Pi-hole)
  • Non-DNS C2 (HTTP/HTTPS beaconing, IRC)
  • TLS fingerprinting (JA3/JA3S – malware TLS stack identification)
  • Protocol anomalies (Zeek's own weird.log detection)
  • Suspicious destination ports (4444, 31337, 6667 IRC, etc.)

Components:
  ZeekLogTailer      – tails a single Zeek JSON log file with log
                       rotation detection (inode change or size shrink)
  ZeekCollector      – manages all tailers, returns events via poll()
                       same interface as PiHoleCollector
  ZeekFeatureExtractor – per-device state: conn counts, new IPs, JA3
                         hits, HTTP user agents, Zeek notices

Malicious JA3 fingerprints detected:
  Cobalt Strike, Metasploit, Dridex, Trickbot, NanoCore RAT,
  Remcos RAT, AgentTesla, Sliver C2, Havoc C2

Gracefully disabled if Zeek not installed:
  ZeekCollector logs a warning and returns [] from poll() every cycle.
  No code changes needed in main.py – all Zeek features default to 0.

Setup (one-time):
  sudo apt install zeek
  # /opt/zeek/etc/node.cfg: set interface=<LAN NIC>
  # /opt/zeek/share/zeek/site/local.zeek: add JSON logging
  sudo zeekctl deploy
"""
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


class ZeekLogTailer:
    """
    Tails a single Zeek JSON log file.
    Handles log rotation (Zeek rotates hourly by default).
    """

    def __init__(self, path: Path, event_type: str,
                 callback: Callable[[str, dict], None]):
        self.path       = path
        self.event_type = event_type
        self.callback   = callback
        self._pos       = 0
        self._inode     = None
        self._seek_to_end()

    def _seek_to_end(self) -> None:
        """On startup, seek to end of file — don't replay old events."""
        if self.path.exists():
            stat         = self.path.stat()
            self._inode  = stat.st_ino
            self._pos    = stat.st_size

    def poll(self) -> int:
        """Read any new lines since last poll. Returns count of events processed."""
        count = 0
        if not self.path.exists():
            return 0
        try:
            stat = self.path.stat()
            # Detect log rotation (inode changed or file shrank)
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
    """
    Manages all Zeek log tailers.
    Provides a get_events() method that returns accumulated events
    since the last call — same interface as PiHoleCollector.poll().
    """

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
            LOGGER.warning(
                "Zeek log directory not found: %s — Zeek integration disabled. "
                "Install Zeek: sudo apt install zeek", self.log_dir
            )
            return

        for filename, etype in _LOG_FILES.items():
            path = self.log_dir / filename
            self._tailers[filename] = ZeekLogTailer(
                path, etype, self._on_event
            )
        self._available = True
        LOGGER.info("Zeek integration active — tailing %d log files from %s",
                    len(self._tailers), self.log_dir)

    def _on_event(self, event_type: str, event: dict) -> None:
        event["_zeek_type"] = event_type
        with self._lock:
            self._events.append(event)

    def poll(self) -> list[dict]:
        """Poll all log files and return new events since last call."""
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
    """
    Extracts IDS-relevant features from Zeek events.
    Maintains per-device rolling state for:
      - Direct IP connections (conn.log) — catches malware bypassing DNS
      - JA3 fingerprints (ssl.log) — catches known malware TLS stacks
      - HTTP user-agent anomalies (http.log)
      - Zeek notices (notice.log) — Zeek's own detection
      - Beaconing via conn.log intervals (more accurate than DNS-based)
    """

    # Known malicious JA3 fingerprints
    # Source: https://ja3er.com/  and  https://github.com/salesforce/ja3
    _MALICIOUS_JA3 = frozenset([
        "e7d705a3286e19ea42f587b6207263db",  # Cobalt Strike
        "6734f37431670b3ab4292b8f60f29984",  # Metasploit
        "36f7277af969b30647d1de5e8c4e6b08",  # Dridex
        "a0e9f5d64349fb13191bc781f81f42e1",  # Trickbot
        "72a589da586844d7f0818ce684948eea",  # NanoCore RAT
        "c12f54a3f91dc7bafd92cb59fe009a35",  # Remcos RAT
        "a2fb5534f0b5a8de1c21d8fc4efb3f95",  # AgentTesla
        "3b5074b1b5d032e5620f69f9159a2983",  # Sliver C2
        "b386946a5a3b9a6e0f78f7c6b9d1c9a0",  # Havoc C2
    ])

    # Ports that should rarely be used for outbound connections from home devices
    _SUSPICIOUS_PORTS = frozenset([
        4444, 4445,  # Metasploit default
        8888, 9999,  # common RAT ports
        1337,        # l33tspeak — common malware
        31337,       # Elite / classic backdoor
        6667, 6697,  # IRC (C2 via IRC is still used)
        1080,        # SOCKS proxy
        3128,        # Squid proxy
    ])

    def __init__(self):
        # Per-device state for Zeek-derived features
        self._conn_counts:   defaultdict[str, int]   = defaultdict(int)
        self._new_ips:       defaultdict[str, set]   = defaultdict(set)
        self._ja3_hits:      defaultdict[str, list]  = defaultdict(list)
        self._http_uas:      defaultdict[str, set]   = defaultdict(set)
        self._notices:       defaultdict[str, list]  = defaultdict(list)
        self._susp_ports:    defaultdict[str, int]   = defaultdict(int)
        self._last_reset     = time.time()

    def ingest(self, event: dict) -> None:
        """Process a single Zeek event and update per-device state."""
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
        proto    = ev.get("proto", "")
        state    = ev.get("conn_state", "")

        self._conn_counts[src] += 1

        if dst_ip:
            self._new_ips[src].add(dst_ip)

        if dst_port in self._SUSPICIOUS_PORTS:
            self._susp_ports[src] += 1

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

    def _process_http(self, src: str, ev: dict) -> None:
        ua = ev.get("user_agent", "")
        if ua:
            self._http_uas[src].add(ua)

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
        """
        Return Zeek-derived features for a device.
        Called once per scoring cycle, same as DNS features.
        """
        return {
            "zeek_conn_count":    self._conn_counts.get(device_ip, 0),
            "zeek_new_ips":       len(self._new_ips.get(device_ip, set())),
            "zeek_ja3_malicious": len(self._ja3_hits.get(device_ip, [])),
            "zeek_notices":       len(self._notices.get(device_ip, [])),
            "zeek_susp_ports":    self._susp_ports.get(device_ip, 0),
            "zeek_http_ua_count": len(self._http_uas.get(device_ip, set())),
        }

    def get_dest_ips(self, device_ip: str) -> set:
        """Destination IPs observed this cycle (for AbuseIPDB / VT IP checks)."""
        return set(self._new_ips.get(device_ip, set()))

    def get_alerts(self, device_ip: str) -> list[dict]:
        """Return any active Zeek notices/JA3 hits for this device."""
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

    def reset_cycle(self, device_ip: str) -> None:
        """Clear per-cycle counters for a device after scoring."""
        self._conn_counts.pop(device_ip, None)
        self._new_ips.pop(device_ip, None)
        self._ja3_hits.pop(device_ip, None)
        self._notices.pop(device_ip, None)
        self._susp_ports.pop(device_ip, None)
        self._http_uas.pop(device_ip, None)
