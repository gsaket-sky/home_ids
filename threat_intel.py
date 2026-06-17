"""
threat_intel.py – Threat intelligence enrichment engine.

New in v1 (current version):
─────────────────────────────────────────────────────────────────────
Feeds integrated (all free, no API key for first three):
  • Feodo Tracker – Botnet C2 IPs (Emotet, QakBot, Dridex) – hourly
  • URLhaus       – Malicious URLs and domains – frequently updated
  • ThreatFox     – IOCs: domains, IPs, confidence scores – hourly
  • OTX AlienVault – Community pulses (free API key required)
  • AbuseIPDB     – Community-reported IPs via bulk blacklist download
                    Strategy: download full list hourly (1 API call),
                    lookup is O(1) with zero per-lookup quota usage
  • VirusTotal    – On-demand domain/IP lookup (free: 500/day, 4/min)
                    Strategy: smart queue – only query DGA-flagged,
                    high-NXDOMAIN, or newly-seen suspicious domains.
                    Results cached 24h. Daily cap at 480 to leave margin.

Architecture:
  • ThreatIntel   – master class managing Feodo/URLhaus/ThreatFox/OTX
  • AbuseIPDB     – separate class, bulk download + in-memory set
  • VirusTotalClient – priority queue + rate limiter + 24h result cache
  • All data compressed (gzip) to disk for fast load on restart
  • All lookups in-memory O(1) – never block the scoring hot path
  • Background refresh threads with stagger to avoid simultaneous fetches
"""
import csv
import gzip
import ipaddress
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import URLError

LOGGER = logging.getLogger("home_ids.ti")


# ── Feed definitions ───────────────────────────────────────────────────────

_FEEDS = {
    "feodo_ips": {
        "url":      "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv",
        "type":     "csv_ips",
        "comment":  "#",
        "ip_col":   0,
        "tags":     ["c2", "botnet", "feodo"],
        "confidence": 0.95,
        "ttl":      3600,   # refresh every hour
    },
    "urlhaus_domains": {
        "url":      "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "type":     "csv_domains",
        "comment":  "#",
        "domain_col": 2,   # URL column — extract hostname
        "tags":     ["malware", "urlhaus"],
        "confidence": 0.90,
        "ttl":      3600,
    },
    "threatfox_iocs": {
        "url":      "https://threatfox.abuse.ch/export/csv/recent/",
        "type":     "threatfox_csv",
        "comment":  "#",
        "tags":     ["threatfox"],
        "confidence": 0.88,
        "ttl":      3600,
    },
}

# OTX requires a free API key — add yours to config.json
# "otx_api_key": "your_key_here"
_OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since={since}"


class ThreatIntel:
    """
    Manages threat intelligence data with background refresh.
    All lookups are in-memory O(1) — never block the scoring loop.
    """

    def __init__(self, cache_dir: str = "state/ti_cache",
                 otx_api_key: str = "",
                 refresh_interval: int = 3600):
        self.cache_dir        = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.otx_api_key      = otx_api_key
        self.refresh_interval = refresh_interval

        # Hot lookup tables — populated by _refresh()
        self._bad_ips:     dict[str, dict] = {}   # ip str → metadata
        self._bad_domains: dict[str, dict] = {}   # domain str → metadata
        self._bad_cidrs:   list[tuple]     = []   # [(network, metadata), ...]

        self._lock       = threading.RLock()
        self._last_load  = 0.0
        self._stats      = {"ips": 0, "domains": 0, "cidrs": 0, "last_refresh": "never"}

        # Load from disk cache immediately (don't wait for network)
        self._load_cache()

    # ── public API ─────────────────────────────────────────────────────────

    def lookup_ip(self, ip: str) -> Optional[dict]:
        """
        Check if an IP is in threat intel feeds.
        Returns None if clean, dict with metadata if malicious.
        O(1) for exact match, O(n_cidrs) for CIDR check (n_cidrs typically < 200).
        """
        if not ip or ip == "unknown":
            return None
        with self._lock:
            # Exact IP match
            if ip in self._bad_ips:
                return self._bad_ips[ip]
            # CIDR range match
            try:
                addr = ipaddress.ip_address(ip)
                for network, meta in self._bad_cidrs:
                    if addr in network:
                        return meta
            except ValueError:
                pass
        return None

    def lookup_domain(self, domain: str) -> Optional[dict]:
        """
        Check if a domain or its parent is in threat intel feeds.
        Checks: exact match, eTLD+1 match.
        Returns None if clean, dict with metadata if malicious.
        """
        if not domain:
            return None
        domain = domain.lower().strip(".")
        with self._lock:
            if domain in self._bad_domains:
                return self._bad_domains[domain]
            # Check parent domain (e.g. sub.evil.com → evil.com)
            parts = domain.split(".")
            if len(parts) > 2:
                parent = ".".join(parts[-2:])
                if parent in self._bad_domains:
                    return {**self._bad_domains[parent], "matched_parent": True}
        return None

    def check_domain(self, domain: str) -> bool:
        """Return True if domain matches any loaded IOC feed."""
        return self.lookup_domain(domain) is not None

    def ioc_risk_score(self, domain: str = "", ip: str = "") -> float:
        """
        Returns a risk contribution (0.0–4.0) based on TI matches.
        Used directly in scoring.py as an additive risk component.
        """
        score = 0.0
        if domain:
            match = self.lookup_domain(domain)
            if match:
                score += match.get("confidence", 0.8) * 4.0
        if ip:
            match = self.lookup_ip(ip)
            if match:
                score += match.get("confidence", 0.8) * 4.0
        return min(score, 4.0)

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    # ── background refresh ─────────────────────────────────────────────────

    def start_refresh_thread(self) -> None:
        """Start background thread that refreshes feeds periodically."""
        t = threading.Thread(
            target=self._refresh_loop,
            daemon=True,
            name="ti-refresh"
        )
        t.start()
        LOGGER.info("Threat intel refresh thread started (interval=%ds)",
                    self.refresh_interval)

    def _refresh_loop(self) -> None:
        # Stagger initial fetch slightly to not hammer on startup
        time.sleep(10)
        while True:
            try:
                self._refresh_all()
            except Exception:
                LOGGER.exception("TI refresh failed")
            time.sleep(self.refresh_interval)

    def _refresh_all(self) -> None:
        LOGGER.info("Refreshing threat intel feeds...")
        new_ips     = {}
        new_domains = {}
        new_cidrs   = []

        for feed_name, feed in _FEEDS.items():
            try:
                cache_file = self.cache_dir / f"{feed_name}.cache"
                data       = self._fetch_with_cache(
                    feed["url"], cache_file, feed["ttl"]
                )
                if not data:
                    continue

                ftype = feed["type"]
                meta  = {
                    "source":     feed_name,
                    "tags":       feed["tags"],
                    "confidence": feed["confidence"],
                    "malicious":  True,
                }

                if ftype == "csv_ips":
                    self._parse_ip_csv(data, feed, meta, new_ips, new_cidrs)
                elif ftype == "csv_domains":
                    self._parse_domain_csv(data, feed, meta, new_domains)
                elif ftype == "threatfox_csv":
                    self._parse_threatfox(data, meta, new_ips, new_domains)

            except Exception:
                LOGGER.exception("Failed to process feed %s", feed_name)

        # OTX (optional — only if API key provided)
        if self.otx_api_key:
            try:
                self._fetch_otx(new_ips, new_domains)
            except Exception:
                LOGGER.exception("OTX fetch failed")

        # Atomic swap
        with self._lock:
            self._bad_ips     = new_ips
            self._bad_domains = new_domains
            self._bad_cidrs   = new_cidrs
            self._stats.update({
                "ips":          len(new_ips),
                "domains":      len(new_domains),
                "cidrs":        len(new_cidrs),
                "last_refresh": time.strftime("%Y-%m-%d %H:%M:%S"),
            })
            self._last_load = time.time()

        # Persist to disk cache for fast load on next startup
        self._save_cache(new_ips, new_domains, new_cidrs)
        LOGGER.info("TI refresh complete: %d IPs, %d domains, %d CIDRs",
                    len(new_ips), len(new_domains), len(new_cidrs))

    # ── parsers ────────────────────────────────────────────────────────────

    def _parse_ip_csv(self, data, feed, meta, ips, cidrs):
        for row in csv.reader(data.splitlines()):
            if not row or row[0].startswith(feed.get("comment", "#")):
                continue
            try:
                raw = row[feed.get("ip_col", 0)].strip()
                if not raw:
                    continue
                if "/" in raw:
                    net = ipaddress.ip_network(raw, strict=False)
                    cidrs.append((net, {**meta, "cidr": raw}))
                else:
                    ipaddress.ip_address(raw)  # validate
                    ips[raw] = {**meta, "ip": raw}
            except (ValueError, IndexError):
                pass

    def _parse_domain_csv(self, data, feed, meta, domains):
        from urllib.parse import urlparse
        col = feed.get("domain_col", 0)
        for row in csv.reader(data.splitlines()):
            if not row or row[0].startswith(feed.get("comment", "#")):
                continue
            try:
                raw = row[col].strip().strip('"')
                if not raw:
                    continue
                # Extract hostname from URL if needed
                if raw.startswith("http"):
                    raw = urlparse(raw).hostname or ""
                raw = raw.lower().strip(".")
                if raw and "." in raw:
                    domains[raw] = {**meta, "domain": raw}
            except (ValueError, IndexError):
                pass

    def _parse_threatfox(self, data, meta, ips, domains):
        from urllib.parse import urlparse
        for row in csv.reader(data.splitlines()):
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 3:
                continue
            try:
                ioc_type  = row[2].strip().lower()
                ioc_value = row[1].strip().strip('"')
                confidence = float(row[5]) / 100 if len(row) > 5 else 0.8
                tags       = [t.strip() for t in row[6].split(",")] if len(row) > 6 else []
                entry = {**meta, "confidence": confidence, "tags": meta["tags"] + tags}

                if ioc_type in ("ip:port", "ip"):
                    ip = ioc_value.split(":")[0]
                    ipaddress.ip_address(ip)
                    ips[ip] = {**entry, "ip": ip}
                elif ioc_type in ("domain", "url"):
                    if ioc_value.startswith("http"):
                        ioc_value = urlparse(ioc_value).hostname or ""
                    dom = ioc_value.lower().strip(".")
                    if dom and "." in dom:
                        domains[dom] = {**entry, "domain": dom}
            except Exception:
                pass

    def _fetch_otx(self, ips, domains):
        since = time.strftime(
            "%Y-%m-%dT%H:%M:%S",
            time.gmtime(time.time() - self.refresh_interval * 2)
        )
        url = _OTX_URL.format(since=since)
        req = Request(url, headers={
            "X-OTX-API-KEY": self.otx_api_key,
            "User-Agent": "home-ids/1.0"
        })
        try:
            with urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
            for pulse in data.get("results", []):
                tags = pulse.get("tags", [])
                for ioc in pulse.get("indicators", []):
                    itype = ioc.get("type", "")
                    val   = ioc.get("indicator", "").strip()
                    entry = {
                        "malicious":  True,
                        "source":     "otx",
                        "tags":       tags,
                        "confidence": 0.80,
                        "pulse":      pulse.get("name", ""),
                    }
                    if itype == "IPv4" and val:
                        try:
                            ipaddress.ip_address(val)
                            ips[val] = {**entry, "ip": val}
                        except ValueError:
                            pass
                    elif itype in ("domain", "hostname", "URL") and val:
                        from urllib.parse import urlparse
                        if val.startswith("http"):
                            val = urlparse(val).hostname or ""
                        val = val.lower().strip(".")
                        if val and "." in val:
                            domains[val] = {**entry, "domain": val}
        except Exception:
            LOGGER.warning("OTX fetch failed")

    # ── disk cache ─────────────────────────────────────────────────────────

    def _save_cache(self, ips, domains, cidrs) -> None:
        try:
            payload = {
                "ips":     ips,
                "domains": domains,
                "cidrs":   [[str(n), m] for n, m in cidrs],
                "saved":   time.time(),
            }
            cache_file = self.cache_dir / "combined.json.gz"
            with gzip.open(cache_file, "wt", encoding="utf-8") as f:
                json.dump(payload, f)
        except Exception:
            LOGGER.warning("Could not save TI cache")

    def _load_cache(self) -> None:
        cache_file = self.cache_dir / "combined.json.gz"
        if not cache_file.exists():
            return
        try:
            with gzip.open(cache_file, "rt", encoding="utf-8") as f:
                payload = json.load(f)
            age = time.time() - payload.get("saved", 0)
            if age > 86400:  # ignore if > 24 hours old
                LOGGER.info("TI cache too old (%dh), will refresh", int(age/3600))
                return
            cidrs = []
            for net_str, meta in payload.get("cidrs", []):
                try:
                    cidrs.append((ipaddress.ip_network(net_str, strict=False), meta))
                except ValueError:
                    pass
            with self._lock:
                self._bad_ips     = payload.get("ips",     {})
                self._bad_domains = payload.get("domains", {})
                self._bad_cidrs   = cidrs
                self._stats.update({
                    "ips":          len(self._bad_ips),
                    "domains":      len(self._bad_domains),
                    "cidrs":        len(cidrs),
                    "last_refresh": "from cache",
                })
            LOGGER.info("Loaded TI cache: %d IPs, %d domains, %d CIDRs (age=%dmin)",
                        len(self._bad_ips), len(self._bad_domains),
                        len(cidrs), int(age/60))
        except Exception:
            LOGGER.warning("Could not load TI cache")

    def _fetch_with_cache(self, url: str, cache_file: Path, ttl: int) -> Optional[str]:
        """Fetch URL, using disk cache if still fresh."""
        if cache_file.exists():
            age = time.time() - cache_file.stat().st_mtime
            if age < ttl:
                return cache_file.read_text(encoding="utf-8", errors="ignore")
        try:
            req = Request(url, headers={"User-Agent": "home-ids/1.0"})
            with urlopen(req, timeout=20) as r:
                data = r.read().decode("utf-8", errors="ignore")
            cache_file.write_text(data, encoding="utf-8")
            return data
        except URLError as exc:
            LOGGER.warning("Failed to fetch %s: %s", url, exc)
            # Return stale cache if available
            if cache_file.exists():
                LOGGER.info("Using stale cache for %s", url)
                return cache_file.read_text(encoding="utf-8", errors="ignore")
            return None


# ══════════════════════════════════════════════════════════════════════════
# AbuseIPDB integration
# ══════════════════════════════════════════════════════════════════════════

class AbuseIPDB:
    """
    AbuseIPDB IP reputation via bulk blacklist download.

    Strategy: download the full blacklist once per hour (one API call),
    load into memory as a set — never burn quota on per-IP lookups.
    Free tier allows up to 10,000 IPs per download.

    Free tier: 1,000 lookups/day — but we use ZERO lookups/day with
    the bulk download approach. The single hourly download does not
    count against the lookup quota.

    Signup: https://www.abuseipdb.com/register
    Docs:   https://docs.abuseipdb.com/#blacklist
    """

    _BLACKLIST_URL = (
        "https://api.abuseipdb.com/api/v2/blacklist"
        "?confidenceMinimum=75&limit=10000&plaintext"
    )

    def __init__(self, api_key: str, cache_dir: Path,
                 refresh_interval: int = 3600,
                 confidence_threshold: int = 75):
        self.api_key            = api_key
        self.cache_file         = cache_dir / "abuseipdb_blacklist.txt"
        self.refresh_interval   = refresh_interval
        self.confidence_threshold = confidence_threshold
        self._bad_ips: set[str] = set()
        self._lock              = threading.RLock()
        self._stats             = {"count": 0, "last_refresh": "never"}

        # Load from disk cache on startup
        self._load_cache()

    def start_refresh_thread(self) -> None:
        t = threading.Thread(
            target=self._refresh_loop,
            daemon=True,
            name="abuseipdb-refresh"
        )
        t.start()

    def _refresh_loop(self) -> None:
        time.sleep(15)   # stagger from other feeds
        while True:
            try:
                self._refresh()
            except Exception:
                LOGGER.exception("AbuseIPDB refresh failed")
            time.sleep(self.refresh_interval)

    def _refresh(self) -> None:
        if not self.api_key:
            return

        # Check if cache is still fresh
        if self.cache_file.exists():
            age = time.time() - self.cache_file.stat().st_mtime
            if age < self.refresh_interval:
                self._load_cache()
                return

        try:
            req = Request(
                self._BLACKLIST_URL,
                headers={
                    "Key":         self.api_key,
                    "Accept":      "text/plain",
                    "User-Agent":  "home-ids/1.0",
                }
            )
            with urlopen(req, timeout=30) as r:
                data = r.read().decode("utf-8", errors="ignore")

            self.cache_file.write_text(data, encoding="utf-8")
            self._parse(data)
            LOGGER.info("AbuseIPDB blacklist refreshed: %d IPs", len(self._bad_ips))

        except URLError as exc:
            LOGGER.warning("AbuseIPDB fetch failed: %s — using stale cache", exc)
            self._load_cache()

    def _parse(self, data: str) -> None:
        new_ips: set[str] = set()
        for line in data.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                ipaddress.ip_address(line)
                new_ips.add(line)
            except ValueError:
                pass
        with self._lock:
            self._bad_ips = new_ips
            self._stats.update({
                "count":        len(new_ips),
                "last_refresh": time.strftime("%Y-%m-%d %H:%M:%S"),
            })

    def _load_cache(self) -> None:
        if self.cache_file.exists():
            try:
                data = self.cache_file.read_text(encoding="utf-8", errors="ignore")
                self._parse(data)
            except Exception:
                pass

    def lookup(self, ip: str) -> bool:
        """Return True if IP is in AbuseIPDB blacklist. O(1)."""
        if not ip or ip == "unknown":
            return False
        with self._lock:
            return ip in self._bad_ips

    @property
    def stats(self) -> dict:
        return dict(self._stats)


# ══════════════════════════════════════════════════════════════════════════
# VirusTotal integration
# ══════════════════════════════════════════════════════════════════════════

class VirusTotalClient:
    """
    VirusTotal on-demand lookup for suspicious domains and IPs.

    Rate limits (free tier):
        4 requests/minute
        500 requests/day

    Strategy — smart queuing to stay well within limits:
        Only enqueue items that pass a suspicion pre-filter:
          • domain flagged by suspicious_dga()
          • NXDOMAIN ratio > 0.3 for the device
          • newly-seen domain (new_domains spike)
          • already matched by another TI feed (confirm confidence)
        Results cached for 24 hours — never requery same item.
        Internal rate limiter: 1 request per 16 seconds (3.75/min).
        Daily counter resets at UTC midnight — hard stop at 480/day.

    Signup: https://www.virustotal.com/gui/join-us
    Docs:   https://docs.virustotal.com/reference/overview
    """

    _BASE       = "https://www.virustotal.com/api/v3"
    _RATE_DELAY = 16.0     # seconds between requests (3.75/min to stay under 4/min)
    _DAILY_CAP  = 480      # stop at 480/day, leaving 20 margin from 500 limit

    def __init__(self, api_key: str, cache_dir: Path):
        self.api_key    = api_key
        self.cache_file = cache_dir / "vt_cache.json.gz"
        self._cache:    dict[str, dict] = {}   # key → {result, expires}
        self._queue:    list[tuple]     = []   # [(priority, type, value), ...]
        self._lock      = threading.RLock()
        self._last_req  = 0.0
        self._today_count   = 0
        self._today_date    = ""

        self._load_cache()

        if api_key:
            t = threading.Thread(
                target=self._worker_loop,
                daemon=True,
                name="vt-worker"
            )
            t.start()
            LOGGER.info("VirusTotal client started (cap=%d/day)", self._DAILY_CAP)

    # ── public API ─────────────────────────────────────────────────────────

    def enqueue_domain(self, domain: str, priority: int = 5) -> None:
        """
        Add a domain to the VT query queue.
        priority: 1 = highest (DGA-flagged), 10 = lowest.
        Lower number = higher priority.
        """
        if not self.api_key or not domain:
            return
        key = f"domain:{domain}"
        with self._lock:
            if self._is_cached(key):
                return
            # Avoid duplicate queue entries
            if not any(v == domain for _, t, v in self._queue if t == "domain"):
                self._queue.append((priority, "domain", domain))
                self._queue.sort(key=lambda x: x[0])

    def enqueue_ip(self, ip: str, priority: int = 5) -> None:
        """Add an IP to the VT query queue."""
        if not self.api_key or not ip or ip == "unknown":
            return
        key = f"ip:{ip}"
        with self._lock:
            if self._is_cached(key):
                return
            if not any(v == ip for _, t, v in self._queue if t == "ip"):
                self._queue.append((priority, "ip", ip))
                self._queue.sort(key=lambda x: x[0])

    def get_result(self, ioc_type: str, value: str) -> dict | None:
        """
        Return cached VT result for a domain or IP.
        Returns None if not yet queried or result expired.
        """
        key = f"{ioc_type}:{value}"
        with self._lock:
            entry = self._cache.get(key)
            if entry and time.time() < entry["expires"]:
                return entry["result"]
        return None

    def is_malicious(self, ioc_type: str, value: str,
                     threshold: int = 3) -> bool:
        """
        Returns True if VT result has >= threshold malicious votes.
        threshold=3 means at least 3 antivirus engines flagged it.
        """
        result = self.get_result(ioc_type, value)
        if not result:
            return False
        stats = result.get("last_analysis_stats", {})
        return stats.get("malicious", 0) >= threshold

    def risk_contribution(self, ioc_type: str, value: str) -> float:
        """
        Returns a 0.0–4.0 risk score from VT result.
        Scaled by how many engines flagged it.
        """
        result = self.get_result(ioc_type, value)
        if not result:
            return 0.0
        stats     = result.get("last_analysis_stats", {})
        malicious = stats.get("malicious",  0)
        suspicious= stats.get("suspicious", 0)
        total     = sum(stats.values()) or 1
        mal_ratio = (malicious + suspicious * 0.5) / total
        return min(mal_ratio * 6.0, 4.0)  # 67% of engines = 4.0 risk

    @property
    def stats(self) -> dict:
        with self._lock:
            return {
                "queue_size":  len(self._queue),
                "cache_size":  len(self._cache),
                "today_count": self._today_count,
                "daily_cap":   self._DAILY_CAP,
            }

    # ── internal worker ────────────────────────────────────────────────────

    def _worker_loop(self) -> None:
        while True:
            item = None
            with self._lock:
                today = time.strftime("%Y-%m-%d")
                if today != self._today_date:
                    self._today_count = 0
                    self._today_date  = today

                if self._queue and self._today_count < self._DAILY_CAP:
                    item = self._queue.pop(0)

            if item is None:
                time.sleep(5)
                continue

            # Rate limit: wait until 16 seconds after last request
            wait = self._RATE_DELAY - (time.time() - self._last_req)
            if wait > 0:
                time.sleep(wait)

            _, ioc_type, value = item
            try:
                result = self._query(ioc_type, value)
                key    = f"{ioc_type}:{value}"
                with self._lock:
                    self._cache[key] = {
                        "result":  result,
                        "expires": time.time() + 86400,  # 24h cache
                    }
                    self._today_count += 1
                self._save_cache()
                LOGGER.debug("VT %s %s: malicious=%d suspicious=%d",
                             ioc_type, value,
                             result.get("last_analysis_stats",{}).get("malicious",0),
                             result.get("last_analysis_stats",{}).get("suspicious",0))
            except Exception as exc:
                LOGGER.warning("VT query failed %s %s: %s", ioc_type, value, exc)
            finally:
                self._last_req = time.time()

    def _query(self, ioc_type: str, value: str) -> dict:
        if ioc_type == "domain":
            url = f"{self._BASE}/domains/{value}"
        elif ioc_type == "ip":
            url  = f"{self._BASE}/ip_addresses/{value}"
        else:
            return {}

        req = Request(url, headers={
            "x-apikey":    self.api_key,
            "User-Agent":  "home-ids/1.0",
        })
        with urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        attrs = data.get("data", {}).get("attributes", {})
        return {
            "last_analysis_stats": attrs.get("last_analysis_stats", {}),
            "reputation":          attrs.get("reputation", 0),
            "categories":          attrs.get("categories", {}),
            "last_analysis_date":  attrs.get("last_analysis_date", 0),
        }

    def _is_cached(self, key: str) -> bool:
        entry = self._cache.get(key)
        return bool(entry and time.time() < entry["expires"])

    def _save_cache(self) -> None:
        try:
            with self._lock:
                data = dict(self._cache)
            with gzip.open(self.cache_file, "wt", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def _load_cache(self) -> None:
        if not self.cache_file.exists():
            return
        try:
            with gzip.open(self.cache_file, "rt", encoding="utf-8") as f:
                data = json.load(f)
            now = time.time()
            # Only keep non-expired entries
            with self._lock:
                self._cache = {
                    k: v for k, v in data.items()
                    if v.get("expires", 0) > now
                }
            LOGGER.info("Loaded %d VT cache entries", len(self._cache))
        except Exception:
            pass
