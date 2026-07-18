"""
threat_intel.py – Threat intelligence enrichment engine.

Consolidates IP/Domain reputation tracking, parses static and streaming feeds, 
and integrates on-demand asynchronous VirusTotal/Abuse.ch lookup queues.
"""
import csv
import gzip
import ipaddress
import json
import logging
import threading
import time
import heapq
from pathlib import Path
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import URLError

LOGGER = logging.getLogger("home_ids.ti")

_FEEDS = {
    "feodo_ips": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv", 
        "type": "csv_ips", "comment": "#", "ip_col": 0, "tags": ["c2", "botnet", "feodo"], 
        "confidence": 0.95, "ttl": 3600
    },
    "urlhaus_hosts": {
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/", 
        "type": "hostfile", "comment": "#", "tags": ["malware", "urlhaus_host"], 
        "confidence": 0.90, "ttl": 3600
    },
    "urlhaus_urls": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/", 
        "type": "csv_urls", "comment": "#", "url_col": 2, "tags": ["malware", "urlhaus_url"], 
        "confidence": 0.95, "ttl": 3600
    },
    "threatfox_iocs": {
        "url": "https://threatfox.abuse.ch/export/csv/recent/", 
        "type": "threatfox_csv", "comment": "#", "tags": ["threatfox"], 
        "confidence": 0.88, "ttl": 3600
    }
}

_OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since={since}"

class ThreatIntel:
    def __init__(self, cache_dir: str = "state/ti_cache", otx_api_key: str = "", refresh_interval: int = 3600):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.otx_api_key = otx_api_key
        self.refresh_interval = refresh_interval

        self._bad_ips:     dict[str, dict] = {}   
        self._bad_domains: dict[str, dict] = {}   
        self._bad_urls:    dict[str, dict] = {}   
        self._bad_cidrs:   list[tuple]     = []   
        self.dynamic_ja3 = frozenset()

        self._lock = threading.RLock()
        self._stats = {"ips": 0, "domains": 0, "urls": 0, "cidrs": 0, "last_refresh": "never"}
        self._infrastructure_allowlist = frozenset({
            "raw.githubusercontent.com", "githubusercontent.com", "github.com", 
            "google.com", "googleapis.com", "apple.com", "icloud.com", 
            "microsoft.com", "windows.com"
        })
        self._load_cache()

    def lookup_ip(self, ip: str) -> Optional[dict]:
        if not ip or ip == "unknown": 
            return None
        with self._lock:
            if ip in self._bad_ips: 
                return self._bad_ips[ip]
            try:
                addr = ipaddress.ip_address(ip)
                for network, meta in self._bad_cidrs:
                    if addr in network: 
                        return meta
            except ValueError: 
                pass
        return None

    def lookup_domain(self, domain: str) -> Optional[dict]:
        if not domain: 
            return None
        domain = domain.lower().strip(".")
        if domain in self._infrastructure_allowlist: 
            return None
        with self._lock:
            if domain in self._bad_domains: 
                return self._bad_domains[domain]
            parts = domain.split(".")
            if len(parts) > 2:
                parent = ".".join(parts[-2:])
                if parent in self._bad_domains: 
                    return {**self._bad_domains[parent], "matched_parent": True}
        return None

    def lookup_url(self, url: str) -> Optional[dict]:
        if not url: 
            return None
        with self._lock: 
            return self._bad_urls.get(url)

    def check_domain(self, domain: str) -> bool: 
        return self.lookup_domain(domain) is not None

    def ioc_risk_score(self, domain: str = "", ip: str = "") -> float:
        score = 0.0
        if domain and self.lookup_domain(domain): 
            score += self.lookup_domain(domain).get("confidence", 0.8) * 4.0
        if ip and self.lookup_ip(ip):             
            score += self.lookup_ip(ip).get("confidence", 0.8) * 4.0
        return min(score, 4.0)

    def start_refresh_thread(self) -> None:
        threading.Thread(target=self._refresh_loop, daemon=True, name="ti-refresh").start()
        threading.Thread(target=self._start_ja3_feed, daemon=True, name="ja3-refresh").start()

    def _refresh_loop(self) -> None:
        time.sleep(10)
        while True:
            try: 
                self._refresh_all()
            except Exception as e: 
                LOGGER.warning("TI Refresh failed: %s", e)
            time.sleep(self.refresh_interval)

    def _start_ja3_feed(self) -> None:
        time.sleep(15)
        while True:
            try:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = Request("https://sslbl.abuse.ch/blacklist/sslblacklist.csv")
                with urlopen(req, timeout=10, context=ctx) as resp:
                    lines = resp.read().decode('utf-8').splitlines()
                    new_ja3 = {
                        line.split(',')[1].strip() 
                        for line in lines 
                        if not line.startswith('#') and len(line.split(',')) >= 2
                    }
                    if new_ja3: 
                        self.dynamic_ja3 = frozenset(new_ja3)
            except Exception as e: 
                LOGGER.warning("JA3 Feed Refresh failed: %s", e)
            time.sleep(86400) 

    def _refresh_all(self) -> None:
        new_ips, new_domains, new_urls, new_cidrs = {}, {}, {}, []
        for feed_name, feed in _FEEDS.items():
            try:
                cache_file = self.cache_dir / f"{feed_name}.cache"
                data = self._fetch_with_cache(feed["url"], cache_file, feed["ttl"])
                if not data: 
                    continue
                meta = {
                    "source": feed_name, 
                    "tags": feed["tags"], 
                    "confidence": feed["confidence"], 
                    "malicious": True
                }
                ftype = feed["type"]
                if ftype == "csv_ips":        
                    self._parse_ip_csv(data, feed, meta, new_ips, new_cidrs)
                elif ftype == "hostfile":     
                    self._parse_hostfile(data, feed, meta, new_domains)
                elif ftype == "csv_urls":     
                    self._parse_csv_urls(data, feed, meta, new_urls)
                elif ftype == "threatfox_csv": 
                    self._parse_threatfox(data, meta, new_ips, new_domains, new_urls)
            except Exception: 
                pass

        if self.otx_api_key:
            try: 
                self._fetch_otx(new_ips, new_domains)
            except Exception: 
                pass

        with self._lock:
            self._bad_ips = new_ips
            self._bad_domains = new_domains
            self._bad_urls = new_urls
            self._bad_cidrs = new_cidrs
            self._stats.update({
                "ips": len(new_ips), 
                "domains": len(new_domains), 
                "urls": len(new_urls), 
                "cidrs": len(new_cidrs), 
                "last_refresh": time.strftime("%Y-%m-%d %H:%M:%S")
            })
        self._save_cache(new_ips, new_domains, new_urls, new_cidrs)

    def _parse_ip_csv(self, data, feed, meta, ips, cidrs):
        for row in csv.reader(data.splitlines()):
            if not row or row[0].startswith(feed.get("comment", "#")): 
                continue
            try:
                raw = row[feed.get("ip_col", 0)].strip()
                if not raw: 
                    continue
                if "/" in raw: 
                    cidrs.append((ipaddress.ip_network(raw, strict=False), {**meta, "cidr": raw}))
                else:          
                    ipaddress.ip_address(raw)
                    ips[raw] = {**meta, "ip": raw}
            except (ValueError, IndexError): 
                pass

    def _parse_hostfile(self, data, feed, meta, domains):
        for line in data.splitlines():
            line = line.strip()
            if not line or line.startswith(feed.get("comment", "#")): 
                continue
            dom = line.split()[-1].lower().strip(".")
            if dom and "." in dom and dom != "localhost": 
                domains[dom] = {**meta, "domain": dom}

    def _parse_csv_urls(self, data, feed, meta, urls):
        from urllib.parse import urlparse
        col = feed.get("url_col", 2)
        for row in csv.reader(data.splitlines()):
            if not row or row[0].startswith(feed.get("comment", "#")): 
                continue
            try:
                raw = row[col].strip().strip('"')
                if raw.startswith("http"):
                    p = urlparse(raw)
                    u = f"{p.hostname}{p.path}" + (f"?{p.query}" if p.query else "")
                    urls[u] = {**meta, "url": raw}
            except (ValueError, IndexError): 
                pass

    def _parse_threatfox(self, data, meta, ips, domains, urls):
        from urllib.parse import urlparse
        for row in csv.reader(data.splitlines()):
            if not row or row[0].startswith("#") or len(row) < 3: 
                continue
            try:
                ioc_type, ioc_value = row[2].strip().lower(), row[1].strip().strip('"')
                conf = float(row[5]) / 100 if len(row) > 5 else 0.8
                tags = [t.strip() for t in row[6].split(",")] if len(row) > 6 else []
                entry = {**meta, "confidence": conf, "tags": meta["tags"] + tags}
                
                if ioc_type in ("ip:port", "ip"):
                    ip = ioc_value.split(":")[0]
                    ipaddress.ip_address(ip)
                    ips[ip] = {**entry, "ip": ip}
                elif ioc_type in ("domain", "url"):
                    if ioc_type == "url" and ioc_value.startswith("http"):
                        p = urlparse(ioc_value)
                        u = f"{p.hostname}{p.path}" + (f"?{p.query}" if p.query else "")
                        urls[u] = {**entry, "url": ioc_value}
                    else:
                        d = (urlparse(ioc_value).hostname or ioc_value if ioc_value.startswith("http") else ioc_value).lower().strip(".")
                        if d and "." in d: 
                            domains[d] = {**entry, "domain": d}
            except Exception: 
                pass

    def _fetch_otx(self, ips, domains):
        from urllib.parse import urlparse
        since = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - self.refresh_interval * 2))
        req = Request(_OTX_URL.format(since=since), headers={"X-OTX-API-KEY": self.otx_api_key, "User-Agent": "home-ids/1.0"})
        with urlopen(req, timeout=15) as r:
            for p in json.loads(r.read()).get("results", []):
                for ioc in p.get("indicators", []):
                    itype, val = ioc.get("type", ""), ioc.get("indicator", "").strip()
                    e = {"malicious": True, "source": "otx", "tags": p.get("tags", []), "confidence": 0.80, "pulse": p.get("name", "")}
                    if itype == "IPv4" and val:
                        try: 
                            ipaddress.ip_address(val)
                            ips[val] = {**e, "ip": val}
                        except ValueError: 
                            pass
                    elif itype in ("domain", "hostname", "URL") and val:
                        d = (urlparse(val).hostname or val if val.startswith("http") else val).lower().strip(".")
                        if d and "." in d: 
                            domains[d] = {**e, "domain": d}

    def _save_cache(self, ips, domains, urls, cidrs) -> None:
        try:
            payload = {
                "ips": ips, 
                "domains": domains, 
                "urls": urls, 
                "cidrs": [[str(n), m] for n, m in cidrs], 
                "saved": time.time()
            }
            with gzip.open(self.cache_dir / "combined.json.gz", "wt", encoding="utf-8") as f: 
                json.dump(payload, f)
        except Exception: 
            pass

    def _load_cache(self) -> None:
        if not (self.cache_dir / "combined.json.gz").exists(): 
            return
        try:
            with gzip.open(self.cache_dir / "combined.json.gz", "rt", encoding="utf-8") as f: 
                payload = json.load(f)
            if time.time() - payload.get("saved", 0) > 86400: 
                return
            
            cidrs = []
            for net_str, m in payload.get("cidrs", []):
                try: 
                    cidrs.append((ipaddress.ip_network(net_str, strict=False), m))
                except ValueError: 
                    pass
            with self._lock:
                self._bad_ips = payload.get("ips", {})
                self._bad_domains = payload.get("domains", {})
                self._bad_urls = payload.get("urls", {})
                self._bad_cidrs = cidrs
        except Exception: 
            pass

    def _fetch_with_cache(self, url: str, cache_file: Path, ttl: int) -> Optional[str]:
        if cache_file.exists() and (time.time() - cache_file.stat().st_mtime) < ttl: 
            return cache_file.read_text(encoding="utf-8", errors="ignore")
        try:
            req = Request(url, headers={"User-Agent": "home-ids/1.0"})
            with urlopen(req, timeout=20) as r: 
                data = r.read().decode("utf-8", errors="ignore")
            cache_file.write_text(data, encoding="utf-8")
            return data
        except URLError: 
            return cache_file.read_text(encoding="utf-8", errors="ignore") if cache_file.exists() else None

class AbuseIPDB:
    _BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=75&limit=10000&plaintext"
    
    def __init__(self, api_key: str, cache_dir: Path, refresh_interval: int = 3600):
        self.api_key = api_key
        self.cache_file = cache_dir / "abuseipdb_blacklist.txt"
        self.refresh_interval = refresh_interval
        self._bad_ips = set()
        self._lock = threading.RLock()
        self._load_cache()

    def start_refresh_thread(self) -> None: 
        threading.Thread(target=self._refresh_loop, daemon=True, name="abuseipdb-refresh").start()
    
    def _refresh_loop(self) -> None:
        time.sleep(15)
        while True:
            try: 
                self._refresh()
            except Exception: 
                pass
            time.sleep(self.refresh_interval)
            
    def _refresh(self) -> None:
        if not self.api_key: 
            return
        if self.cache_file.exists() and (time.time() - self.cache_file.stat().st_mtime) < self.refresh_interval: 
            self._load_cache()
            return
        try:
            req = Request(self._BLACKLIST_URL, headers={"Key": self.api_key, "Accept": "text/plain", "User-Agent": "home-ids/1.0"})
            with urlopen(req, timeout=30) as r: 
                data = r.read().decode("utf-8", errors="ignore")
            self.cache_file.write_text(data, encoding="utf-8")
            self._parse(data)
        except URLError: 
            self._load_cache()
            
    def _parse(self, data: str) -> None:
        new_ips = set()
        for line in data.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                try: 
                    ipaddress.ip_address(line)
                    new_ips.add(line)
                except ValueError: 
                    pass
        with self._lock: 
            self._bad_ips = new_ips
            
    def _load_cache(self) -> None:
        if self.cache_file.exists(): 
            try:
                self._parse(self.cache_file.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                pass
                
    def lookup(self, ip: str) -> bool:
        with self._lock: 
            return ip in self._bad_ips

class VirusTotalClient:
    _BASE = "https://www.virustotal.com/api/v3"
    _RATE_DELAY = 16.0
    _DAILY_CAP = 480
    
    def __init__(self, api_key: str, cache_dir: Path):
        self.api_key = api_key
        self.cache_file = cache_dir / "vt_cache.json.gz"
        self._cache = {}
        self._queue = []
        self._queued_items = set()
        self._lock = threading.RLock()
        self._last_req = 0.0
        self._today_count = 0
        self._today_date = ""
        self._load_cache()
        if api_key: 
            threading.Thread(target=self._worker_loop, daemon=True, name="vt-worker").start()

    def enqueue_domain(self, domain: str, priority: int = 5) -> None:
        if not self.api_key or not domain: 
            return
        k = f"domain:{domain}"
        with self._lock:
            if not self._is_cached(k) and k not in self._queued_items: 
                self._queued_items.add(k)
                heapq.heappush(self._queue, (priority, time.time(), "domain", domain))

    def enqueue_ip(self, ip: str, priority: int = 5) -> None:
        if not self.api_key or not ip or ip == "unknown": 
            return
        k = f"ip:{ip}"
        with self._lock:
            if not self._is_cached(k) and k not in self._queued_items: 
                self._queued_items.add(k)
                heapq.heappush(self._queue, (priority, time.time(), "ip", ip))

    def get_result(self, ioc_type: str, value: str) -> dict | None:
        k = f"{ioc_type}:{value}"
        with self._lock:
            e = self._cache.get(k)
            if e and time.time() < e["expires"]: 
                return e["result"]
        return None

    def is_malicious(self, ioc_type: str, value: str, threshold: int = 3) -> bool:
        res = self.get_result(ioc_type, value)
        return res and res.get("last_analysis_stats", {}).get("malicious", 0) >= threshold

    def risk_contribution(self, ioc_type: str, value: str) -> float:
        res = self.get_result(ioc_type, value)
        if not res: 
            return 0.0
        s = res.get("last_analysis_stats", {})
        total = sum(s.values()) or 1
        return min(((s.get("malicious", 0) + s.get("suspicious", 0) * 0.5) / total) * 6.0, 4.0)

    def _worker_loop(self) -> None:
        while True:
            item = None
            with self._lock:
                t = time.strftime("%Y-%m-%d")
                if t != self._today_date: 
                    self._today_count = 0
                    self._today_date = t
                if self._queue and self._today_count < self._DAILY_CAP:
                    _, _, itype, val = heapq.heappop(self._queue)
                    self._queued_items.discard(f"{itype}:{val}")
                    item = (itype, val)
                    
            if item is None: 
                time.sleep(5)
                continue
                
            w = self._RATE_DELAY - (time.time() - self._last_req)
            if w > 0: 
                time.sleep(w)
                
            itype, val = item
            try:
                res = self._query(itype, val)
                k = f"{itype}:{val}"
                with self._lock:
                    self._cache[k] = {"result": res, "expires": time.time() + 86400}
                    self._today_count += 1
                    if len(self._cache) > 2000: 
                        del self._cache[next(iter(self._cache))]
                self._save_cache()
            except Exception: 
                pass
            finally: 
                self._last_req = time.time()

    def _query(self, ioc_type: str, value: str) -> dict:
        u = f"{self._BASE}/domains/{value}" if ioc_type == "domain" else f"{self._BASE}/ip_addresses/{value}"
        req = Request(u, headers={"x-apikey": self.api_key, "User-Agent": "home-ids/1.0"})
        with urlopen(req, timeout=15) as r: 
            data = json.loads(r.read())
        attrs = data.get("data", {}).get("attributes", {})
        return {
            "last_analysis_stats": attrs.get("last_analysis_stats", {}), 
            "reputation": attrs.get("reputation", 0)
        }

    def _is_cached(self, key: str) -> bool:
        e = self._cache.get(key)
        return bool(e and time.time() < e["expires"])

    def _save_cache(self) -> None:
        try:
            with self._lock: 
                d = dict(self._cache)
            with gzip.open(self.cache_file, "wt", encoding="utf-8") as f: 
                json.dump(d, f)
        except Exception: 
            pass

    def _load_cache(self) -> None:
        if not self.cache_file.exists(): 
            return
        try:
            with gzip.open(self.cache_file, "rt", encoding="utf-8") as f: 
                data = json.load(f)
            now = time.time()
            with self._lock: 
                self._cache = {k: v for k, v in data.items() if v.get("expires", 0) > now}
        except Exception: 
            pass