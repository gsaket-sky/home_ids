"""
collector.py – Pi-hole FTL database collector.

Hooks safely into Pi-hole's SQLite database to stream queries in near real-time
without creating file locks or interrupting the main Pi-hole FTL engine.

RECENT FIXES:
- Decoupled hostname caching into a dynamic TTL refresh loop to prevent 
  attribution failures and IPS bypasses caused by network DHCP churn.
"""

import logging
import sqlite3
import time
from pathlib import Path

LOGGER = logging.getLogger("home_ids.collector")

class PiHoleCollector:
    """Reads newly written DNS records natively from Pi-hole's backend DB."""
    def __init__(self, db_path="/etc/pihole/pihole-FTL.db", lookback_seconds=300, excluded_ips=None, excluded_patterns=None):
        self.db_path = db_path
        self.lookback_seconds = lookback_seconds
        self.excluded_ips = excluded_ips or set()
        self.excluded_patterns = {str(p).lower().strip() for p in (excluded_patterns or []) if str(p).strip()}
        self._conn = None
        self.last_id = 0
        self._hostnames = {}
        
        # FIX: Track mapping staleness to survive DHCP IP churn
        self._last_hostname_refresh = 0.0
        self._hostname_refresh_interval = 60.0
        
        self._connect()

    def _refresh_hostnames(self) -> None:
        """Dynamically updates IP-to-Hostname mappings with safe atomic swaps."""
        if not self._conn:
            return
        try:
            new_hostnames = {}
            for row in self._conn.execute("SELECT ip, name FROM network_addresses WHERE name IS NOT NULL").fetchall():
                new_hostnames[row[0]] = row[1]
            
            # Atomic swap ensures zero downtime if the query fails mid-execution
            self._hostnames = new_hostnames
            self._last_hostname_refresh = time.time()
        except Exception as exc:
            LOGGER.debug("Failed to refresh Pi-hole hostnames: %s", exc)

    def _connect(self) -> None:
        """Connects safely using read-only mode to prevent DB locking."""
        try:
            uri = f"file:{self.db_path}?mode=ro"
            self._conn = sqlite3.connect(uri, uri=True, check_same_thread=False, timeout=10.0)
            self._conn.text_factory = lambda b: b.decode("utf-8", "ignore")
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA cache_size=-8000;")
            
            # Populate initial hostname state
            self._refresh_hostnames()
                
            cur = self._conn.execute("SELECT MAX(id) FROM queries")
            self.last_id = max(0, (cur.fetchone()[0] or 0) - 2000)
        except Exception as exc:
            LOGGER.error("Pi-hole DB connect failed: %s", exc)
            self._conn = None

    def _reconnect(self) -> None:
        if self._conn:
            try:
                self._conn.close()
            except:
                pass
        self._conn = None
        time.sleep(1.0)
        self._connect()

    def poll(self, limit: int = 5000) -> list[dict]:
        """Polls for new queries, skipping safelists at the SQL layer for speed."""
        if self._conn is None:
            self._reconnect()
            if self._conn is None:
                return []
                
        # FIX: Ensure hostnames accurately reflect live network state
        if time.time() - self._last_hostname_refresh > self._hostname_refresh_interval:
            self._refresh_hostnames()
                
        excl_params = list(self.excluded_ips)
        excl_clause = f"AND client NOT IN ({','.join('?'*len(excl_params))})" if excl_params else ""
        query = f"SELECT id, timestamp, domain, client, status FROM queries WHERE id > ? {excl_clause} ORDER BY id ASC LIMIT ?"
        
        try:
            rows = self._conn.execute(query, [self.last_id] + excl_params + [limit]).fetchall()
        except sqlite3.OperationalError:
            self._reconnect()
            return []
        except Exception:
            return []
            
        if not rows:
            return []
        
        results = []
        dropped_patterns = 0
        
        for r in rows:
            hostname = self._hostnames.get(r[3], r[3])
            if any(pat in hostname.lower() for pat in self.excluded_patterns):
                dropped_patterns += 1
                continue
            results.append({
                "timestamp": r[1],
                "domain": r[2],
                "client_ip": r[3],
                "hostname": hostname,
                "status": r[4]
            })
            
        if dropped_patterns > 0:
            LOGGER.debug("Collector dropped %d queries matching excluded host patterns", dropped_patterns)
            
        self.last_id = rows[-1][0]
        return results