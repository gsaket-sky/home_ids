"""
collector.py – Multi-process Concurrent-Safe Pi-hole Collector.

Hardened Features:
  • Configures strict read-only modes using raw URI file targets to bypass access mutations.
  • Configures high explicit timeout markers to defeat local lock contentions.
"""
import sqlite3
import time
import pandas as pd

PIHOLE_DB = "/etc/pihole/pihole-FTL.db"


class PiHoleCollector:
    def __init__(self, lookback_seconds: int = 0, excluded_ips: set | None = None):
        self.last_ts      = int(time.time()) - lookback_seconds
        self.excluded_ips = excluded_ips or set()

    def poll(self, limit: int = 5000) -> pd.DataFrame:
        # Establish strict read-only flags with explicit 30s timeouts to absorb lock waits
        db_uri = f"file:{PIHOLE_DB}?mode=ro"
        conn = sqlite3.connect(db_uri, uri=True, timeout=30.0)
        conn.text_factory = lambda b: b.decode("utf-8", "ignore")

        try:
            if self.excluded_ips:
                placeholders = ",".join(["?"] * len(self.excluded_ips))
                excl_clause  = f"AND q.client NOT IN ({placeholders})"
                excl_params  = list(self.excluded_ips)
            else:
                excl_clause  = ""
                excl_params  = []

            query = f"""
            SELECT
                q.timestamp,
                q.domain,
                q.status,
                q.client                                    AS client_ip,
                COALESCE(na.name, na.ip, q.client)          AS hostname
            FROM queries q
            LEFT JOIN network_addresses na
                ON q.client = na.ip
            WHERE q.timestamp > ?
            {excl_clause}
            ORDER BY q.timestamp ASC
            LIMIT ?
            """

            params = [self.last_ts] + excl_params + [limit]
            df     = pd.read_sql_query(query, conn, params=params)

            if not df.empty:
                self.last_ts = int(df["timestamp"].max())

            return df
        finally:
            conn.close()