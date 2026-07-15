"""
geoip_engine.py - GeoIP City (+ optional ASN) lookups for Home IDS.

Bugfix changelog (this version):
  - BUG: geo_labels() previously hardcoded "asn": "unknown" and "org": "unknown"
    for every single lookup — there was no code path that could ever populate
    them, even though metrics.py/main.py build several ASN-keyed Prometheus
    metrics (asn_risk_metric, per-ASN geo_hits_metric, etc.). Those metrics were
    therefore permanently stuck in a single "unknown" bucket.
    Fix: GeoIPEngine now optionally accepts a second `asn_db_path` (GeoLite2-ASN.mmdb,
    configured via config.json's new `geoip_asn_db` key). When provided, ASN number
    and organization are looked up for real. When not provided, we still cleanly
    fall back to "unknown" instead of silently pretending the field was checked —
    behavior is unchanged from before unless the user opts in via config.
"""
import geoip2.database
import geoip2.errors
import socket
import ipaddress
import logging

LOGGER = logging.getLogger("home_ids.geoip")


class GeoIPEngine:
    def __init__(self, db_path, asn_db_path: str = ""):
        self.reader = geoip2.database.Reader(db_path)

        # NEW: Optional ASN reader. If no path is configured (or the file can't
        # be opened), self.asn_reader stays None and geo_labels() falls back to
        # "unknown" for asn/org exactly like before this fix.
        self.asn_reader = None
        if asn_db_path:
            try:
                self.asn_reader = geoip2.database.Reader(asn_db_path)
                LOGGER.info("GeoIP ASN database loaded from %s", asn_db_path)
            except Exception as exc:
                LOGGER.warning(
                    "Could not open GeoIP ASN database at %s (%s) — "
                    "asn/org fields will stay 'unknown'", asn_db_path, exc
                )
                self.asn_reader = None

    def lookup(self, ip):
        try:
            return self.reader.city(ip)
        except Exception:
            return None

    def lookup_asn(self, ip):
        """Return the geoip2 ASN record for ip, or None if unavailable/unconfigured."""
        if not self.asn_reader:
            return None
        try:
            return self.asn_reader.asn(ip)
        except Exception:
            return None

    def reverse_dns(self, ip):
        try:
            parsed = ipaddress.ip_address(ip)

            # Support IPv4 and IPv6
            if parsed.version in (4, 6):
                host, _, _ = socket.gethostbyaddr(ip)
                return host.lower().rstrip('.')

        except Exception:
            return None

        return None

    def geo_labels(self, ip):
        geo = self.lookup(ip)

        if not geo:
            return {
                "country": "unknown",
                "city": "unknown",
                "continent": "unknown",
                "latitude": "0",
                "longitude": "0",
                "asn": "unknown",
                "org": "unknown"
            }

        # NEW: Real ASN/org lookup when an ASN database is configured; otherwise
        # this stays "unknown" just like before the fix.
        asn_label = "unknown"
        org_label = "unknown"
        asn_record = self.lookup_asn(ip)
        if asn_record is not None:
            if asn_record.autonomous_system_number is not None:
                asn_label = f"AS{asn_record.autonomous_system_number}"
            org_label = asn_record.autonomous_system_organization or "unknown"

        return {
            "country": geo.country.iso_code or "unknown",
            "city": geo.city.name or "unknown",
            "continent": geo.continent.code or "unknown",
            "latitude": str(geo.location.latitude or 0),
            "longitude": str(geo.location.longitude or 0),
            "asn": asn_label,
            "org": org_label
        }
