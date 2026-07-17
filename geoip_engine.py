"""
geoip_engine.py - GeoIP City (+ optional ASN) lookups for Home IDS.
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
        # BUGFIX: Optional ASN/Org reader initialization prevents metric starvation
        self.asn_reader = None
        if asn_db_path:
            try:
                self.asn_reader = geoip2.database.Reader(asn_db_path)
                LOGGER.info("GeoIP ASN database loaded from %s", asn_db_path)
            except Exception as exc:
                LOGGER.warning("Could not open GeoIP ASN database: %s", exc)
                self.asn_reader = None

    def lookup(self, ip):
        try:
            return self.reader.city(ip)
        except Exception:
            return None

    def lookup_asn(self, ip):
        if not self.asn_reader:
            return None
        try:
            return self.asn_reader.asn(ip)
        except Exception:
            return None

    def reverse_dns(self, ip):
        try:
            parsed = ipaddress.ip_address(ip)
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
                "country": "unknown", "city": "unknown", "continent": "unknown",
                "latitude": "0", "longitude": "0", "asn": "unknown", "org": "unknown"
            }
        
        # BUGFIX: Populate real ASN and Org fields when the secondary database path is active
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