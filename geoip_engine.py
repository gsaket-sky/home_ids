import geoip2.database
import socket
import ipaddress


class GeoIPEngine:
    def __init__(self, db_path):
        self.reader = geoip2.database.Reader(db_path)

    def lookup(self, ip):
        try:
            return self.reader.city(ip)
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

        return {
            "country": geo.country.iso_code or "unknown",
            "city": geo.city.name or "unknown",
            "continent": geo.continent.code or "unknown",
            "latitude": str(geo.location.latitude or 0),
            "longitude": str(geo.location.longitude or 0),
            "asn": "unknown",
            "org": "unknown"
        }
