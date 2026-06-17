"""
geoip_engine.py – GeoIP lookup and reverse DNS resolution.

Changelog
─────────────────────────────────────────────────────────────────────
v1  Original: gethostbyaddr() for reverse DNS, no IPv6 handling.

v2  IPv6 fixes:
    • Scope IDs (fe80::1%eth0) stripped before ip_address() parsing –
      original crashed with ValueError, swallowed by bare except.
    • gethostbyaddr() replaced with getaddrinfo() + getnameinfo() for
      correct RFC 3493 IPv6 resolution including ::ffff: mapped addresses.
    • Link-local IPv6 scope ID reattached for resolution attempt.
    • geo_labels() strips scope ID before GeoIP lookup.
"""

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

    def reverse_dns(self, ip: str) -> str | None:
        """
        Resolve an IP (v4 or v6) to a hostname via rDNS.

        Fixes vs original:
        - Strips IPv6 scope IDs (fe80::1%eth0 → fe80::1) before
          parsing, so ip_address() doesn't throw.
        - For link-local IPv6 (fe80::/10): gethostbyaddr() needs the
          scope ID to actually resolve, but Pi-hole strips it.  We fall
          back to trying with the raw string Pi-hole gave us (works on
          some OS/resolver combos) and then give up gracefully — never
          crash, never block.
        - Uses socket.getaddrinfo() + getnameinfo() instead of the
          deprecated gethostbyaddr() for IPv6, which handles the full
          RFC 3493 flow correctly including mapped IPv4 addresses
          (::ffff:192.168.1.1).
        """
        if not ip:
            return None

        raw = ip.strip()

        # Strip scope ID so ip_address() can parse it
        scope_id = None
        if "%" in raw:
            raw, scope_id = raw.split("%", 1)

        try:
            parsed = ipaddress.ip_address(raw)
        except ValueError:
            return None

        # For public IPs and normal private IPs use getnameinfo – handles
        # both v4 and v6 cleanly.
        try:
            # AF_INET6 accepts both v4-mapped and native v6
            family = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
            addr   = raw

            # Reattach scope ID for link-local so the OS resolver can
            # route the query to the right interface.
            if parsed.is_link_local and scope_id:
                addr = f"{raw}%{scope_id}"

            results = socket.getaddrinfo(
                addr, None, family,
                socket.SOCK_STREAM,
                flags=socket.AI_CANONNAME
            )
            if results:
                # getaddrinfo canonname is in index [3]
                canon = results[0][3]
                if canon:
                    return canon.lower().rstrip(".")
        except OSError:
            pass

        # Fallback: getnameinfo – works on most platforms for v4 and
        # global-scope v6.
        try:
            port     = 0
            sockaddr = (raw, port, 0, 0) if parsed.version == 6 else (raw, port)
            hostname, _ = socket.getnameinfo(sockaddr, socket.NI_NAMEREQD)
            if hostname and hostname != raw:
                return hostname.lower().rstrip(".")
        except OSError:
            pass

        return None

    def geo_labels(self, ip: str) -> dict:
        # Strip scope ID before GeoIP lookup
        clean_ip = ip.split("%")[0] if ip else ip
        geo      = self.lookup(clean_ip)

        if not geo:
            return {
                "country":   "unknown",
                "city":      "unknown",
                "continent": "unknown",
                "latitude":  "0",
                "longitude": "0",
                "asn":       "unknown",
                "org":       "unknown",
            }

        return {
            "country":   geo.country.iso_code      or "unknown",
            "city":      geo.city.name             or "unknown",
            "continent": geo.continent.code        or "unknown",
            "latitude":  str(geo.location.latitude  or 0),
            "longitude": str(geo.location.longitude or 0),
            "asn":       "unknown",
            "org":       "unknown",
        }
