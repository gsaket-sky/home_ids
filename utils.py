"""
utils.py – Utility helper functions.
Houses the static string parsers, heuristic evaluations (DGA calculations, entropy math),
and bypass allowlists (CDNs, Telemetry) used to prevent false positive alert floods.
"""
import math
import hashlib
import tldextract
import socket
import ipaddress
import logging
import functools

LOGGER = logging.getLogger("home_ids.utils")

def normalize_domain(domain):
    """Lowercases and cleans up trailing dots from raw DNS queries."""
    return str(domain).lower().strip(".")

def safe_label(label):
    """Hashes labels that are too long or weird into safe representations."""
    return hashlib.sha1(str(label).encode()).hexdigest()[:8]

def sanitize_hostname(host):
    """Prevents invalid characters in Prometheus labels and dashboard variables."""
    if not host:
        return "unknown"
    return host.lower().replace(".", "_").replace("-", "_")[:40]

def etld1(domain):
    """Extracts the base domain and suffix (e.g., mail.google.com -> google.com)."""
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}"

def entropy(text):
    """Computes Shannon entropy of a string. High entropy suggests encryption or DGA."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    ent = 0
    for v in freq.values():
        p = v / len(text)
        ent -= p * math.log2(p)
    return ent

def vowel_ratio(text):
    """Measures vowel concentration. DGA strings often lack human-readable vowel structures."""
    vowels = sum(1 for c in text if c in "aeiou")
    return vowels / max(len(text), 1)

_CDN_PARENT_ALLOWLIST = frozenset({
    "cloudfront.net", "amazonaws.com", "awsstatic.com", "amazonvideo.com", "aiv-cdn.net", "media-amazon.com",
    "akamaized.net", "akamai.net", "akamaihd.net", "akamaiedge.net", "akadns.net", "edgesuite.net", "edgekey.net",
    "googlevideo.com", "ggpht.com", "gstatic.com", "googleusercontent.com", "googlesyndication.com", "doubleclick.net",
    "fastly.net", "fastlylb.net", "cloudflare.net", "cdn.ampproject.org", "fbcdn.net", "azureedge.net", "msecnd.net",
    "aaplimg.com", "mzstatic.com", "nflxvideo.net", "nflxso.net", "nflxext.com",
    "scdn.co", "spotifycdn.com", "twimg.com", "ytimg.com",
    "samsungcloud.com", "samsungcloud.net", "samsungrm.net",
    "gvt1.com", "gvt2.com", "gvt3.com", "crashlytics.com", "app-measurement.com", "firebaseio.com",
    "icloud.com", "apple-dns.net", "push.apple.com", "googleapis.com", "android.clients.google.com"
})

_TELEMETRY_DOMAINS = frozenset({
    "appsflyersdk.com", "crashlytics.com", "google-analytics.com",
    "firebaseio.com", "aria.microsoft.com", "bugsmirror.com",
    "app-measurement.com", "moengage.com", "zomato.com"
})

def is_telemetry_domain(domain: str) -> bool:
    """True if domain matches known high-volume but benign telemetry SDKs."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 2 and ".".join(parts[-2:]) in _TELEMETRY_DOMAINS:
        return True
    if len(parts) >= 3 and ".".join(parts[-3:]) in _TELEMETRY_DOMAINS:
        return True
    return False

def _is_cdn_domain(domain: str) -> bool:
    """True if the domain's parent or grandparent is a known CDN."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 2 and ".".join(parts[-2:]) in _CDN_PARENT_ALLOWLIST:
        return True
    if len(parts) >= 3 and ".".join(parts[-3:]) in _CDN_PARENT_ALLOWLIST:
        return True
    return False

def suspicious_dga(domain):
    """
    Heuristic DGA (Domain Generation Algorithm) detector.
    Evaluates entropy, digit ratios, and vowel formations to catch randomly generated domains.
    """
    norm = normalize_domain(domain)
    
    # CloudFront and fastly subdomains use hashes that look like DGAs. Ignore them.
    if _is_cdn_domain(norm):
        return False
        
    left = norm.split(".", 1)[0]
    n = len(left)
    
    if 6 <= n <= 11:
        vr = vowel_ratio(left)
        # FIX: Adjusted vowel ratio allowance to 10% to catch modern algorithms
        if vr <= 0.10:
            ent = entropy(left)
            digits = sum(1 for c in left if c.isdigit())
            if ent > 2.5 and digits / n < 0.20:
                return True
        return False
        
    if n < 12:
        return False
        
    ent = entropy(left)
    vr = vowel_ratio(left)
    digits = sum(1 for c in left if c.isdigit())
    dr = digits / n
    
    return ent > 3.8 and vr < 0.25 and dr < 0.40

@functools.lru_cache(maxsize=10000)
def resolve_domain(domain):
    """Attempts to do a physical socket check on a domain to find its true endpoint."""
    try:
        infos = socket.getaddrinfo(domain, None)
        for info in infos:
            ip = info[4][0]
            parsed = ipaddress.ip_address(ip)
            if not parsed.is_private and not parsed.is_loopback and not parsed.is_multicast and not parsed.is_link_local:
                return ip
    except Exception:
        return None
    return None

def infer_device_type(hostname):
    """Assigns generalized classes to hostnames to correctly calibrate baseline bounds."""
    if not hostname:
        return "unknown"
        
    h = hostname.lower()
    
    patterns = {
        "iphone": "phone", "android": "phone", "pixel": "phone", "samsung": "phone", "galaxy": "phone",
        "ipad": "tablet", 
        "macbook": "laptop", "thinkpad": "laptop", "dell": "laptop", "hp": "laptop", "lenovo": "laptop", "linux": "laptop",
        "roku": "smart_tv", "firetv": "smart_tv", "appletv": "smart_tv", "bravia": "smart_tv", "samsungtv": "smart_tv", "monitor": "smart_tv", "lgwebos": "smart_tv", "amazon": "smart_tv",
        "printer": "printer", "epson": "printer", "hp-print": "printer",
        "nas": "nas", "synology": "nas", "qnap": "nas",
        "camera": "camera", "ring": "camera", "arlo": "camera",
        "xbox": "gaming_console", "playstation": "gaming_console", "nintendo": "gaming_console",
        "echo": "iot", "alexa": "iot", "nest": "iot", "thermostat": "iot", "bulb": "iot"
    }
    
    for key, dtype in patterns.items():
        if key in h:
            return dtype
            
    return "unknown"