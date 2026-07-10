import math
import hashlib
import tldextract
import socket
import ipaddress

def normalize_domain(domain):
    return str(domain).lower().strip(".")



def safe_label(label):
    return hashlib.sha1(str(label).encode()).hexdigest()[:8]



def sanitize_hostname(host):
    if not host:
        return "unknown"

    return (
        host.lower()
        .replace(".", "_")
        .replace("-", "_")
        [:40]
    )



def etld1(domain):
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}"



def entropy(text):
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
    vowels = sum(1 for c in text if c in "aeiou")
    return vowels / max(len(text), 1)



# FP-5: CDN parent domain allowlist.
# Amazon CloudFront and similar CDNs use hash-based subdomain labels
# (d2oc6owyhiaj1t.cloudfront.net) that score as DGA: len≈14, entropy≈3.8,
# low vowels. FireTV was generating suspicious_domains=80 from this.
_CDN_PARENT_ALLOWLIST = frozenset({
    "cloudfront.net", "amazonaws.com", "awsstatic.com",
    "amazonvideo.com", "aiv-cdn.net", "media-amazon.com",
    "akamaized.net", "akamai.net", "akamaihd.net", "akamaiedge.net",
    "akadns.net", "edgesuite.net", "edgekey.net",
    "googlevideo.com", "ggpht.com", "gstatic.com", "googleusercontent.com",
    "googlesyndication.com", "doubleclick.net",
    "fastly.net", "fastlylb.net", "cloudflare.net", "cdn.ampproject.org",
    "fbcdn.net", "azureedge.net", "msecnd.net",
    "aaplimg.com", "mzstatic.com",
    "nflxvideo.net", "nflxso.net", "nflxext.com",
    "scdn.co", "spotifycdn.com", "twimg.com", "ytimg.com",
})


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
    Heuristic DGA detector.

    FP-5 fix: CDN allowlist short-circuits before any heuristic so hash-based
    CDN labels (CloudFront, Akamai, etc.) are never flagged as DGA.

    Threshold changes vs original:
      min_len: 18 → 12  (catches Conficker 17-char family)
      digit_ratio guard: < 0.40  (eliminates UUID/CDN token FPs)
    """
    norm = normalize_domain(domain)

    # CDN short-circuit: hash-based CDN labels look like DGA but are not
    if _is_cdn_domain(norm):
        return False

    left = norm.split(".", 1)[0]
    n    = len(left)

    # Path 2 (short consonant DGA): len 6-11, zero vowels
    if 6 <= n <= 11:
        vr = vowel_ratio(left)
        if vr == 0.0:
            ent = entropy(left)
            digits = sum(1 for c in left if c.isdigit())
            if ent > 2.5 and digits / n < 0.20:
                return True
        return False

    if n < 12:
        return False

    ent    = entropy(left)
    vr     = vowel_ratio(left)
    digits = sum(1 for c in left if c.isdigit())
    dr     = digits / n

    # Path 1 (standard DGA): high entropy, low vowels, not a digit-heavy token
    return ent > 3.8 and vr < 0.25 and dr < 0.40

import socket
import ipaddress


def resolve_domain(domain):

    try:

        infos = socket.getaddrinfo(
            domain,
            None
        )

        for info in infos:

            ip = info[4][0]

            parsed = ipaddress.ip_address(ip)

            if (
                not parsed.is_private
                and not parsed.is_loopback
                and not parsed.is_multicast
                and not parsed.is_link_local
            ):
                return ip

    except Exception:
        return None

    return None

def infer_device_type(hostname):

    if not hostname:
        return "unknown"

    h = hostname.lower()

    patterns = {

        "iphone": "phone",
        "android": "phone",
        "pixel": "phone",
        "samsung": "phone",

        "macbook": "laptop",
        "thinkpad": "laptop",
        "dell": "laptop",
        "hp": "laptop",
        "lenovo": "laptop",

        "roku": "smart_tv",
        "firetv": "smart_tv",
        "appletv": "smart_tv",
        "bravia": "smart_tv",
        "samsungtv": "smart_tv",
        "lgwebos": "smart_tv",

        "printer": "printer",
        "epson": "printer",
        "hp-print": "printer",

        "nas": "nas",
        "synology": "nas",
        "qnap": "nas",

        "camera": "camera",
        "ring": "camera",
        "arlo": "camera",

        "xbox": "gaming_console",
        "playstation": "gaming_console",
        "nintendo": "gaming_console",

        "echo": "iot",
        "alexa": "iot",
        "nest": "iot",
        "thermostat": "iot",
        "bulb": "iot"
    }

    for key, dtype in patterns.items():

        if key in h:
            return dtype

    return "unknown"
