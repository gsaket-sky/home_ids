"""
state.py – Per-device state management.

Changelog
─────────────────────────────────────────────────────────────────────
v1  Original dataclasses with no __slots__. EWMAStat with no warmup
    tracking. RollingWindow with unbounded events deque.

v2  Memory optimisation:
    • __slots__ on EWMAStat, RollingWindow, DeviceState (~200 B/device
      saving; eliminates __dict__ overhead)
    • RollingWindow.events bounded (maxlen=20_000) – prevents unbounded
      RAM growth from chatty devices
    • decay() single-pass prune – avoids two iterations over domain dict
    • Dead fields removed: total, first_seen, last_seen

v3  EWMA improvements:
    • Observation counter n added to EWMAStat
    • zscore() returns 0.0 during warmup (n < 30) – prevents false alerts
      from cold baselines on startup or newly-seen devices
    • warmed_up property for gate checks in main.py
    • Serialisation: to_dict() / from_dict() for state persistence

v4  New baselines (Fix P):
    • nxdomain_baseline, blocked_baseline, dga_baseline added
    • risk_baseline (alpha=0.1, faster) for velocity tracking (Fix H)
    • seen_domains: set[str] – lifetime domain set for new_domains signal
      (Fix B). Persisted in to_dict() as sorted list capped at 20k entries.
    • All new slots added to __slots__, __init__, to_dict, from_dict

v5  Variance floor (current version):
    • std = max(raw_std, mean×15%, 1.0) – absorbs ±20% daily variation.
      Original floor of 1e-6 caused z-scores of 10,000+ on stable devices
      (a single extra DNS query looked like a 10,000-sigma event).
"""
"""
state.py – Persistent baseline states tracking device behaviors.
"""
from collections import deque, Counter

# Maximum events held in the rolling window deque.
# 50 q/min laptop × 300s window = 250 events normal peak.
# 10_000 gives a 40× safety margin and still bounds RAM.
_MAX_EVENTS_PER_DEVICE  = 10_000
# Maximum unique domain entries in the per-device Counter.
# A laptop browsing normally sees ~200 unique domains/5min.
# 2_000 gives 10× headroom and bounds RAM at ~120 KB/device.
_MAX_DOMAINS_PER_DEVICE = 2_000


class RollingWindow:
    def __init__(self):
        # FIX 1: maxlen bounds the deque — no matter how many events
        # arrive in one burst (startup seed, chatty device), the deque
        # never exceeds _MAX_EVENTS_PER_DEVICE entries.
        self.events   = deque(maxlen=_MAX_EVENTS_PER_DEVICE)
        self.domains  = Counter()
        self.blocked  = 0.0
        self.nxdomain = 0.0

    def cap_domains(self) -> None:
        """
        FIX 2: hard cap on Counter size.
        Evict the lowest-count entries when the Counter grows beyond
        _MAX_DOMAINS_PER_DEVICE. Called from features.py after each
        eviction pass. Domains with count near 0 are stale anyway.
        """
        if len(self.domains) > _MAX_DOMAINS_PER_DEVICE:
            # Keep the top-N by count — most recently active domains
            # have the highest decayed count values.
            keep = self.domains.most_common(_MAX_DOMAINS_PER_DEVICE)
            self.domains = Counter(dict(keep))


class BaselineMetric:
    def __init__(self, alpha: float):
        self.alpha = alpha
        self.mean = 0.0
        self.var = 1.0
        self.initialized = False
        self.n = 0

    def update(self, val: float):
        self.n += 1
        if not self.initialized:
            self.mean = val
            self.var = 1.0
            self.initialized = True
            return

        old_mean = self.mean
        self.mean = (1 - self.alpha) * old_mean + self.alpha * val
        diff = val - old_mean
        self.var = (1 - self.alpha) * self.var + self.alpha * (diff ** 2)

    def to_dict(self) -> dict:
        return {"alpha": self.alpha, "mean": self.mean, "var": self.var, "initialized": self.initialized, "n": self.n}

    @classmethod
    def from_dict(cls, d: dict) -> "BaselineMetric":
        obj = cls(d.get("alpha", 0.05))
        obj.mean = d.get("mean", 0.0)
        obj.var = d.get("var", 1.0)
        obj.initialized = d.get("initialized", False)
        obj.n = d.get("n", 0)
        return obj


class DeviceState:
    def __init__(self, device_id: str, client_ip: str, hostname: str, alpha: float = 0.05):
        self.device_id = device_id
        self.client_ip = client_ip
        self.hostname = hostname
        self.device_type = "unknown"
        
        self.last_alert_time = 0.0
        # Hardened Alert Hysteresis Tracking Variables
        self.last_alert_risk = 0.0
        self.last_alert_signature = ""

        self.rolling = RollingWindow()
        # FIX 3: seen_domains uses a plain dict (insertion-ordered since
        # Python 3.7) instead of a set. Oldest entries are at the front
        # and can be evicted reliably with next(iter(d)) — unlike a set
        # where list(s)[-N:] returns arbitrary elements.
        # Cap reduced from 20_000 → 5_000: sufficient for the new_domains
        # signal (we only care whether a domain is "new this window") and
        # 5_000 × ~60 bytes = 300 KB per device vs 1.2 MB previously.
        self.seen_domains: dict = {}   # domain → None (ordered set)

        self.rate_baseline = BaselineMetric(alpha)
        self.entropy_baseline = BaselineMetric(alpha)
        self.unique_baseline = BaselineMetric(alpha)
        self.nxdomain_baseline = BaselineMetric(alpha)
        self.blocked_baseline = BaselineMetric(alpha)
        self.dga_baseline = BaselineMetric(alpha)
        self.risk_baseline = BaselineMetric(0.1)

    def to_dict(self) -> dict:
        return {
            "client_ip": self.client_ip,
            "hostname": self.hostname,
            "device_type": self.device_type,
            "last_alert_time": self.last_alert_time,
            # Persist alert hysteresis filters across engine save/loads
            "last_alert_risk": self.last_alert_risk,
            "last_alert_signature": self.last_alert_signature,
            "rate_baseline": self.rate_baseline.to_dict(),
            "entropy_baseline": self.entropy_baseline.to_dict(),
            "unique_baseline": self.unique_baseline.to_dict(),
            "nxdomain_baseline": self.nxdomain_baseline.to_dict(),
            "blocked_baseline": self.blocked_baseline.to_dict(),
            "dga_baseline": self.dga_baseline.to_dict(),
            "risk_baseline": self.risk_baseline.to_dict(),
            "seen_domains": list(self.seen_domains),
        }

    @classmethod
    def from_dict(cls, d: dict, alpha: float = 0.05) -> "DeviceState":
        obj = cls(d.get("device_id", ""), d.get("client_ip", ""), d.get("hostname", ""), alpha)
        obj.device_type = d.get("device_type", "unknown")
        obj.last_alert_time = d.get("last_alert_time", 0.0)
        obj.last_alert_risk = d.get("last_alert_risk", 0.0)
        obj.last_alert_signature = d.get("last_alert_signature", "")

        if "rate_baseline" in d: obj.rate_baseline = BaselineMetric.from_dict(d["rate_baseline"])
        if "entropy_baseline" in d: obj.entropy_baseline = BaselineMetric.from_dict(d["entropy_baseline"])
        if "unique_baseline" in d: obj.unique_baseline = BaselineMetric.from_dict(d["unique_baseline"])
        if "nxdomain_baseline" in d: obj.nxdomain_baseline = BaselineMetric.from_dict(d["nxdomain_baseline"])
        if "blocked_baseline" in d: obj.blocked_baseline = BaselineMetric.from_dict(d["blocked_baseline"])
        if "dga_baseline" in d: obj.dga_baseline = BaselineMetric.from_dict(d["dga_baseline"])
        if "risk_baseline" in d: obj.risk_baseline = BaselineMetric.from_dict(d["risk_baseline"])
        
        # Restore seen_domains as insertion-ordered dict regardless of
        # what format it was saved in (list from old code, or dict keys).
        # A list of strings → {s: None for s in list} gives the right type.
        # An empty default → {}.
        raw_seen = d.get("seen_domains", [])
        if isinstance(raw_seen, dict):
            obj.seen_domains = raw_seen
        else:
            obj.seen_domains = {s: None for s in raw_seen if isinstance(s, str)}
        return obj