"""
state.py - Device state management and statistical baselining.

Handles serialization, EWMA (Exponentially Weighted Moving Average) tracking,
and diurnal (time-of-day) baseline segregation.
"""
from collections import deque, defaultdict

class BaselineMetric:
    """Tracks a 24-hour diurnal array of running mean and variance."""
    def __init__(self, alpha: float = 0.05):
        self.alpha = alpha
        self.mean = [0.0] * 24
        self.var = [1.0] * 24
        self.n = [0] * 24
        self.initialized = False

    def update(self, value: float, hour: int) -> None:
        """Updates the specific hour's mean and variance with a new data point."""
        hour = int(hour) % 24
        if self.n[hour] == 0:
            self.mean[hour] = value
            self.var[hour] = 1.0
            self.initialized = True
        else:
            diff = value - self.mean[hour]
            self.mean[hour] += self.alpha * diff
            self.var[hour] = (1 - self.alpha) * (self.var[hour] + self.alpha * diff ** 2)
        self.n[hour] += 1

    def get_stats(self, hour: int) -> tuple[float, float, bool, int]:
        hour = int(hour) % 24
        return self.mean[hour], self.var[hour], self.initialized, self.n[hour]

    def to_dict(self) -> dict:
        return {
            "alpha": self.alpha,
            "mean": self.mean,
            "var": self.var,
            "n": self.n,
            "initialized": self.initialized
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BaselineMetric":
        bm = cls(alpha=data.get("alpha", 0.05))
        bm.mean = data.get("mean", [0.0] * 24)
        bm.var = data.get("var", [1.0] * 24)
        bm.n = data.get("n", [0] * 24)
        bm.initialized = data.get("initialized", False)
        return bm

class RollingWindow:
    """Ephemeral memory tracking current cycle metrics before pipeline flush."""
    def __init__(self):
        self.events = deque()
        self.domains = defaultdict(int)
        self.domain_timestamps = defaultdict(deque)
        self.blocked = 0
        self.nxdomain = 0
        
    def cap_domains(self):
        """Prevents dynamic memory explosion during massive DGA bursts."""
        if len(self.domains) > 10000:
            sorted_domains = sorted(self.domains.items(), key=lambda x: x[1], reverse=True)[:5000]
            self.domains = defaultdict(int, sorted_domains)

class DeviceState:
    """Persistent tracking matrix per physical network device."""
    def __init__(self, device_id: str, client_ip: str, hostname: str, alpha: float = 0.05):
        self.device_id = device_id
        self.client_ip = client_ip
        self.hostname = hostname
        self.device_type = "unknown"
        self.mac_address = "unknown"
        
        self.rolling = RollingWindow()
        self.seen_domains = {}
        
        self.last_alert_time = 0.0
        self.last_alert_risk = 0.0
        self.last_alert_signature = ""
        
        self.rate_baseline = BaselineMetric(alpha)
        self.entropy_baseline = BaselineMetric(alpha)
        self.unique_baseline = BaselineMetric(alpha)
        self.nxdomain_baseline = BaselineMetric(alpha)
        self.blocked_baseline = BaselineMetric(alpha)
        self.dga_baseline = BaselineMetric(alpha)
        self.risk_baseline = BaselineMetric(alpha)
        self.outbound_bytes_baseline = BaselineMetric(alpha)

    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "client_ip": self.client_ip,
            "hostname": self.hostname,
            "device_type": self.device_type,
            "mac_address": getattr(self, "mac_address", "unknown"),
            "seen_domains": list(self.seen_domains.keys()),
            "last_alert_time": self.last_alert_time,
            "last_alert_risk": self.last_alert_risk,
            "last_alert_signature": self.last_alert_signature,
            "rate_baseline": self.rate_baseline.to_dict(),
            "entropy_baseline": self.entropy_baseline.to_dict(),
            "unique_baseline": self.unique_baseline.to_dict(),
            "nxdomain_baseline": self.nxdomain_baseline.to_dict(),
            "blocked_baseline": self.blocked_baseline.to_dict(),
            "dga_baseline": self.dga_baseline.to_dict(),
            "risk_baseline": self.risk_baseline.to_dict(),
            "outbound_bytes_baseline": self.outbound_bytes_baseline.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict, alpha: float = 0.05) -> "DeviceState":
        st = cls(
            device_id=data.get("device_id", ""),
            client_ip=data.get("client_ip", ""),
            hostname=data.get("hostname", ""),
            alpha=alpha
        )
        st.device_type = data.get("device_type", "unknown")
        st.mac_address = data.get("mac_address", "unknown")
        
        seen_list = data.get("seen_domains", [])
        st.seen_domains = {d: None for d in seen_list}
        
        st.last_alert_time = data.get("last_alert_time", 0.0)
        st.last_alert_risk = data.get("last_alert_risk", 0.0)
        st.last_alert_signature = data.get("last_alert_signature", "")
        
        if "rate_baseline" in data: 
            st.rate_baseline = BaselineMetric.from_dict(data["rate_baseline"])
        if "entropy_baseline" in data: 
            st.entropy_baseline = BaselineMetric.from_dict(data["entropy_baseline"])
        if "unique_baseline" in data: 
            st.unique_baseline = BaselineMetric.from_dict(data["unique_baseline"])
        if "nxdomain_baseline" in data: 
            st.nxdomain_baseline = BaselineMetric.from_dict(data["nxdomain_baseline"])
        if "blocked_baseline" in data: 
            st.blocked_baseline = BaselineMetric.from_dict(data["blocked_baseline"])
        if "dga_baseline" in data: 
            st.dga_baseline = BaselineMetric.from_dict(data["dga_baseline"])
        if "risk_baseline" in data: 
            st.risk_baseline = BaselineMetric.from_dict(data["risk_baseline"])
        if "outbound_bytes_baseline" in data: 
            st.outbound_bytes_baseline = BaselineMetric.from_dict(data["outbound_bytes_baseline"])
        
        return st