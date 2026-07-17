"""
features.py – Per-device DNS feature extraction.

Fixes applied (this version):
  - Fixed NXDOMAIN TLD concentration bug: Metric now exclusively calculates the TLD density 
    of FAILED queries, rather than all queries in the window.
  - Aligned BLOCKED status codes with main.py (added code 10).
  - events_per_second uses window_seconds as the denominator.
  - top_domain_ratio calculation normalized.
  - NEW: Incorporates time-arrival pacing parameters (Jitter CV) mapping algorithmic C2 intervals.
  
MEMORY LEAK FIX:
  - Completely removed the massive domain_timestamps reconstruction loop.
    Timestamps are now natively appended in main.py, eliminating massive CPU
    and memory slot churn overhead.
"""
from collections import Counter
import math
from utils import entropy, suspicious_dga
import logging

LOGGER = logging.getLogger("home_ids.features")

BLOCKED  = frozenset({1, 4, 5, 6, 7, 8, 10})
NXDOMAIN = frozenset({3, 12, 13})

class FeatureExtractor:
    def compute(self, state, now: float, window_seconds: int) -> dict:
        rw = state.rolling

        # Sliding window eviction loop pass
        while rw.events and rw.events[0][0] < now - window_seconds:
            ts, domain, status = rw.events.popleft()
            if status in BLOCKED:
                rw.blocked = max(rw.blocked - 1, 0.0)
            if status in NXDOMAIN:
                rw.nxdomain = max(rw.nxdomain - 1, 0.0)
            rw.domains[domain] -= 1
            if rw.domains[domain] <= 0:
                del rw.domains[domain]
                
            # Clean stale timestamp lists for popped items out of sliding queues
            if domain in rw.domain_timestamps:
                while rw.domain_timestamps[domain] and rw.domain_timestamps[domain][0] < now - window_seconds:
                    rw.domain_timestamps[domain].popleft()
                if not rw.domain_timestamps[domain]:
                    del rw.domain_timestamps[domain]

        # Cap Counter size after eviction pass
        rw.cap_domains()

        n_events = len(rw.events)
        if n_events == 0:
            return _zero_features()

        entropy_sum  = 0.0
        suspicious   = 0
        deep_domains = 0
        beaconing_c2_count = 0
        min_jitter_cv = 999.0

        for domain in rw.domains:
            parts        = domain.split(".")
            entropy_sum += entropy(parts[0])
            if suspicious_dga(domain):
                suspicious += 1
            if len(parts) > 5:
                deep_domains += 1
                
            # Compute Coefficient of Variation (Jitter CV) on domain timestamps
            t_list = list(rw.domain_timestamps.get(domain, []))
            if len(t_list) >= 5:
                deltas = [t_list[i] - t_list[i-1] for i in range(1, len(t_list))]
                mean_delta = sum(deltas) / len(deltas)
                if mean_delta > 0:
                    var_delta = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
                    std_delta = math.sqrt(var_delta)
                    cv = std_delta / mean_delta
                    min_jitter_cv = min(min_jitter_cv, cv)
                    
                    # CV < 0.1 reveals strict mechanical timing typical of automation scripts / beacons
                    if cv < 0.1:
                        beaconing_c2_count += 1

        n_domains   = len(rw.domains)
        avg_entropy = entropy_sum / max(n_domains, 1)

        query_rate = n_events * 60.0 / window_seconds
        events_per_second = n_events / max(window_seconds, 1)

        vals   = rw.domains.values()
        mean_v = sum(vals) / max(n_domains, 1)
        query_variance = (
            sum((v - mean_v) ** 2 for v in rw.domains.values()) / max(n_domains, 1)
        )

        domain_total     = sum(rw.domains.values()) or 1
        top_val          = max(rw.domains.values(), default=0)
        top_domain_ratio = top_val / domain_total

        if not isinstance(getattr(state, "seen_domains", None), dict):
            state.seen_domains = {}
        new_domains = sum(1 for d in rw.domains if d not in state.seen_domains)

        nxdomain_tld_conc = 0.0
        nx_events = [ev[1] for ev in rw.events if ev[2] in NXDOMAIN]
        
        # Only calculate concentration if there is a meaningful cluster of failures
        if len(nx_events) >= 5:
            tld_counts = Counter()
            for domain in nx_events:
                parts = domain.rsplit(".", 1)
                if len(parts) == 2:
                    tld_counts[parts[-1]] += 1
            if tld_counts:
                top_tld_count     = tld_counts.most_common(1)[0][1]
                nxdomain_tld_conc = top_tld_count / len(nx_events)

        return {
            "query_rate":         query_rate,
            "unique_domains":     n_domains,
            "blocked_ratio":      min(rw.blocked  / n_events, 1.0),
            "nxdomain_ratio":     min(rw.nxdomain / n_events, 1.0),
            "entropy_avg":        avg_entropy,
            "suspicious_domains": suspicious,
            "total":              n_events,
            "query_variance":     query_variance,
            "events_per_second":  events_per_second,
            "top_domain_ratio":   top_domain_ratio,
            "new_domains":        new_domains,
            "deep_domains":       deep_domains,
            "nxdomain_tld_conc":  nxdomain_tld_conc,
            "beaconing_c2_count": beaconing_c2_count,                      
            "min_jitter_cv":      min_jitter_cv if min_jitter_cv != 999.0 else 0.0  
        }

def _zero_features() -> dict:
    return {
        "query_rate": 0.0,        "unique_domains": 0,
        "blocked_ratio": 0.0,     "nxdomain_ratio": 0.0,
        "entropy_avg": 0.0,       "suspicious_domains": 0,
        "total": 0,               "query_variance": 0.0,
        "events_per_second": 0.0, "top_domain_ratio": 0.0,
        "new_domains": 0,         "deep_domains": 0,
        "nxdomain_tld_conc": 0.0,
        "beaconing_c2_count": 0,                                  
        "min_jitter_cv": 0.0                                      
    }