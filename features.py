"""
features.py – Per-device DNS feature extraction.

Computes metrics over the specified lookback window, tracks algorithmic entropy, 
and measures standard coefficients of variation to surface mechanical timing blocks.

RECENT FIXES:
- FIXED (CRITICAL): Synchronized the `rw.events` popleft() loop with `rw.domains` 
  to prevent defaultdict from spawning artificial negative counts (-1) when 
  processing orphaned events that were truncated by DGA RAM capping.
"""
from collections import Counter
import math
from utils import entropy, suspicious_dga
from config import CONFIG

BLOCKED  = frozenset({1, 4, 5, 6, 7, 8, 10})
NXDOMAIN = frozenset({3, 12, 13})

_DEFAULT_DECAY_FACTOR = 0.995

def _decay_rate_per_second() -> float:
    decay_factor = CONFIG.get("decay_factor", _DEFAULT_DECAY_FACTOR)
    poll_interval = CONFIG.get("poll_interval", 2.0)
    try:
        decay_factor = float(decay_factor)
        poll_interval = float(poll_interval)
    except (TypeError, ValueError):
        return 1.0
    if not (0.0 < decay_factor < 1.0) or poll_interval <= 0:
        return 1.0  
    return decay_factor ** (1.0 / poll_interval)

class FeatureExtractor:
    def compute(self, state, now: float, window_seconds: int) -> dict:
        rw = state.rolling

        # Continuous window eviction logic pass
        while rw.events and rw.events[0][0] < now - window_seconds:
            ts, domain, status = rw.events.popleft()
            if status in BLOCKED:
                rw.blocked = max(rw.blocked - 1, 0)
            if status in NXDOMAIN:
                rw.nxdomain = max(rw.nxdomain - 1, 0)
            
            # FIX: Prevent orphaned events from corrupting domain matrices with negative counts
            if domain in rw.domains:
                rw.domains[domain] -= 1
                if rw.domains[domain] <= 0:
                    del rw.domains[domain]
                
            if domain in rw.domain_timestamps:
                while rw.domain_timestamps[domain] and rw.domain_timestamps[domain][0] < now - window_seconds:
                    rw.domain_timestamps[domain].popleft()
                if not rw.domain_timestamps[domain]:
                    del rw.domain_timestamps[domain]

        rw.cap_domains()
        n_events = len(rw.events)
        if n_events == 0:
            return self._zero_features()

        entropy_sum  = 0.0
        suspicious   = 0
        deep_domains = 0
        beaconing_c2_count = 0
        min_jitter_cv = 999.0

        decay_rate = _decay_rate_per_second()
        decayed_weights = {}
        decayed_total = 0.0

        for domain in rw.domains:
            parts = domain.split(".")
            entropy_sum += entropy(parts[0])
            if suspicious_dga(domain):
                suspicious += 1
            if len(parts) > 5:
                deep_domains += 1
                
            t_list = list(rw.domain_timestamps.get(domain, []))

            weight = sum(decay_rate ** max(0.0, now - t) for t in t_list)
            decayed_weights[domain] = weight
            decayed_total += weight

            if len(t_list) >= 5:
                deltas = [t_list[i] - t_list[i-1] for i in range(1, len(t_list))]
                mean_delta = sum(deltas) / len(deltas)
                if mean_delta > 0:
                    var_delta = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
                    cv = math.sqrt(var_delta) / mean_delta
                    min_jitter_cv = min(min_jitter_cv, cv)
                    if cv < 0.1:
                        beaconing_c2_count += 1

        n_domains   = len(rw.domains)
        avg_entropy = entropy_sum / max(n_domains, 1)
        query_rate = n_events * 60.0 / window_seconds

        vals   = list(rw.domains.values())
        mean_v = sum(vals) / max(n_domains, 1)
        query_variance = sum((v - mean_v) ** 2 for v in vals) / max(n_domains, 1)

        top_domain_ratio = max(decayed_weights.values(), default=0.0) / max(decayed_total, 1e-9)
        new_domains = sum(1 for d in rw.domains if d not in state.seen_domains)

        nxdomain_tld_conc = 0.0
        nx_events = [ev[1] for ev in rw.events if ev[2] in NXDOMAIN]
        if len(nx_events) >= 5:
            tld_counts = Counter()
            for domain in nx_events:
                parts = domain.rsplit(".", 1)
                if len(parts) == 2:
                    tld_counts[parts[-1]] += 1
            if tld_counts:
                nxdomain_tld_conc = tld_counts.most_common(1)[0][1] / len(nx_events)

        return {
            "query_rate": query_rate,
            "unique_domains": n_domains,
            "blocked_ratio": min(rw.blocked / n_events, 1.0),
            "nxdomain_ratio": min(rw.nxdomain / n_events, 1.0),
            "entropy_avg": avg_entropy,
            "suspicious_domains": suspicious,
            "total": n_events,
            "query_variance": query_variance,
            "events_per_second": n_events / max(window_seconds, 1),
            "top_domain_ratio": top_domain_ratio,
            "new_domains": new_domains,
            "deep_domains": deep_domains,
            "nxdomain_tld_conc": nxdomain_tld_conc,
            "beaconing_c2_count": beaconing_c2_count,
            "min_jitter_cv": min_jitter_cv if min_jitter_cv != 999.0 else 0.0
        }

    def _zero_features(self) -> dict:
        return {
            "query_rate": 0.0,
            "unique_domains": 0,
            "blocked_ratio": 0.0,
            "nxdomain_ratio": 0.0,
            "entropy_avg": 0.0,
            "suspicious_domains": 0,
            "total": 0,
            "query_variance": 0.0,
            "events_per_second": 0.0,
            "top_domain_ratio": 0.0,
            "new_domains": 0,
            "deep_domains": 0,
            "nxdomain_tld_conc": 0.0,
            "beaconing_c2_count": 0,
            "min_jitter_cv": 0.0
        }