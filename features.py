"""
features.py – Scale-Normalized Vector Feature Extraction.

Hardened Architectural Syncs:
  • Handles signature inspection for suspicious_dga transparently.
  • Clamps window counters cleanly to eliminate floating-point decay drops.
"""
import math
import time
import inspect
from collections import Counter
from utils import entropy, suspicious_dga

BLOCKED  = frozenset({1, 4, 5, 6, 7, 8, 10})
NXDOMAIN = frozenset({3, 12, 13})


class FeatureExtractor:
    def __init__(self):
        try:
            sig = inspect.signature(suspicious_dga)
            self._dga_takes_entropy = len(sig.parameters) >= 2
        except Exception:
            self._dga_takes_entropy = False

    def compute(self, state, now: float, window_seconds: int) -> dict:
        rw      = state.rolling
        popleft = rw.events.popleft
        cutoff  = now - window_seconds

        while rw.events and rw.events[0][0] < cutoff:
            ts, domain, status = popleft()
            if status in BLOCKED:
                rw.blocked = max(rw.blocked - 1, 0.0)
            if status in NXDOMAIN:
                rw.nxdomain = max(rw.nxdomain - 1, 0.0)
            rw.domains[domain] -= 1
            if rw.domains[domain] <= 0:
                del rw.domains[domain]

        n_events = len(rw.events)
        if n_events == 0:
            return _zero_features()

        entropy_sum = 0
        suspicious  = 0
        deep_domains = 0
        new_domains  = 0
        tld_counts   = Counter()

        for domain, count in rw.domains.items():
            ent = entropy(domain)
            entropy_sum += ent * count

            if self._dga_takes_entropy:
                is_dga = suspicious_dga(domain, ent)
            else:
                is_dga = suspicious_dga(domain)

            if is_dga:
                suspicious += count

            labels = domain.split(".")
            if len(labels) > 5:
                deep_domains += count

            if domain not in state.seen_domains:
                new_domains += count

            if len(labels) >= 2:
                tld = labels[-1]
                tld_counts[tld] += count

        avg_entropy = entropy_sum / n_events
        query_rate  = (n_events / window_seconds) * 60.0
        n_domains   = len(rw.domains)

        mean_rate = n_events / len(rw.domains) if rw.domains else 1.0
        query_variance = float(sum((count - mean_rate) ** 2 for count in rw.domains.values()) / n_domains) if n_domains > 1 else 0.0
        events_per_second = n_events / window_seconds

        top_domain_count = rw.domains.most_common(1)[0][1] if rw.domains else 0
        top_domain_ratio = top_domain_count / sum(rw.domains.values())

        new_domains_ratio = new_domains / n_events
        deep_domains_ratio = deep_domains / n_events

        nxdomain_tld_conc = 0.0
        if rw.nxdomain > 0 and tld_counts:
            top_tld_count = tld_counts.most_common(1)[0][1]
            nxdomain_tld_conc = top_tld_count / n_events

        return {
            "query_rate":          query_rate,
            "unique_domains":      n_domains,
            "blocked_ratio":       min(rw.blocked  / n_events, 1.0),
            "nxdomain_ratio":      min(rw.nxdomain / n_events, 1.0),
            "entropy_avg":         avg_entropy,
            "suspicious_domains":  suspicious,
            "total":               n_events,
            "query_variance":      query_variance,
            "events_per_second":   events_per_second,
            "top_domain_ratio":    top_domain_ratio,
            "new_domains":         new_domains_ratio,
            "deep_domains":        deep_domains_ratio,
            "nxdomain_tld_conc":   nxdomain_tld_conc,
        }


def _zero_features() -> dict:
    return {
        "query_rate": 0.0,       "unique_domains": 0,
        "blocked_ratio": 0.0,    "nxdomain_ratio": 0.0,
        "entropy_avg": 0.0,      "suspicious_domains": 0,
        "total": 0,              "query_variance": 0.0,
        "events_per_second": 0.0,"top_domain_ratio": 0.0,
        "new_domains": 0.0,      "deep_domains": 0.0,
        "nxdomain_tld_conc": 0.0
    }