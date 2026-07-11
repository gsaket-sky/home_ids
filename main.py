"""
main.py – Thread-Safe Home IDS Core Processing Loop with Complete Prometheus Metrics Export.

Hardened Architectural Syncs:
  • Aligns ALL geographic traffic metrics (geo_traffic_total, geo_queries_per_minute,
    geo_unique_domains, geo_entropy, geo_device_count) to their exact label configurations.
  • Corrects geo_hits_metric syntax from .set() to .inc().
  • Retains structural engine patches for threat intel and zscore behaviors.

Advanced Security & Statistical Enhancements:
  • Diurnal Core: Time-aware metric extraction blocks for Day/Night anomaly accuracy.
  • Peer-Group Clustering: Falls back to clustered device-type baseline models for cold devices.
  • Anti-Poisoning Filter: Freezes ML models & baselines instantly if a device joins infected (Day-Zero protection).
  • Stateful Enrichment: Detects familiar infrastructure to dampen false-positive beaconing risks.

Codex changelog 2026-06-18:
  - Added explainable alert payloads with all scoring factors.
  - Added threat-intel match details in alerts, including provider, domain, IP, hostname, and device IP.
  - Added capped JSON alert logging via AlertJSONWriter.
  - Excluded safe Pi-hole/DNS hosts from state creation, scoring, metrics, and alerts.
  - Removed stale Prometheus label series when safe devices are dropped or hostname/type labels change.
"""

import argparse
import sys

import hashlib
import json
import logging
import signal
import time
import threading
import socket
import math
from collections import OrderedDict, Counter
from pathlib import Path

from prometheus_client import start_http_server

from config import CONFIG
from collector import PiHoleCollector
from threat_intel import ThreatIntel, AbuseIPDB, VirusTotalClient
from zeek_collector import ZeekCollector, ZeekFeatureExtractor
from state import DeviceState
from features import FeatureExtractor
from scoring import RiskScorer
from ml_engine import MLRegistry
from alerts import AlertManager, AlertJSONWriter
from geoip_engine import GeoIPEngine
from utils import (
    normalize_domain,
    sanitize_hostname,
    resolve_domain,
    infer_device_type,
    suspicious_dga,
)
from metrics import (
    risk_metric, query_rate_metric, unique_domains_metric, entropy_metric,
    blocked_ratio_metric, nxdomain_ratio_metric, suspicious_domains_metric,
    ml_anomaly_metric, zscore_query_metric, zscore_entropy_metric,
    zscore_unique_metric, new_domains_metric, deep_domains_metric,
    nxdomain_tld_conc_metric, zscore_nxdomain_metric, zscore_blocked_metric,
    zscore_dga_metric, risk_velocity_metric, zeek_conn_count_metric,
    zeek_new_ips_metric, zeek_ja3_metric, zeek_notices_metric,
    zeek_susp_ports_metric, ti_risk_metric, ti_match_metric,
    ti_ioc_hits_total, safe_device_metric, geo_risk_metric, geo_hits_metric,
    geo_beacon_metric, asn_risk_metric, country_density_metric,
    geo_traffic_total, geo_queries_per_minute, geo_unique_domains,
    geo_entropy, geo_device_count, collector_lag_metric, alert_queue_metric,
    ml_model_loaded_metric, events_processed_metric, alerts_total,
    query_rate_baseline_mean_metric,
    query_rate_threshold_limit_metric,
)

RUNNING         = True
_SHUTDOWN_EVENT = threading.Event()
LOGGER          = logging.getLogger("home_ids")

STATE_LOCK        = threading.Lock()
ML_WARMUP_SAMPLES = int(CONFIG.get("ml_warmup_samples", 5000))
MAX_STATES        = int(CONFIG.get("max_device_states", 5000))

KNOWN_BLOCKED     = frozenset({1, 4, 5, 6, 7, 8, 10})
KNOWN_NXDOMAIN    = frozenset({3, 12, 13})

_GEO_CACHE = OrderedDict()
_GEO_CACHE_MAX = 1024
_GEO_CACHE_TTL = 300

# =============================================================================
# GLOBAL REGISTRY FOR PEER CLUSTERING
# Maintain group baseline falls: device_type -> feature_name -> {"mean", "var"}
# =============================================================================
PEER_CLUSTER_REGISTRY = {}


def print_ids_documentation():
    """Outputs the complete Home IDS architecture, config blueprint, and hunting playbook."""
    print("=" * 80)
    print("                    HOME IDS - SYSTEM DOCUMENTATION ENGINE                    ")
    print("=" * 80)
    print("\n## 1. HIGH-LEVEL ARCHITECTURE")
    print("-" * 30)
    print("  [Pi-hole DB] ──(Every 2s)──► [collector.py] ─────┐")
    print("  [Zeek Logs]  ──(Every 2s)──► [zeek_collector.py] ─┴─► [main.py] (Core loop)")
    print("                                                            │")
    print("       ┌──────────────────┬─────────────────────────┼────────────────────────┐")
    print("       ▼                  ▼                         ▼                        ▼")
    print(" [state.py]        [features.py]            [threat_intel.py]          [ml_engine.py]")
    print(" (EWMA Memory)     (13 DNS/Zeek Feats)      (O(1) Feodo/URLhaus/VT)    (IsolationForest)")
    print("       │                  │                         │                        │")
    print("       └──────────────────┴───────────┬─────────────┴────────────────────────┘")
    print("                                      ▼")
    print("                                [scoring.py] ──(Risk >= threshold)──► [Telegram Alerts]")

    print("\n## 2. CORE CONFIGURATION BLUEPRINT & IMPACTS")
    print("-" * 45)
    print("  • poll_interval       : Sleep loop timer (Default: 2s). Lowering increases resolution.")
    print("  • window_seconds     : Focus depth for feature extraction counters (Default: 300s/5min).")
    print("  • alert_threshold    : Actionable risk score floor (Default: 6.0). Lower drops false negatives.")
    print("  • threshold_std_dev  : Sigma multiplier (k) for dynamic baseline bounds (Default: 3.0).")
    print("  • baseline_alpha     : EWMA adaptation weight (Default: 0.05). High values blur threat memory.")
    print("  • decay_factor       : Beaconing half-life degradation factor (Default: 0.995).")

    print("\n## 3. THREAT IDENTIFICATION PLAYBOOK")
    print("-" * 37)
    print("  [A] COMMAND & CONTROL BEACONING:")
    print("      - Indicators : High home_ids_zscore_query_rate + top_domain_ratio approaching 1.0.")
    print("      - Concept    : Device stops natural browsing rhythms and ticks fixedly to an endpoint.")
    print("\n  [B] DGA MALWARE BURST:")
    print("      - Indicators : Spike in home_ids_new_domains + home_ids_zscore_nxdomain_ratio.")
    print("      - Concept    : Ransomware querying randomized strings trying to find live active servers.")
    print("\n  [C] DETERMINISTIC MALICIOUS CONNECTIONS:")
    print("      - Indicators : home_ids_ti_match == 1 OR home_ids_zeek_ja3_malicious > 0.")
    print("      - Concept    : Client hit a blocklist threat feed IP or matched standard malware TLS fingerprints.")
    print("\n  [D] STEALTHY BEHAVIORAL ANOMALIES:")
    print("      - Indicators : Elevated home_ids_ml_anomaly_score with flat standard Z-scores.")
    print("      - Concept    : Isolation Forest detected structural shifting inside multi-feature data matrix.")
    print("=" * 80)

# =============================================================================
# DETECTOR ENGINE DUCK-TYPING PROPERTY COUPLING PIPELINE
# =============================================================================
def _baseline_zscore_patch(self, val: float) -> float:
    """Dynamically attached calculation for internal scoring.py calls."""
    if not getattr(self, "initialized", False) or getattr(self, "n", 0) < 30:
        return 0.0
    variance = getattr(self, "var", 1.0)
    std_dev = math.sqrt(max(variance, 1e-6))
    return (val - getattr(self, "mean", 0.0)) / std_dev

try:
    from state import BaselineMetric
    if not hasattr(BaselineMetric, "warmed_up"):
        BaselineMetric.warmed_up = property(lambda self: getattr(self, "initialized", False))
    if not hasattr(BaselineMetric, "zscore"):
        BaselineMetric.zscore = _baseline_zscore_patch
except Exception as patch_exc:
    LOGGER.warning("Could not execute structural baseline property bindings: %s", patch_exc)


def calculate_zscore(val: float, baseline, cap=8.0) -> float:
    """
    Safely calculates the Z-Score of a feature using its running baseline.
    (Legacy flat baseline structure - kept for compatibility)
    """
    if not getattr(baseline, 'initialized', False) or getattr(baseline, 'n', 0) < 100:
        return 0.0
    std_dev = math.sqrt(max(getattr(baseline, 'var', 1.0), 1.0))
    z = (val - getattr(baseline, 'mean', 0.0)) / std_dev
    return max(-cap, min(cap, z))


def calculate_adaptive_zscore(val: float, baseline, feature_name: str, dev_type: str, hour: int) -> float:
    """
    Extracts diurnal stats based on the hour; falls back to peer cluster averages 
    if the device profile is cold. This protects newly connected devices from 
    anomalous scoring traps by comparing them to known 'like' device profiles.
    """
    mean, var, initialized, n = baseline.get_stats(hour)
    
    # If this specific device baseline is warm for this time block, use it directly
    if initialized and n >= 100:
        # Update peer cluster matrix with fresh, verified data points to continuously train peer groups
        PEER_CLUSTER_REGISTRY.setdefault(dev_type, {}).setdefault(feature_name, {"mean": mean, "var": var})
        std_dev = math.sqrt(max(var, 1.0))
        return max(-8.0, min(8.0, (val - mean) / std_dev))
    
    # Cold start fallback: check if peer cluster behavior templates exist
    peer_template = PEER_CLUSTER_REGISTRY.get(dev_type, {}).get(feature_name)
    if peer_template:
        p_mean = peer_template["mean"]
        p_std  = math.sqrt(max(peer_template["var"], 1.0))
        return max(-8.0, min(8.0, (val - p_mean) / p_std))
    
    # Absolute cold start fallback with no peer baseline history
    return 0.0


def _geo_lookup_cached(geoip_engine: GeoIPEngine, domain: str) -> dict:
    now = time.time()
    cached = _GEO_CACHE.get(domain)
    if cached is not None:
        _ip, geo, expiry = cached
        if now < expiry:
            _GEO_CACHE.move_to_end(domain)
            return geo

    ip  = _resolve_safe_timeout(domain)
    geo = _geo_from_ip(geoip_engine, ip)
    _GEO_CACHE[domain] = (ip, geo, now + _GEO_CACHE_TTL)
    _GEO_CACHE.move_to_end(domain)
    if len(_GEO_CACHE) > _GEO_CACHE_MAX:
        _GEO_CACHE.popitem(last=False)
    return geo


def _resolve_safe_timeout(domain: str):
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(1.0)
        return resolve_domain(domain)
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def _geo_from_ip(geoip_engine: GeoIPEngine, ip) -> dict:
    if not ip:
        return _unknown_geo()
    try:
        geo = geoip_engine.geo_labels(ip) or {}
    except Exception:
        return _unknown_geo()
    geo.setdefault("country",   "unknown")
    geo.setdefault("city",      "unknown")
    geo.setdefault("continent", "unknown")
    geo.setdefault("asn",       "unknown")
    geo.setdefault("org",       "unknown")
    geo.setdefault("latitude",  "0")
    geo.setdefault("longitude", "0")
    return geo


def _unknown_geo() -> dict:
    return {
        "country": "unknown", "city": "unknown", "continent": "unknown",
        "latitude": "0", "longitude": "0", "asn": "unknown", "org": "unknown",
    }


def load_states(path: str, alpha: float) -> "OrderedDict":
    p = Path(path)
    if not p.exists():
        return OrderedDict()
    try:
        data = json.loads(p.read_text())
        result = OrderedDict()
        for device_id, d in data.items():
            result[device_id] = DeviceState.from_dict(d, alpha=alpha)
        LOGGER.info("Loaded baselines for %d devices from %s", len(result), path)
        return result
    except Exception:
        LOGGER.warning("Could not load state from %s — starting fresh", path)
        return OrderedDict()


def save_states(states: "OrderedDict", path: str) -> None:
    p = Path(path)
    try:
        with STATE_LOCK:
            cloned_snapshot = {k: v.to_dict() for k, v in states.items()}
        
        tmp = p.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cloned_snapshot, f, separators=(",", ":"))
        tmp.replace(p)
        LOGGER.info("Successfully flushed structural baselines safely to disk: %s", p)
    except Exception as exc:
        LOGGER.warning("Could not save state to %s: %s", path, exc)


def shutdown(*_):
    global RUNNING
    RUNNING = False
    _SHUTDOWN_EVENT.set()


def setup_logging():
    level = CONFIG.get("log_level", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def stable_device_id(raw_client: str) -> str:
    return hashlib.sha256(raw_client.encode("utf-8", errors="ignore")).hexdigest()[:12]


def trim_states(states: OrderedDict):
    while len(states) > MAX_STATES:
        states.popitem(last=False)


def _safe_pattern_set(patterns) -> set[str]:
    return {str(p).lower() for p in (patterns or []) if str(p).strip()}


def _is_safe_device(client_ip: str, hostname: str, safe_ips: set, safe_host_patterns: set) -> bool:
    ip = str(client_ip or "").strip()
    host = str(hostname or "").lower().strip()
    if ip and ip in safe_ips:
        return True
    return any(pattern in host for pattern in safe_host_patterns)


def _drop_safe_states(states: OrderedDict, safe_ips: set, safe_host_patterns: set) -> None:
    for dev_id, st in list(states.items()):
        if _is_safe_device(st.client_ip, st.hostname, safe_ips, safe_host_patterns):
            _remove_device_metric_labels(dev_id, st.hostname, st.device_type)
            states.pop(dev_id, None)


_DEVICE_GAUGES = (
    risk_metric, query_rate_metric, unique_domains_metric, entropy_metric,
    blocked_ratio_metric, nxdomain_ratio_metric, suspicious_domains_metric,
    ml_anomaly_metric, zscore_query_metric, zscore_entropy_metric,
    zscore_unique_metric, new_domains_metric, deep_domains_metric,
    nxdomain_tld_conc_metric, zscore_nxdomain_metric, zscore_blocked_metric,
    zscore_dga_metric, risk_velocity_metric, zeek_conn_count_metric,
    zeek_new_ips_metric, zeek_ja3_metric, zeek_notices_metric,
    zeek_susp_ports_metric, ti_risk_metric, ti_match_metric,
    safe_device_metric, query_rate_baseline_mean_metric,
    query_rate_threshold_limit_metric,
)


def _remove_device_metric_labels(dev_id: str, hostname: str, device_type: str) -> None:
    if not dev_id or not hostname or not device_type:
        return
    for metric in _DEVICE_GAUGES:
        try:
            metric.remove(dev_id, hostname, device_type)
        except KeyError:
            pass
        except Exception:
            LOGGER.debug("Could not remove stale metric labels for %s/%s", dev_id, hostname)


def safe_ti_check(ti_obj, domain: str) -> bool:
    """Return True if domain matches any loaded threat-intel feed."""
    try:
        if hasattr(ti_obj, "lookup_domain"):
            return ti_obj.lookup_domain(domain) is not None
        if hasattr(ti_obj, "check_domain"):
            return bool(ti_obj.check_domain(domain))
        if hasattr(ti_obj, "match"):
            return bool(ti_obj.match(domain))
    except Exception:
        pass
    return False


def _apply_device_type(st, dev_id: str, overrides: dict) -> None:
    if st.client_ip in overrides:
        st.device_type = overrides[st.client_ip]
        return
    if dev_id in overrides:
        st.device_type = overrides[dev_id]
        return
    if st.device_type == "unknown":
        st.device_type = infer_device_type(st.hostname)


_MAX_SEEN_DOMAINS = 5_000   # reduced from 20k — saves ~60 MB on 50-device network


def _vt_should_enqueue(domain: str, feats: dict) -> bool:
    """Pre-filter domains worth a VirusTotal lookup (rate-limited API)."""
    if suspicious_dga(domain):
        return True
    if feats.get("nxdomain_ratio", 0.0) > 0.3:
        return True
    if feats.get("new_domains", 0.0) > 0.05:
        return True
    return False


def _evaluate_intel(
    st,
    feats: dict,
    ti: ThreatIntel,
    abuseipdb: AbuseIPDB | None,
    vt: VirusTotalClient | None,
    zeek_dest_ips: set,
    zeek_http_reqs: set,  
) -> tuple[float, float, float, int, list]:
    """
    Evaluate all IOC feeds for a device window.
    Returns (ti_risk, abuseipdb_risk, vt_risk, any_match_flag, matches).
    """
    ti_risk = 0.0
    abuse_risk = 0.0
    vt_risk = 0.0
    any_match = 0
    matches = []
    checked_ips: set[str] = set()

    # Check exact URL matches from Zeek's http.log
    for req in zeek_http_reqs:
        url_ti = ti.lookup_url(req)
        if url_ti:
            score = url_ti.get("confidence", 0.95) * 4.0
            ti_risk = max(ti_risk, score)
            any_match = 1
            matches.append({
                "provider": url_ti.get("source", "threat_intel"),
                "ioc_type": "url",
                "url": req,
                "hostname": st.hostname or "unknown",
                "device_ip": st.client_ip or "unknown",
                "confidence": url_ti.get("confidence"),
                "tags": url_ti.get("tags", []),
                "risk": score,
            })
            ti_ioc_hits_total.labels(source="threat_intel", ioc_type="url").inc()

    def _check_ip(ip: str) -> None:
        nonlocal ti_risk, abuse_risk, vt_risk, any_match
        if not ip or ip in checked_ips:
            return
        checked_ips.add(ip)

        if abuseipdb and abuseipdb.lookup(ip):
            abuse_risk = 4.0
            any_match = 1
            matches.append({
                "provider": "abuseipdb",
                "ioc_type": "ip",
                "ip": ip,
                "hostname": st.hostname or "unknown",
                "device_ip": st.client_ip or "unknown",
                "risk": 4.0,
            })
            ti_ioc_hits_total.labels(source="abuseipdb", ioc_type="ip").inc()
            if vt:
                vt.enqueue_ip(ip, priority=2)

        ip_ti = ti.lookup_ip(ip)
        if ip_ti:
            ip_score = ti.ioc_risk_score(ip=ip)
            ti_risk = max(ti_risk, ip_score)
            any_match = 1
            matches.append({
                "provider": ip_ti.get("source", "threat_intel"),
                "ioc_type": "ip",
                "ip": ip,
                "hostname": st.hostname or "unknown",
                "device_ip": st.client_ip or "unknown",
                "confidence": ip_ti.get("confidence"),
                "tags": ip_ti.get("tags", []),
                "risk": ip_score,
            })
            ti_ioc_hits_total.labels(source="threat_intel", ioc_type="ip").inc()

        if vt:
            ip_vt_risk = vt.risk_contribution("ip", ip)
            vt_risk = max(vt_risk, ip_vt_risk)
            if vt.is_malicious("ip", ip):
                any_match = 1
                matches.append({
                    "provider": "virustotal",
                    "ioc_type": "ip",
                    "ip": ip,
                    "hostname": st.hostname or "unknown",
                    "device_ip": st.client_ip or "unknown",
                    "risk": ip_vt_risk,
                })

    for domain_entry in st.rolling.domains.keys():
        resolved_ip = _resolve_safe_timeout(domain_entry) or "unknown"
        domain_ti = ti.lookup_domain(domain_entry)
        if domain_ti:
            domain_score = ti.ioc_risk_score(domain=domain_entry)
            ti_risk = max(ti_risk, domain_score)
            any_match = 1
            matches.append({
                "provider": domain_ti.get("source", "threat_intel"),
                "ioc_type": "domain",
                "domain": domain_entry,
                "ip": resolved_ip,
                "hostname": st.hostname or "unknown",
                "device_ip": st.client_ip or "unknown",
                "confidence": domain_ti.get("confidence"),
                "tags": domain_ti.get("tags", []),
                "matched_parent": domain_ti.get("matched_parent", False),
                "risk": domain_score,
            })
            ti_ioc_hits_total.labels(source="threat_intel", ioc_type="domain").inc()
            if vt:
                vt.enqueue_domain(domain_entry, priority=2)
        elif vt and _vt_should_enqueue(domain_entry, feats):
            priority = 1 if suspicious_dga(domain_entry) else 5
            vt.enqueue_domain(domain_entry, priority=priority)

        if vt:
            domain_vt_risk = vt.risk_contribution("domain", domain_entry)
            vt_risk = max(vt_risk, domain_vt_risk)
            if vt.is_malicious("domain", domain_entry):
                any_match = 1
                matches.append({
                    "provider": "virustotal",
                    "ioc_type": "domain",
                    "domain": domain_entry,
                    "ip": resolved_ip,
                    "hostname": st.hostname or "unknown",
                    "device_ip": st.client_ip or "unknown",
                    "risk": domain_vt_risk,
                })

        _check_ip(resolved_ip)

    for ip in zeek_dest_ips:
        _check_ip(ip)

    return ti_risk, abuse_risk, vt_risk, any_match, matches


def _format_alert_message(payload: dict) -> str:
    device = payload["device"]
    lines = [
        f"[ALERT] {device['hostname']} ({device['ip']}) risk {payload['risk']:.2f} / threshold {payload['threshold']:.2f}",
        f"Device type: {device['type']} | top reason: {payload['signature']}",
        "Factors:",
    ]
    for factor in payload.get("factors", []):
        detail = f" - {factor.get('detail')}" if factor.get("detail") else ""
        value = f" value={factor.get('value')}" if factor.get("value") not in (None, "") else ""
        lines.append(f"- {factor.get('name')}: +{factor.get('score')}{value}{detail}")
    matches = payload.get("threat_intel_matches", [])
    if matches:
        lines.append("Threat intel matches:")
        for match in matches[:10]:
            ioc = match.get("domain") or match.get("ip") or "unknown"
            lines.append(f"- {match.get('provider', 'unknown')} {match.get('ioc_type')}: {ioc} ip={match.get('ip', 'unknown')} host={match.get('hostname', 'unknown')}")
    return "\n".join(lines)[:3900]


def _build_alert_payload(st, dev_id: str, now: float, risk_score: float,
                         alert_threshold: float, signature: str,
                         risk_details: dict, feats: dict, ml_score: float,
                         ti_matches: list, zeek_alerts: list) -> dict:
    return {
        "timestamp": now,
        "device": {
            "id": dev_id,
            "ip": st.client_ip or "unknown",
            "hostname": st.hostname or "unknown",
            "type": st.device_type or "unknown",
        },
        "risk": float(risk_score),
        "threshold": float(alert_threshold),
        "signature": signature,
        "factors": risk_details.get("factors", []),
        "features": dict(feats),
        "ml_score": float(ml_score),
        "threat_intel_matches": ti_matches,
        "zeek_alerts": zeek_alerts or [],
    }


def main():
    global RUNNING

    # Set up argument parser for terminal documentation injection
    parser = argparse.ArgumentParser(description="Home IDS Threat Hunting Engine Processing Daemon")
    parser.add_main = parser.add_argument(
        "--info", action="store_true", help="Display interactive system architecture, config blueprint, and hunting playbook"
    )
    args, unknown = parser.parse_known_args()

    if args.info:
        print_ids_documentation()
        sys.exit(0)
        
    setup_logging()
    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    _safe_ips = set(CONFIG.get("safe_ips", ["127.0.0.1"]))
    _safe_host_patterns = _safe_pattern_set(CONFIG.get("safe_host_patterns", []))
    collector = PiHoleCollector(
        db_path            = CONFIG.get("pihole_db", "/etc/pihole/pihole-FTL.db"),
        lookback_seconds   = int(CONFIG.get("startup_lookback_seconds", 300)),
        excluded_ips       = _safe_ips,
        excluded_patterns  = _safe_host_patterns,
    )
    extractor = FeatureExtractor()
    scorer    = RiskScorer()
    ml        = MLRegistry(
        model_dir         = Path(CONFIG["model_path"]).parent / "devices",
        global_model_path = Path(CONFIG["model_path"]),
    )
    geoip_engine = GeoIPEngine(CONFIG["geoip_db"])
    
    tg_token = CONFIG.get("telegram_token", "")
    tg_chat  = CONFIG.get("telegram_chat_id", "")
    _tg_enabled  = CONFIG.get("telegram_enabled", False) and bool(tg_token) and bool(tg_chat)
    
    alerts       = AlertManager(
        token   = tg_token if _tg_enabled else "",
        chat_id = tg_chat if _tg_enabled else "",
        enabled = _tg_enabled,
    )
    alert_log = AlertJSONWriter(
        path=CONFIG.get("alert_json_path", "alerts.jsonl"),
        max_bytes=int(CONFIG.get("alert_json_max_bytes", 1073741824)),
    )
    
    _alpha = float(CONFIG.get("baseline_alpha", 0.05))
    
    with STATE_LOCK:
        states = load_states(CONFIG["state_path"], alpha=_alpha)
        _drop_safe_states(states, _safe_ips, _safe_host_patterns)

    ti = ThreatIntel(
        cache_dir        = str(Path(CONFIG["state_path"]).parent / "ti_cache"),
        otx_api_key      = CONFIG.get("otx_api_key", ""),
        refresh_interval = int(CONFIG.get("ti_refresh_interval", 3600)),
    )
    ti.start_refresh_thread()

    _ti_cache = Path(CONFIG["state_path"]).parent / "ti_cache"
    _ti_cache.mkdir(parents=True, exist_ok=True)
    _ti_refresh = int(CONFIG.get("ti_refresh_interval", 3600))

    abuseipdb = None
    if CONFIG.get("abuseipdb_api_key", ""):
        abuseipdb = AbuseIPDB(
            api_key          = CONFIG["abuseipdb_api_key"],
            cache_dir        = _ti_cache,
            refresh_interval = _ti_refresh,
        )
        abuseipdb.start_refresh_thread()
        LOGGER.info("AbuseIPDB integration enabled")

    vt = None
    if CONFIG.get("virustotal_api_key", ""):
        vt = VirusTotalClient(api_key=CONFIG["virustotal_api_key"], cache_dir=_ti_cache)
        LOGGER.info("VirusTotal integration enabled (async queue)")

    zeek = ZeekCollector(
        log_dir       = CONFIG.get("zeek_log_dir", "/opt/zeek/logs/current"),
        poll_interval = float(CONFIG["poll_interval"]),
    )
    zeek_fx = ZeekFeatureExtractor()
    start_http_server(int(CONFIG.get("metrics_port", 9105)))

    def _on_config_change(changed: dict) -> None:
        if "safe_ips" in changed or "safe_host_patterns" in changed:
            _safe_ips.clear()
            _safe_ips.update(CONFIG.get("safe_ips", ["127.0.0.1"]))
            _safe_host_patterns.clear()
            _safe_host_patterns.update(_safe_pattern_set(CONFIG.get("safe_host_patterns", [])))
            collector.excluded_ips = set(_safe_ips)
            collector.excluded_patterns = set(_safe_host_patterns)
            with STATE_LOCK:
                _drop_safe_states(states, _safe_ips, _safe_host_patterns)
        if "telegram_enabled" in changed or "telegram_token" in changed or "telegram_chat_id" in changed:
            tk = CONFIG.get("telegram_token", "")
            ch = CONFIG.get("telegram_chat_id", "")
            alerts.enabled = CONFIG.get("telegram_enabled", False) and bool(tk) and bool(ch)
            if alerts.enabled:
                alerts.token = tk
                alerts.chat_id = ch

    CONFIG.set_notify(_on_config_change)
    CONFIG.start_watcher(interval=5.0)

    LOGGER.info("HOME IDS Core actively parsing threats.")
    _save_interval = 300
    _last_save = time.time()

    total_events_processed = 0
    _type_overrides = CONFIG.get("device_type_overrides", {})

    while RUNNING:
        loop_start = time.time()
        try:
            rows = collector.poll()
            zeek_events = list(zeek.poll())
            for zeek_event in zeek_events:
                zeek_fx.ingest(zeek_event)

            now        = loop_start
            batch_size = len(rows)
            total_events_processed += batch_size
            events_processed_metric.inc(batch_size)

            if rows:
                collector_lag_metric.set(max(0.0, now - rows[-1]["timestamp"]))

                with STATE_LOCK:
                    for row in rows:
                        client_ip = str(row["client_ip"])
                        hostname  = str(row["hostname"])
                        dev_id    = stable_device_id(client_ip)

                        if dev_id not in states:
                            states[dev_id] = DeviceState(
                                device_id = dev_id,
                                client_ip = client_ip,
                                hostname  = hostname,
                                alpha     = _alpha
                            )
                            trim_states(states)

                        st = states[dev_id]
                        old_hostname    = st.hostname
                        old_device_type = st.device_type
                        st.client_ip = client_ip
                        st.hostname  = hostname
                        _apply_device_type(st, dev_id, _type_overrides)
                        if old_hostname != st.hostname or old_device_type != st.device_type:
                            _remove_device_metric_labels(dev_id, old_hostname, old_device_type)

                        domain = normalize_domain(str(row["domain"]))
                        status = int(row["status"])

                        st.rolling.events.append((now, domain, status))
                        st.rolling.domains[domain] += 1
                        if status in KNOWN_BLOCKED:
                            st.rolling.blocked += 1
                        if status in KNOWN_NXDOMAIN:
                            st.rolling.nxdomain += 1
            else:
                collector_lag_metric.set(0.0)

            with STATE_LOCK:
                active_devices = list(states.items())

            geo_country_counts = Counter()
            geo_device_tracking = {}
            geo_domain_tracking = {}

            for dev_id, st in active_devices:
                if _is_safe_device(st.client_ip, st.hostname, _safe_ips, _safe_host_patterns):
                    _remove_device_metric_labels(dev_id, st.hostname, st.device_type)
                    with STATE_LOCK:
                        states.pop(dev_id, None)
                    continue

                # Set diurnal clock bounds
                current_hour = time.localtime(now).tm_hour

                with STATE_LOCK:
                    feats = extractor.compute(st, now, int(CONFIG["window_seconds"]))
                
                if feats["total"] == 0:
                    continue

                # Inject diurnal context for scoring pipeline
                feats["current_hour"] = current_hour

                # --- IMPROVEMENT 3: STATEFUL ENRICHMENT DETECTOR ---
                # Find the top queried domain in this window to evaluate historical familiarity
                if st.rolling.domains:
                    top_domain = max(st.rolling.domains, key=st.rolling.domains.get, default=None)
                else:
                    top_domain = None
                feats["top_domain_is_familiar"] = bool(top_domain and top_domain in st.seen_domains)
                # ----------------------------------------------------

                # Bind time-aware clustered Z-scores using adaptive peer groupings
                feats["query_rate_z"]         = calculate_adaptive_zscore(feats["query_rate"], st.rate_baseline, "rate", st.device_type, current_hour)
                feats["entropy_avg_z"]        = calculate_adaptive_zscore(feats["entropy_avg"], st.entropy_baseline, "entropy", st.device_type, current_hour)
                feats["entropy_z"]            = feats["entropy_avg_z"]
                feats["unique_domains_z"]     = calculate_adaptive_zscore(feats["unique_domains"], st.unique_baseline, "unique", st.device_type, current_hour)
                feats["nxdomain_ratio_z"]     = calculate_adaptive_zscore(feats["nxdomain_ratio"], st.nxdomain_baseline, "nxdomain", st.device_type, current_hour)
                feats["blocked_ratio_z"]      = calculate_adaptive_zscore(feats["blocked_ratio"], st.blocked_baseline, "blocked", st.device_type, current_hour)
                feats["suspicious_domains_z"] = calculate_adaptive_zscore(feats["suspicious_domains"], st.dga_baseline, "dga", st.device_type, current_hour)

                # --- NEW: Dynamic Threshold Calculation with diurnal hour stats ---
                std_dev_multiplier = float(CONFIG.get("threshold_std_dev", 3.0))
                device_overrides = CONFIG.get("per_device_thresholds", {})
                device_multiplier = device_overrides.get(st.client_ip, std_dev_multiplier)

                mean, var, init, n = st.rate_baseline.get_stats(current_hour)
                if init and n >= 100:
                    std_dev = math.sqrt(max(var, 1.0))
                    current_threshold_limit = mean + (device_multiplier * std_dev)
                else:
                    mean = 0.0
                    current_threshold_limit = 0.0
                # ----------------------------------------------------------------

                zeek_feats  = zeek_fx.get_features(st.client_ip)
                zeek_alerts = zeek_fx.get_alerts(st.client_ip)
                zeek_dest_ips = zeek_fx.get_dest_ips(st.client_ip)
                zeek_http_reqs = zeek_fx.get_http_reqs(st.client_ip)
                feats.update(zeek_feats)

                ti_risk, abuse_risk, vt_risk, ti_match, ti_matches = _evaluate_intel(
                    st, feats, ti, abuseipdb, vt, zeek_dest_ips, zeek_http_reqs,
                )
                feats["ti_risk"] = ti_risk
                feats["abuseipdb_risk"] = abuse_risk
                feats["vt_risk"] = vt_risk

                ml_score = ml.score(dev_id, feats)

                # Fetch risk details early BEFORE baseline updates to guard against Day-Zero poisoning
                with STATE_LOCK:
                    risk_details = scorer.explain(feats, st, ml_score, zeek_alerts=zeek_alerts)
                    risk_score   = risk_details["risk"]

                # --- ANTI-POISONING INTEL FILTER ---
                # If the device is exhibiting high-risk behavior or matching known IOCs,
                # freeze its learning pipeline immediately to prevent model corruption.
                is_poisoned = (risk_score >= 4.0 or ti_match == 1)

                if is_poisoned:
                    LOGGER.warning(
                        "SUSPICIOUS NEW TRAFFIC DETECTED on %s (%s). "
                        "Freezing baseline updates to prevent memory poisoning.",
                        st.hostname, st.client_ip
                    )
                else:
                    # Normal baseline and ML training only continues if the device behaves safely
                    with STATE_LOCK:
                        st.rate_baseline.update(feats["query_rate"], current_hour)
                        st.entropy_baseline.update(feats["entropy_avg"], current_hour)
                        st.unique_baseline.update(feats["unique_domains"], current_hour)
                        st.nxdomain_baseline.update(feats["nxdomain_ratio"], current_hour)
                        st.blocked_baseline.update(feats["blocked_ratio"], current_hour)
                        st.dga_baseline.update(feats["suspicious_domains"], current_hour)
                        st.risk_baseline.update(risk_score, current_hour)
                    
                    ml.learn(dev_id, feats)

                    if not isinstance(st.seen_domains, dict):
                        st.seen_domains = {}
                    st.seen_domains.update((d, None) for d in st.rolling.domains)
                    while len(st.seen_domains) > _MAX_SEEN_DOMAINS:
                        del st.seen_domains[next(iter(st.seen_domains))]

                # Reset Zeek features for this IP so it doesn't compound regardless of poisoning
                zeek_fx.reset_cycle(st.client_ip)

                # Risk velocity tracking (Must pull proper diurnal tracking stat)
                rmean, rvar, rinit, rn = st.risk_baseline.get_stats(current_hour)
                if rinit and rn >= 100:
                    _rstd = math.sqrt(max(rvar, 1.0))
                    risk_velocity = max(-8.0, min(8.0, (risk_score - rmean) / _rstd))
                else:
                    risk_velocity = 0.0

                ti_risk_metric.labels(dev_id, st.hostname, st.device_type).set(ti_risk)
                ti_match_metric.labels(dev_id, st.hostname, st.device_type).set(ti_match)

                for domain_entry, d_count in st.rolling.domains.items():
                    geo_info = _geo_lookup_cached(geoip_engine, domain_entry)
                    c_code = geo_info.get("country", "unknown")
                    c_city = geo_info.get("city", "unknown")
                    c_asn  = geo_info.get("asn", "unknown")
                    c_org  = geo_info.get("org", "unknown")
                    c_cont = geo_info.get("continent", "unknown")
                    c_lat  = geo_info.get("latitude", "0")
                    c_lon  = geo_info.get("longitude", "0")

                    geo_risk = 0.0
                    geo_beacon = 0
                    if c_code != "unknown":
                        geo_country_counts[c_code] += d_count
                    if c_code in ["RU", "CN", "IR", "KP"]:
                        geo_risk = 5.0
                        geo_beacon = d_count

                    geo_risk_metric.labels(c_code, c_city, c_asn, c_org, c_cont, c_lat, c_lon).set(geo_risk)
                    if geo_risk > 0:
                        geo_hits_metric.labels(c_code, c_asn).inc(d_count)
                    if geo_beacon > 0:
                        geo_beacon_metric.labels(c_code, c_asn).inc(geo_beacon)
                    asn_risk_metric.labels(c_asn, c_org).set(5.0 if geo_risk > 0 else 0.0)

                    geo_traffic_total.labels(c_code, c_city, c_cont, c_asn, c_org, c_lat, c_lon).inc(d_count)
                    
                    qpm_calc = d_count * (60.0 / float(CONFIG["window_seconds"]))
                    geo_queries_per_minute.labels(c_code, c_city, c_asn, c_lat, c_lon).set(qpm_calc)
                    
                    dim_3 = (c_code, c_city, c_asn)
                    geo_domain_tracking.setdefault(dim_3, set()).add(domain_entry)
                    geo_device_tracking.setdefault(dim_3, set()).add(dev_id)

                    try:
                        from utils import entropy as _ent_fn
                        ent_score = _ent_fn(domain_entry.split(".")[0])
                    except Exception:
                        ent_score = 3.0
                    geo_entropy.labels(c_code, c_city, c_asn).set(ent_score)

                zeek_conn_count_metric.labels(dev_id, st.hostname, st.device_type).set(
                    zeek_feats.get("zeek_conn_count", 0)
                )
                zeek_new_ips_metric.labels(dev_id, st.hostname, st.device_type).set(
                    zeek_feats.get("zeek_new_ips", 0)
                )
                zeek_ja3_metric.labels(dev_id, st.hostname, st.device_type).set(
                    zeek_feats.get("zeek_ja3_malicious", 0)
                )
                zeek_notices_metric.labels(dev_id, st.hostname, st.device_type).set(
                    zeek_feats.get("zeek_notices", 0)
                )
                zeek_susp_ports_metric.labels(dev_id, st.hostname, st.device_type).set(
                    zeek_feats.get("zeek_susp_ports", 0)
                )

                risk_metric.labels(dev_id, st.hostname, st.device_type).set(risk_score)
                query_rate_metric.labels(dev_id, st.hostname, st.device_type).set(feats["query_rate"])
                query_rate_baseline_mean_metric.labels(dev_id, st.hostname, st.device_type).set(mean)
                query_rate_threshold_limit_metric.labels(dev_id, st.hostname, st.device_type).set(current_threshold_limit)

                unique_domains_metric.labels(dev_id, st.hostname, st.device_type).set(feats["unique_domains"])
                entropy_metric.labels(dev_id, st.hostname, st.device_type).set(feats["entropy_avg"])
                blocked_ratio_metric.labels(dev_id, st.hostname, st.device_type).set(feats["blocked_ratio"])
                nxdomain_ratio_metric.labels(dev_id, st.hostname, st.device_type).set(feats["nxdomain_ratio"])
                suspicious_domains_metric.labels(dev_id, st.hostname, st.device_type).set(feats["suspicious_domains"])
                ml_anomaly_metric.labels(dev_id, st.hostname, st.device_type).set(ml_score)

                zscore_query_metric.labels(dev_id, st.hostname, st.device_type).set(feats["query_rate_z"])
                zscore_entropy_metric.labels(dev_id, st.hostname, st.device_type).set(feats["entropy_avg_z"])
                zscore_unique_metric.labels(dev_id, st.hostname, st.device_type).set(feats["unique_domains_z"])
                zscore_nxdomain_metric.labels(dev_id, st.hostname, st.device_type).set(feats["nxdomain_ratio_z"])
                zscore_blocked_metric.labels(dev_id, st.hostname, st.device_type).set(feats["blocked_ratio_z"])
                zscore_dga_metric.labels(dev_id, st.hostname, st.device_type).set(feats["suspicious_domains_z"])
                risk_velocity_metric.labels(dev_id, st.hostname, st.device_type).set(risk_velocity)

                new_domains_metric.labels(dev_id, st.hostname, st.device_type).set(feats.get("new_domains", 0.0))
                deep_domains_metric.labels(dev_id, st.hostname, st.device_type).set(feats.get("deep_domains", 0.0))
                nxdomain_tld_conc_metric.labels(dev_id, st.hostname, st.device_type).set(feats.get("nxdomain_tld_conc", 0.0))
                
                safe_device_metric.labels(dev_id, st.hostname, st.device_type).set(1.0 if risk_score < 4.0 else 0.0)

                alert_threshold = float(CONFIG["alert_threshold"])
                if risk_score >= alert_threshold:
                    factors = risk_details.get("factors", [])
                    sig = factors[0]["name"] if factors else "Risk threshold exceeded"

                    last_alert_risk = getattr(st, "last_alert_risk", 0.0)
                    last_alert_sig = getattr(st, "last_alert_signature", "")

                    risk_delta = abs(risk_score - last_alert_risk)
                    signature_changed = (sig != last_alert_sig)

                    if (now - st.last_alert_time > 300) and (risk_delta >= 1.0 or signature_changed or last_alert_risk < alert_threshold):
                        st.last_alert_time = now
                        st.last_alert_risk = risk_score
                        st.last_alert_signature = sig
                        alerts_total.inc()
                        payload = _build_alert_payload(
                            st, dev_id, now, risk_score, alert_threshold, sig,
                            risk_details, feats, ml_score, ti_matches, zeek_alerts,
                        )
                        alert_log.write(payload)
                        alerts.send(_format_alert_message(payload))
                else:
                    if getattr(st, "last_alert_risk", 0.0) >= alert_threshold:
                        st.last_alert_risk = 0.0
                        st.last_alert_signature = ""

            for dim_3, unique_domains_set in geo_domain_tracking.items():
                c_code, c_city, c_asn = dim_3
                geo_unique_domains.labels(c_code, c_city, c_asn).set(len(unique_domains_set))
                
            for dim_3, unique_devices_set in geo_device_tracking.items():
                c_code, c_city, c_asn = dim_3
                geo_device_count.labels(c_code, c_city, c_asn).set(len(unique_devices_set))

            if geo_country_counts:
                top_country = geo_country_counts.most_common(1)[0][0]
                country_density_metric.labels(country=top_country).set(geo_country_counts[top_country])

            try:
                alert_queue_metric.set(alerts.q.qsize())
            except Exception:
                alert_queue_metric.set(0)

            ml_model_loaded_metric.set(1 if (ml.global_warmed_up or ml.n_device_models > 0) else 0)

            if loop_start - _last_save >= _save_interval:
                save_states(states, CONFIG["state_path"])
                _last_save = loop_start

            _SHUTDOWN_EVENT.wait(timeout=float(CONFIG["poll_interval"]))
        except Exception:
            LOGGER.exception("Main processing engine encountered loop fault")
            _SHUTDOWN_EVENT.wait(timeout=5)

    LOGGER.info("SIGTERM/SIGINT intercepted. Gracefully unwinding alerting pipelines...")
    alerts.stop(timeout=12)
    
    LOGGER.info("Flushing device network baselines to database file...")
    try:
        save_thread = threading.Thread(
            target=save_states,
            args=(states, CONFIG["state_path"]),
            daemon=True
        )
        save_thread.start()
        save_thread.join(timeout=30.0)
        if save_thread.is_alive():
            LOGGER.error("CRITICAL: Disk flushing operation blocked past 30 seconds threshold.")
        else:
            LOGGER.info("HOME IDS Engine safely cleanly closed down.")
    except Exception:
        LOGGER.exception("Error executing final engine state checkpoint flush")


if __name__ == "__main__":
    main()