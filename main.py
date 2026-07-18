"""
main.py – Thread-Safe Home IDS Core Processing Loop with Complete Prometheus Metrics Export.

This is the central execution framework. It synchronizes multiple input streams (Pi-hole, Zeek),
extracts behavioral features, queries local Machine Learning matrices, tracks active external
Threat Intel, and dispatches dynamic IPS mitigation commands and alerts.

RECENT FIXES APPLIED:
1. Config Integration: Pulls all Telegram and API secrets natively via config.py.
2. Z-Score Top-of-the-Hour Fallback: Prevents 10-minute blindness during bucket transitions.
3. Baseline Variance Protection: Updates baselines only once per window to prevent variance collapse.
4. Zeek State Aggregation: Ties state resets to the rolling window to accurately capture slow scans.
5. Grafana Sync: Aligns internal metric exports to match existing Dashboard JSON expectations.
6. Alert Deduplication Lock: Tracks sustained attacks correctly by decoupling time elapsed from risk deltas.
7. Geo Telemetry Sync: Repointed Geographic maps to rely purely on DNS resolutions rather than raw Zeek connections.
8. Telegram Initialization Ping: Dispatches a startup connection test on boot.
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
import concurrent.futures
from collections import OrderedDict, Counter, defaultdict
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
    entropy as _ent_fn  
)

from ips import IPSMitigator

# Bulk import of entire Prometheus registry
from metrics import (
    risk_metric, query_rate_metric, unique_domains_metric, entropy_metric,
    blocked_ratio_metric, nxdomain_ratio_metric, suspicious_domains_metric,
    ml_anomaly_metric, zscore_query_metric, zscore_entropy_metric,
    zscore_unique_metric, new_domains_metric, deep_domains_metric,
    nxdomain_tld_conc_metric, zscore_nxdomain_metric, zscore_blocked_metric,
    zscore_dga_metric, risk_velocity_metric, zeek_conn_count_metric,
    zeek_new_ips_metric, zeek_ja3_metric, zeek_notices_metric,
    zeek_susp_ports_metric, ti_risk_metric, ti_match_metric,
    ti_ioc_hits_total, safe_device_metric, probation_status_metric, baseline_poisoned_metric,
    geo_risk_metric, geo_hits_metric,
    geo_beacon_metric, asn_risk_metric, country_density_metric,
    geo_traffic_total, geo_queries_per_minute, geo_unique_domains,
    geo_entropy, geo_device_count, collector_lag_metric, alert_queue_metric,
    ml_model_loaded_metric, events_processed_metric, alerts_total,
    query_rate_baseline_mean_metric, query_rate_threshold_limit_metric,
    ndr_doh_bypass_metric, ndr_lateral_moves_metric, 
    ndr_jitter_c2_metric, ndr_exfil_z_metric,
    abuseipdb_risk_metric, virustotal_risk_metric,   
    beaconing_volume_metric, jitter_cv_metric,
    zeek_status_metric, zeek_events_processed_metric,
    ips_status_metric, ips_pihole_blocks_metric, ips_isolations_metric, ips_errors_metric 
)

RUNNING         = True
_SHUTDOWN_EVENT = threading.Event()
LOGGER          = logging.getLogger("home_ids")
STATE_LOCK      = threading.Lock()

ML_WARMUP_SAMPLES = int(CONFIG.get("ml_warmup_samples", 5000))
MAX_STATES        = int(CONFIG.get("max_device_states", 5000))
KNOWN_BLOCKED     = frozenset({1, 4, 5, 6, 7, 8, 10})
KNOWN_NXDOMAIN    = frozenset({3, 12, 13})
PEER_CLUSTER_REGISTRY = {}

def calculate_adaptive_zscore(val: float, baseline, feature_name: str, dev_type: str, hour: int) -> float:
    """
    Evaluates how abnormal a metric is compared to historically established boundaries.
    Automatically categorizes data into behavioral clusters (Day, Night, Evening).
    """
    mean, var, initialized, n = baseline.get_stats(hour)
    
    if 6 <= hour < 22:
        time_idx = 0  
    elif 1 <= hour < 5:
        time_idx = 2  
    else:
        time_idx = 1  
    
    # 1. Primary Check: The current hour bucket has enough mature baseline data.
    if initialized and n >= 50:
        dev_cluster = PEER_CLUSTER_REGISTRY.setdefault(dev_type, {})
        feat_cluster = dev_cluster.setdefault(feature_name, {})
        feat_cluster[time_idx] = {"mean": mean, "var": var}
        std_dev = math.sqrt(max(var, 1e-4))
        return max(-10.0, min(10.0, (val - mean) / std_dev))
    
    # 2. First Fallback: If this device is new, borrow the established baseline parameters
    # from other devices of the exact same type (e.g. comparing a new iPhone to an old iPhone).
    peer_template = PEER_CLUSTER_REGISTRY.get(dev_type, {}).get(feature_name, {}).get(time_idx)
    if peer_template:
        p_mean = peer_template["mean"]
        p_std  = math.sqrt(max(peer_template["var"], 1e-4))
        return max(-10.0, min(10.0, (val - p_mean) / p_std))
        
    # 3. FIX - Second Fallback: Top-of-the-hour Z-Score Blindness Prevention
    # When the clock strikes the hour, n=0. This explicitly borrows the standard 
    # deviation from the previous hour until the current hour achieves n >= 50.
    prev_hour = 23 if hour == 0 else hour - 1
    p_mean, p_var, p_init, p_n = baseline.get_stats(prev_hour)
    if p_init and p_n >= 50:
        p_std = math.sqrt(max(p_var, 1e-4))
        return max(-10.0, min(10.0, (val - p_mean) / p_std))
        
    return 0.0

# Aggressive memory-capping mechanisms for DNS/Geo IP resolutions
_GEO_CACHE = OrderedDict()
_GEO_CACHE_MAX = 15000  
_GEO_CACHE_TTL = 3600   
_CACHE_LOCK = threading.Lock()
_DNS_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=20, thread_name_prefix="ids_dns")

def _bg_resolve(domain: str, geoip_engine: GeoIPEngine):
    """Asynchronously executes socket domain resolutions to prevent loop blocking."""
    try:
        ip = resolve_domain(domain)
        geo = _geo_from_ip(geoip_engine, ip)
    except Exception:
        ip = None
        geo = _unknown_geo()
    with _CACHE_LOCK:
        _GEO_CACHE[domain] = (ip, geo, time.time() + _GEO_CACHE_TTL)

def _geo_lookup_cached(geoip_engine: GeoIPEngine, domain: str) -> tuple:
    """Provides high-speed memory-safe domain-to-location mappings."""
    now = time.time()
    with _CACHE_LOCK:
        cached = _GEO_CACHE.get(domain)
        if cached is not None:
            _ip, geo, expiry = cached
            if now < expiry:
                _GEO_CACHE.move_to_end(domain)
                return _ip, geo
        
        # Insert temporary blank state while resolving in background
        _GEO_CACHE[domain] = (None, _unknown_geo(), now + 30)
        _GEO_CACHE.move_to_end(domain)
        if len(_GEO_CACHE) > _GEO_CACHE_MAX:
            _GEO_CACHE.popitem(last=False)
            
    _DNS_POOL.submit(_bg_resolve, domain, geoip_engine)
    return None, _unknown_geo()

def _geo_from_ip(geoip_engine: GeoIPEngine, ip) -> dict:
    if not ip: return _unknown_geo()
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
    return {"country": "unknown", "city": "unknown", "continent": "unknown", "latitude": "0", "longitude": "0", "asn": "unknown", "org": "unknown"}

def load_states(path: str, alpha: float) -> "OrderedDict":
    """Loads previous mathematical baseline states from physical disk on engine boot."""
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
        return OrderedDict()

def save_states(states: "OrderedDict", path: str) -> None:
    """Safely flushes structural machine learning models and tracking states to disk."""
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

def stable_device_id(raw_client: str) -> str:
    """Generates immutable hashes to track devices persistently across dynamic IP shifts."""
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
    """Expunges actively tracked devices if they are dynamically added to the allowlist."""
    for dev_id, st in list(states.items()):
        if _is_safe_device(st.client_ip, st.hostname, safe_ips, safe_host_patterns):
            _remove_device_metric_labels(dev_id, st.hostname, st.device_type)
            states.pop(dev_id, None)

# =============================================================================
# METRIC CLEANUP TRACKING
# Maps all device-level Gauges to ensure orphaned labels are wiped cleanly.
# =============================================================================
_DEVICE_GAUGES = (
    risk_metric, query_rate_metric, unique_domains_metric, entropy_metric,
    blocked_ratio_metric, nxdomain_ratio_metric, suspicious_domains_metric,
    ml_anomaly_metric, zscore_query_metric, zscore_entropy_metric,
    zscore_unique_metric, new_domains_metric, deep_domains_metric,
    nxdomain_tld_conc_metric, zscore_nxdomain_metric, zscore_blocked_metric,
    zscore_dga_metric, risk_velocity_metric, zeek_conn_count_metric,
    zeek_new_ips_metric, zeek_ja3_metric, zeek_notices_metric,
    zeek_susp_ports_metric, ti_risk_metric, ti_match_metric,
    safe_device_metric, probation_status_metric, baseline_poisoned_metric, query_rate_baseline_mean_metric,
    query_rate_threshold_limit_metric, ndr_doh_bypass_metric, ndr_lateral_moves_metric, 
    ndr_jitter_c2_metric, ndr_exfil_z_metric, abuseipdb_risk_metric, virustotal_risk_metric,   
    beaconing_volume_metric, jitter_cv_metric
)

def _remove_device_metric_labels(dev_id: str, hostname: str, device_type: str, keep_safe_flag: bool = False) -> None:
    if not dev_id or not hostname or not device_type: 
        return
    for metric in _DEVICE_GAUGES:
        if keep_safe_flag and metric is safe_device_metric: 
            continue
        try: 
            metric.remove(str(dev_id), str(hostname), str(device_type))
        except KeyError: 
            pass
        except Exception: 
            pass

def _apply_device_type(st, dev_id: str, overrides: dict) -> None:
    if st.client_ip in overrides: 
        st.device_type = overrides[st.client_ip]
        return
    if dev_id in overrides: 
        st.device_type = overrides[dev_id]
        return
    if st.device_type == "unknown": 
        st.device_type = infer_device_type(st.hostname)

_MAX_SEEN_DOMAINS = 5_000   

def _vt_should_enqueue(domain: str, feats: dict) -> bool:
    """Heuristic queue gatekeeper preventing API abuse for benign domains."""
    if suspicious_dga(domain): 
        return True
    if feats.get("nxdomain_ratio", 0.0) > 0.3: 
        return True
    if feats.get("new_domains", 0.0) > 0.05: 
        return True
    return False

def _evaluate_intel(
    st, feats: dict, ti: ThreatIntel, abuseipdb: AbuseIPDB | None, vt: VirusTotalClient | None,
    zeek_dest_ips: set, zeek_http_reqs: set, global_ti_cache: dict  
) -> tuple[float, float, float, int, list]:
    """Correlates real-time traffic against static OSINT feeds and active sandbox analysis."""
    ti_risk, abuse_risk, vt_risk, any_match = 0.0, 0.0, 0.0, 0
    matches = []
    checked_ips: set[str] = set()

    # Phase 1: Assess raw HTTP layer calls
    for req in zeek_http_reqs:
        url_ti = ti.lookup_url(req)
        if url_ti:
            score = url_ti.get("confidence", 0.95) * 4.0
            ti_risk = max(ti_risk, score)
            any_match = 1
            matches.append({
                "provider": url_ti.get("source", "threat_intel"), "ioc_type": "url", "url": req,
                "hostname": st.hostname or "unknown", "device_ip": st.client_ip or "unknown",
                "confidence": url_ti.get("confidence"), "tags": url_ti.get("tags", []), "risk": score,
            })
            ti_ioc_hits_total.labels(source="threat_intel", ioc_type="url").inc()

    # Phase 2: Assess raw IP destinations
    def _check_ip(ip: str, ip_ti: dict=None, ip_score: float=0.0) -> None:
        nonlocal ti_risk, abuse_risk, vt_risk, any_match
        if not ip or ip in checked_ips: return
        checked_ips.add(ip)

        if abuseipdb and abuseipdb.lookup(ip):
            abuse_risk = 4.0
            any_match = 1
            matches.append({
                "provider": "abuseipdb", "ioc_type": "ip", "ip": ip,
                "hostname": st.hostname or "unknown", "device_ip": st.client_ip or "unknown", "risk": 4.0,
            })
            ti_ioc_hits_total.labels(source="abuseipdb", ioc_type="ip").inc()
            if vt: vt.enqueue_ip(ip, priority=2)

        if not ip_ti:
            ip_ti = ti.lookup_ip(ip)
            ip_score = ti.ioc_risk_score(ip=ip) if ip_ti else 0.0

        if ip_ti:
            ti_risk = max(ti_risk, ip_score)
            any_match = 1
            matches.append({
                "provider": ip_ti.get("source", "threat_intel"), "ioc_type": "ip", "ip": ip,
                "hostname": st.hostname or "unknown", "device_ip": st.client_ip or "unknown",
                "confidence": ip_ti.get("confidence"), "tags": ip_ti.get("tags", []), "risk": ip_score,
            })
            ti_ioc_hits_total.labels(source="threat_intel", ioc_type="ip").inc()

        if vt:
            ip_vt_risk = vt.risk_contribution("ip", ip)
            vt_risk = max(vt_risk, ip_vt_risk)
            if vt.is_malicious("ip", ip):
                any_match = 1
                matches.append({
                    "provider": "virustotal", "ioc_type": "ip", "ip": ip,
                    "hostname": st.hostname or "unknown", "device_ip": st.client_ip or "unknown", "risk": ip_vt_risk,
                })
                ti_ioc_hits_total.labels(source="virustotal", ioc_type="ip").inc()

    # Phase 3: Assess DNS Routing lookups
    for domain_entry in st.rolling.domains.keys():
        entry = global_ti_cache.get(domain_entry)
        if not entry: continue
        
        domain_ti = entry["domain_ti"]
        if domain_ti:
            domain_score = entry["domain_score"]
            ti_risk = max(ti_risk, domain_score)
            any_match = 1
            matches.append({
                "provider": domain_ti.get("source", "threat_intel"), "ioc_type": "domain", "domain": domain_entry,
                "ip": entry["ip"], "hostname": st.hostname or "unknown", "device_ip": st.client_ip or "unknown",
                "confidence": domain_ti.get("confidence"), "tags": domain_ti.get("tags", []),
                "matched_parent": domain_ti.get("matched_parent", False), "risk": domain_score,
            })
            ti_ioc_hits_total.labels(source="threat_intel", ioc_type="domain").inc()
            if vt: vt.enqueue_domain(domain_entry, priority=2)
        elif vt and _vt_should_enqueue(domain_entry, feats):
            priority = 1 if suspicious_dga(domain_entry) else 5
            vt.enqueue_domain(domain_entry, priority=priority)

        if vt:
            domain_vt_risk = vt.risk_contribution("domain", domain_entry)
            vt_risk = max(vt_risk, domain_vt_risk)
            if vt.is_malicious("domain", domain_entry):
                any_match = 1
                matches.append({
                    "provider": "virustotal", "ioc_type": "domain", "domain": domain_entry,
                    "ip": entry["ip"], "hostname": st.hostname or "unknown", "device_ip": st.client_ip or "unknown",
                    "risk": domain_vt_risk,
                })
                ti_ioc_hits_total.labels(source="virustotal", ioc_type="domain").inc()

        _check_ip(entry["ip"], entry["ip_ti"], entry["ip_score"])

    for ip in zeek_dest_ips:
        _check_ip(ip)

    return ti_risk, abuse_risk, vt_risk, any_match, matches

def _format_alert_message(payload: dict) -> str:
    """Formats Telegram string blocks."""
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
    """Constructs the universal JSON document structure for Grafana Loki."""
    return {
        "timestamp": now,
        "device": {
            "id": dev_id,
            "ip": st.client_ip or "unknown",
            "hostname": st.hostname or "unknown",
            "type": st.device_type or "unknown",
            "mac": getattr(st, "mac_address", "unknown"),
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
    
    # Dynamically set log level from config.json
    log_level_str = CONFIG.get("log_level", "INFO").upper()
    numeric_level = getattr(logging, log_level_str, logging.INFO)
    logging.basicConfig(level=numeric_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Initialize Extracted IPS Mitigation Engine
    ips_mitigator = IPSMitigator(CONFIG)
    ips_status_metric.set(1.0 if ips_mitigator.enabled else 0.0)

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
        model_dir         = Path(CONFIG.get("model_path", "state/ids_model.pkl")).parent / "devices",
        global_model_path = Path(CONFIG.get("model_path", "state/ids_model.pkl")),
    )
    try:
        geoip_engine = GeoIPEngine(CONFIG.get("geoip_db"), asn_db_path=CONFIG.get("geoip_asn_db", ""))
    except Exception as exc:
        LOGGER.error(
            "GeoIP database could not be opened at %r (geoip_asn_db=%r): %s — "
            "geo/ASN panels will report 'unknown' until this is fixed. Check config.json paths.",
            CONFIG.get("geoip_db"), CONFIG.get("geoip_asn_db", ""), exc,
        )
        geoip_engine = GeoIPEngine.__new__(GeoIPEngine)
        geoip_engine.reader = None
        geoip_engine.asn_reader = None
    
    # Priority: Env variables (mapped via config) -> JSON file -> Fallback empty
    tg_token = CONFIG.get("telegram_token", "")
    tg_chat  = CONFIG.get("telegram_chat_id", "")
    _tg_enabled  = (CONFIG.get("telegram_enabled", False) or (bool(tg_token) and bool(tg_chat)))
    
    alerts = AlertManager(
        token   = tg_token if _tg_enabled else "",
        chat_id = tg_chat if _tg_enabled else "",
        enabled = _tg_enabled,
    )
    alert_log = AlertJSONWriter(
        path=CONFIG.get("alert_json_path", "alerts.json"),
        max_bytes=int(CONFIG.get("alert_json_max_bytes", 1073741824)),
    )
    
    # -------------------------------------------------------------------------
    # NEW FEATURE: Telegram Initialization Ping
    # Dispatches an immediate verification message to ensure networking is active
    # -------------------------------------------------------------------------
    if _tg_enabled:
        startup_msg = "🟢 [SYSTEM] Home IDS Engine Started. Telegram alerting is active and connected."
        alerts.send(startup_msg)
        LOGGER.info("Dispatched Telegram initialization test message.")
    
    _alpha = float(CONFIG.get("baseline_alpha", 0.05))
    states = load_states(CONFIG.get("state_path", "state/ids_state.json"), alpha=_alpha)

    ti = ThreatIntel(
        cache_dir        = str(Path(CONFIG.get("state_path", "state/ids_state.json")).parent / "ti_cache"),
        otx_api_key      = CONFIG.get("otx_api_key", ""),
        refresh_interval = int(CONFIG.get("ti_refresh_interval", 3600)),
    )
    ti.start_refresh_thread()

    _ti_cache = Path(CONFIG.get("state_path", "state/ids_state.json")).parent / "ti_cache"
    _ti_cache.mkdir(parents=True, exist_ok=True)
    _ti_refresh = int(CONFIG.get("ti_refresh_interval", 3600))

    abuseipdb = None
    if CONFIG.get("abuseipdb_api_key", ""):
        abuseipdb = AbuseIPDB(api_key=CONFIG.get("abuseipdb_api_key"), cache_dir=_ti_cache, refresh_interval=_ti_refresh)
        abuseipdb.start_refresh_thread()
        LOGGER.info("AbuseIPDB integration enabled")

    vt = None
    if CONFIG.get("virustotal_api_key", ""):
        vt = VirusTotalClient(api_key=CONFIG.get("virustotal_api_key"), cache_dir=_ti_cache)
        LOGGER.info("VirusTotal integration enabled (async queue)")

    zeek = ZeekCollector(
        log_dir       = CONFIG.get("zeek_log_dir", "/opt/zeek/logs/current"),
        poll_interval = float(CONFIG.get("poll_interval", 2.0)),
    )
    
    home_subnets = CONFIG.get("home_subnets", [CONFIG.get("home_subnet", "192.168.178.0/24")])
    zeek_fx = ZeekFeatureExtractor(home_subnets=home_subnets, ti_engine=ti)
    
    start_http_server(int(CONFIG.get("metrics_port", 9105)))

    def _on_config_change(changed: dict) -> None:
        """Dynamic Config reload bindings"""
        if "safe_ips" in changed or "safe_host_patterns" in changed:
            _safe_ips.clear()
            _safe_ips.update(CONFIG.get("safe_ips", ["127.0.0.1"]))
            _safe_host_patterns.clear()
            _safe_host_patterns.update(_safe_pattern_set(CONFIG.get("safe_host_patterns", [])))
            collector.excluded_ips = set(_safe_ips)
            collector.excluded_patterns = set(_safe_host_patterns)
            with STATE_LOCK:
                _drop_safe_states(states, _safe_ips, _safe_host_patterns)

    CONFIG.set_notify(_on_config_change)
    CONFIG.start_watcher(interval=5.0)

    _save_interval = 300
    _last_save = time.time()
    _last_zeek_reset = time.time()
    total_events_processed = 0
    _type_overrides = CONFIG.get("device_type_overrides", {})

    while RUNNING:
        loop_start = time.time()
        try:
            # 1. Acquire network data batches
            rows = collector.poll()
            zeek_events = list(zeek.poll())
            
            zeek_status_metric.set(1.0 if zeek.available else 0.0)
            zeek_events_processed_metric.inc(len(zeek_events))

            # 2. Ingest low-level packet data
            for zeek_event in zeek_events:
                zeek_fx.ingest(zeek_event)

            # Define temporary containers for DNS-based Geolocation sync
            current_cycle_dns_ips = Counter()
            current_cycle_dns_devices = defaultdict(set)

            now        = loop_start
            batch_size = len(rows)
            total_events_processed += batch_size
            events_processed_metric.inc(batch_size)

            # 3. Synchronize Routing State
            if rows:
                collector_lag_metric.set(max(0.0, now - rows[-1]["timestamp"]))

                with STATE_LOCK:
                    for row in rows:
                        client_ip = str(row["client_ip"])
                        hostname  = str(row["hostname"])
                        
                        mac_addr = zeek_fx.get_mac(client_ip)
                        dev_id   = stable_device_id(mac_addr) if mac_addr else stable_device_id(client_ip)

                        if dev_id not in states:
                            states[dev_id] = DeviceState(
                                device_id = dev_id, client_ip = client_ip, hostname = hostname, alpha = _alpha
                            )
                            trim_states(states)

                        st = states[dev_id]
                        st.mac_address = mac_addr

                        old_hostname    = st.hostname
                        old_device_type = st.device_type
                        st.client_ip = client_ip
                        st.hostname  = hostname
                        _apply_device_type(st, dev_id, _type_overrides)
                        
                        # Scrub abandoned metrics when metadata shifts
                        if old_hostname != st.hostname or old_device_type != st.device_type:
                            _remove_device_metric_labels(dev_id, old_hostname, old_device_type)

                        domain = normalize_domain(str(row["domain"]))
                        status = int(row["status"])

                        st.rolling.events.append((now, domain, status))
                        st.rolling.domains[domain] += 1
                        st.rolling.domain_timestamps[domain].append(now)

                        if status in KNOWN_BLOCKED: st.rolling.blocked += 1
                        if status in KNOWN_NXDOMAIN: st.rolling.nxdomain += 1

                        # FIX: Source Geo metrics directly from DNS lookups instead of Zeek connections.
                        # This aligns the backend Prometheus metrics exactly to the "DNS Query Rate" Grafana panels.
                        resolved_ip = zeek_fx.get_wire_ip(domain)
                        if not resolved_ip:
                            resolved_ip, _ = _geo_lookup_cached(geoip_engine, domain)
                        
                        if resolved_ip and resolved_ip != "unknown":
                            current_cycle_dns_ips[resolved_ip] += 1
                            current_cycle_dns_devices[resolved_ip].add(dev_id)
                            
                            geo_info = geoip_engine.geo_labels(resolved_ip)
                            c_code = geo_info.get("country", "unknown")
                            c_asn = geo_info.get("asn", "unknown")
                            
                            geo_traffic_total.labels(
                                str(c_code), str(geo_info.get("city", "unknown")), str(geo_info.get("continent", "unknown")),
                                str(c_asn), str(geo_info.get("org", "unknown")), 
                                str(geo_info.get("latitude", "0")), str(geo_info.get("longitude", "0"))
                            ).inc(1)
                            
                            if c_code in ["RU", "CN", "IR", "KP"]:
                                geo_hits_metric.labels(str(c_code), str(c_asn)).inc(1)
            else:
                collector_lag_metric.set(0.0)

            with STATE_LOCK:
                active_devices = list(states.items())

            global_domain_counts = Counter()
            global_device_tracking = defaultdict(set)
            
            for dev_id, st in active_devices:
                for d, c in st.rolling.domains.items():
                    global_domain_counts[d] += c
                    global_device_tracking[d].add(dev_id)

            global_ti_cache = {}
            for domain in global_domain_counts.keys():
                resolved_ip = zeek_fx.get_wire_ip(domain)
                if not resolved_ip:
                    resolved_ip, _ = _geo_lookup_cached(geoip_engine, domain)
                resolved_ip = resolved_ip or "unknown"
                
                global_ti_cache[domain] = {
                    "ip": resolved_ip,
                    "domain_ti": ti.lookup_domain(domain),
                    "ip_ti": ti.lookup_ip(resolved_ip),
                    "domain_score": ti.ioc_risk_score(domain=domain) if ti.lookup_domain(domain) else 0.0,
                    "ip_score": ti.ioc_risk_score(ip=resolved_ip) if ti.lookup_ip(resolved_ip) else 0.0,
                }

            unique_geos = {}
            for ip, ip_count in current_cycle_dns_ips.items():
                geo_info = geoip_engine.geo_labels(ip)
                dim_qpm = (
                    str(geo_info.get("country", "unknown")), str(geo_info.get("city", "unknown")),
                    str(geo_info.get("asn", "unknown")), str(geo_info.get("org", "unknown")),
                    str(geo_info.get("continent", "unknown")), str(geo_info.get("latitude", "0")),
                    str(geo_info.get("longitude", "0"))
                )
                if dim_qpm not in unique_geos:
                    unique_geos[dim_qpm] = {"count": 0, "ips": set(), "devices": set()}
                unique_geos[dim_qpm]["count"] += ip_count
                unique_geos[dim_qpm]["ips"].add(ip)
                unique_geos[dim_qpm]["devices"].update(current_cycle_dns_devices[ip])

            # 4. Feature Extraction & AI Scoring
            for dev_id, st in active_devices:
                if _is_safe_device(st.client_ip, st.hostname, _safe_ips, _safe_host_patterns):
                    safe_device_metric.labels(str(dev_id), str(st.hostname), str(st.device_type)).set(1.0)
                    _remove_device_metric_labels(dev_id, st.hostname, st.device_type, keep_safe_flag=True)
                    with STATE_LOCK:
                        states.pop(dev_id, None)
                    continue

                current_hour = time.localtime(now).tm_hour
                with STATE_LOCK:
                    feats = extractor.compute(st, now, int(CONFIG.get("window_seconds", 300)))
                if feats["total"] == 0: continue

                feats["current_hour"] = current_hour
                top_domain = max(st.rolling.domains, key=st.rolling.domains.get, default=None) if st.rolling.domains else None
                feats["top_domain_is_familiar"] = bool(top_domain and top_domain in st.seen_domains)

                zeek_feats  = zeek_fx.get_features(st.client_ip)
                zeek_alerts = zeek_fx.get_alerts(st.client_ip)
                feats.update(zeek_feats)

                feats["query_rate_z"]         = calculate_adaptive_zscore(feats["query_rate"], st.rate_baseline, "rate", st.device_type, current_hour)
                feats["entropy_avg_z"]        = calculate_adaptive_zscore(feats["entropy_avg"], st.entropy_baseline, "entropy", st.device_type, current_hour)
                feats["entropy_z"]            = feats["entropy_avg_z"]
                feats["unique_domains_z"]     = calculate_adaptive_zscore(feats["unique_domains"], st.unique_baseline, "unique", st.device_type, current_hour)
                feats["nxdomain_ratio_z"]     = calculate_adaptive_zscore(feats["nxdomain_ratio"], st.nxdomain_baseline, "nxdomain", st.device_type, current_hour)
                feats["blocked_ratio_z"]      = calculate_adaptive_zscore(feats["blocked_ratio"], st.blocked_baseline, "blocked", st.device_type, current_hour)
                feats["suspicious_domains_z"] = calculate_adaptive_zscore(feats["suspicious_domains"], st.dga_baseline, "dga", st.device_type, current_hour)
                feats["outbound_bytes_z"]     = calculate_adaptive_zscore(feats.get("zeek_outbound_bytes", 0.0), st.outbound_bytes_baseline, "outbound_bytes", st.device_type, current_hour)

                feats["nxdomain_z"] = feats["nxdomain_ratio_z"]
                feats["blocked_z"]  = feats["blocked_ratio_z"]
                feats["dga_z"]      = feats["suspicious_domains_z"]

                std_dev_multiplier = float(CONFIG.get("threshold_std_dev", 3.0))
                device_overrides = CONFIG.get("per_device_thresholds", {})
                device_multiplier = device_overrides.get(st.client_ip, std_dev_multiplier)

                mean, var, init, n = st.rate_baseline.get_stats(current_hour)
                current_threshold_limit = mean + (device_multiplier * math.sqrt(max(var, 1e-4))) if (init and n >= 50) else 0.0

                ti_risk, abuse_risk, vt_risk, ti_match, ti_matches = _evaluate_intel(
                    st, feats, ti, abuseipdb, vt, zeek_fx.get_dest_ips(st.client_ip), zeek_fx.get_http_reqs(st.client_ip), global_ti_cache
                )
                feats["ti_risk"] = ti_risk
                feats["abuseipdb_risk"] = abuse_risk
                feats["vt_risk"] = vt_risk

                ml_score = ml.score(dev_id, feats)
                with STATE_LOCK:
                    risk_details = scorer.explain(feats, st, ml_score, zeek_alerts=zeek_alerts)
                    risk_score   = risk_details["risk"]

                # Day-Zero Freezing Logic
                is_poisoned = (
                    risk_score >= 7.0 or ti_match == 1 or feats.get("zeek_ja3_malicious", 0) > 0 or
                    feats.get("zeek_doh_bypass", 0) > 0 or feats.get("zeek_lateral_moves", 0) > 0
                )

                baseline_poisoned_metric.labels(str(dev_id), str(st.hostname), str(st.device_type)).set(1.0 if is_poisoned else 0.0)

                if is_poisoned:
                    LOGGER.warning("SEVERE ANOMALY/THREAT DETECTED on %s (%s). Freezing baseline.", st.hostname, st.client_ip)
                else:
                    with STATE_LOCK:
                        # FIX: Only update structural baselines once per rolling window
                        # Prevents standard deviation variance collapse and restores the true 24-hour probation curve.
                        window_sec = int(CONFIG.get("window_seconds", 300))
                        if now - getattr(st, "last_baseline_update", 0) >= window_sec:
                            st.rate_baseline.update(feats["query_rate"], current_hour)
                            st.entropy_baseline.update(feats["entropy_avg"], current_hour)
                            st.unique_baseline.update(feats["unique_domains"], current_hour)
                            st.nxdomain_baseline.update(feats["nxdomain_ratio"], current_hour)
                            st.blocked_baseline.update(feats["blocked_ratio"], current_hour)
                            st.dga_baseline.update(feats["suspicious_domains"], current_hour)
                            st.risk_baseline.update(risk_score, current_hour)
                            st.outbound_bytes_baseline.update(feats.get("zeek_outbound_bytes", 0.0), current_hour)
                            st.last_baseline_update = now
                            
                    ml.learn(dev_id, feats)

                    if not isinstance(st.seen_domains, dict): st.seen_domains = {}
                    st.seen_domains.update((d, None) for d in st.rolling.domains)
                    while len(st.seen_domains) > _MAX_SEEN_DOMAINS: del st.seen_domains[next(iter(st.seen_domains))]

                rmean, rvar, rinit, rn = st.risk_baseline.get_stats(current_hour)
                risk_velocity = max(-10.0, min(10.0, (risk_score - rmean) / math.sqrt(max(rvar, 1e-4)))) if (rinit and rn >= 50) else 0.0

                # 5. Prometheus Export Mappings
                str_dev_id = str(dev_id)
                str_host = str(st.hostname)
                str_type = str(st.device_type)

                # SYNC FIX: Explicit mapping to Grafana Dashboard variable queries
                ti_risk_metric.labels(str_dev_id, str_host, str_type).set(ti_risk)
                ti_match_metric.labels(str_dev_id, str_host, str_type).set(ti_match)
                
                # Match to Grafana Dashboard expectation keys implicitly here without breaking `metrics.py` definitions
                ndr_doh_bypass_metric.labels(str_dev_id, str_host, str_type).set(feats.get("zeek_doh_bypass", 0))
                ndr_lateral_moves_metric.labels(str_dev_id, str_host, str_type).set(feats.get("zeek_lateral_moves", 0))
                ndr_jitter_c2_metric.labels(str_dev_id, str_host, str_type).set(feats.get("beaconing_c2_count", 0))
                ndr_exfil_z_metric.labels(str_dev_id, str_host, str_type).set(feats.get("outbound_bytes_z", 0.0))

                abuseipdb_risk_metric.labels(str_dev_id, str_host, str_type).set(abuse_risk)
                virustotal_risk_metric.labels(str_dev_id, str_host, str_type).set(vt_risk)
                beaconing_volume_metric.labels(str_dev_id, str_host, str_type).set(feats.get("top_domain_ratio", 0.0))
                jitter_cv_metric.labels(str_dev_id, str_host, str_type).set(feats.get("min_jitter_cv", 0.0))

                c2_hits = feats.get("beaconing_c2_count", 0)
                if c2_hits and top_domain:
                    resolved_beacon_ip = zeek_fx.get_wire_ip(top_domain)
                    if not resolved_beacon_ip: _, beacon_geo = _geo_lookup_cached(geoip_engine, top_domain)
                    else: beacon_geo = geoip_engine.geo_labels(resolved_beacon_ip)
                    geo_beacon_metric.labels(str(beacon_geo.get("country", "unknown")), str(beacon_geo.get("asn", "unknown"))).inc(c2_hits)

                zeek_conn_count_metric.labels(str_dev_id, str_host, str_type).set(feats.get("zeek_conn_count", 0))
                zeek_new_ips_metric.labels(str_dev_id, str_host, str_type).set(feats.get("zeek_new_ips", 0))
                zeek_ja3_metric.labels(str_dev_id, str_host, str_type).set(feats.get("zeek_ja3_malicious", 0))
                zeek_notices_metric.labels(str_dev_id, str_host, str_type).set(feats.get("zeek_notices", 0))
                zeek_susp_ports_metric.labels(str_dev_id, str_host, str_type).set(feats.get("zeek_susp_ports", 0))
                
                risk_metric.labels(str_dev_id, str_host, str_type).set(risk_score)
                query_rate_metric.labels(str_dev_id, str_host, str_type).set(feats["query_rate"])
                query_rate_baseline_mean_metric.labels(str_dev_id, str_host, str_type).set(mean)
                query_rate_threshold_limit_metric.labels(str_dev_id, str_host, str_type).set(current_threshold_limit)
                unique_domains_metric.labels(str_dev_id, str_host, str_type).set(feats["unique_domains"])
                entropy_metric.labels(str_dev_id, str_host, str_type).set(feats["entropy_avg"])
                blocked_ratio_metric.labels(str_dev_id, str_host, str_type).set(feats["blocked_ratio"])
                nxdomain_ratio_metric.labels(str_dev_id, str_host, str_type).set(feats["nxdomain_ratio"])
                suspicious_domains_metric.labels(str_dev_id, str_host, str_type).set(feats["suspicious_domains"])
                ml_anomaly_metric.labels(str_dev_id, str_host, str_type).set(ml_score)
                zscore_query_metric.labels(str_dev_id, str_host, str_type).set(feats["query_rate_z"])
                zscore_entropy_metric.labels(str_dev_id, str_host, str_type).set(feats["entropy_avg_z"])
                zscore_unique_metric.labels(str_dev_id, str_host, str_type).set(feats["unique_domains_z"])
                zscore_nxdomain_metric.labels(str_dev_id, str_host, str_type).set(feats["nxdomain_ratio_z"])
                zscore_blocked_metric.labels(str_dev_id, str_host, str_type).set(feats["blocked_ratio_z"])
                zscore_dga_metric.labels(str_dev_id, str_host, str_type).set(feats["suspicious_domains_z"])
                risk_velocity_metric.labels(str_dev_id, str_host, str_type).set(risk_velocity)
                new_domains_metric.labels(str_dev_id, str_host, str_type).set(feats.get("new_domains", 0.0))
                deep_domains_metric.labels(str_dev_id, str_host, str_type).set(feats.get("deep_domains", 0.0))
                nxdomain_tld_conc_metric.labels(str_dev_id, str_host, str_type).set(feats.get("nxdomain_tld_conc", 0.0))
                
                safe_device_metric.labels(str_dev_id, str_host, str_type).set(0.0)
                
                rate_baseline_n = sum(getattr(st.rate_baseline, "n", [0, 0]))
                probation_status_metric.labels(str_dev_id, str_host, str_type).set(1.0 if rate_baseline_n < 288 else 0.0)

                # =====================================================================
                # 6. ALERT GENERATION & DEDUPLICATION LOGIC
                # =====================================================================
                alert_threshold = float(CONFIG.get("alert_threshold", 6.0))
                if risk_score >= alert_threshold:
                    factors = risk_details.get("factors", [])
                    sig = factors[0]["name"] if factors else "Risk threshold exceeded"
                    risk_delta = abs(risk_score - getattr(st, "last_alert_risk", 0.0))
                    time_elapsed = now - getattr(st, "last_alert_time", 0.0)
                    
                    # FIX: Sustained Threat & Escalation Tracking
                    # 1. Sustained: Re-alert every 5 minutes if risk remains above threshold.
                    # 2. Escalation: Alert if risk jumps by 1.0+ or signature changes (debounced by 60s to prevent spam).
                    if time_elapsed > 300 or (time_elapsed > 60 and (risk_delta >= 1.0 or sig != getattr(st, "last_alert_signature", ""))):
                        LOGGER.info("Alert generated for %s: %s (Risk: %.2f)", st.hostname, sig, risk_score)
                        st.last_alert_time = now
                        st.last_alert_risk = risk_score
                        st.last_alert_signature = sig
                        alerts_total.inc()
                        payload = _build_alert_payload(st, dev_id, now, risk_score, alert_threshold, sig, risk_details, feats, ml_score, ti_matches, zeek_alerts)
                        alert_log.write(payload)
                        alerts.send(_format_alert_message(payload))
                        
                    dga_burst = feats.get("new_domains", 0) > 15 and feats.get("nxdomain_ratio", 0) > 0.4
                    ips_mitigator.mitigate(st, top_domain, risk_score, c2_hits, dga_burst)
                else:
                    if getattr(st, "last_alert_risk", 0.0) >= alert_threshold:
                        st.last_alert_risk = 0.0
                        st.last_alert_signature = ""

            # FIX: Only reset Zeek features once every rolling window (300s) to allow proper aggregation
            if now - _last_zeek_reset >= int(CONFIG.get("window_seconds", 300)):
                zeek_fx.reset_all()
                _last_zeek_reset = now

            geo_country_counts = Counter()
            for dim, data in unique_geos.items():
                c_code, c_city, c_asn, c_org, c_cont, c_lat, c_lon = dim
                geo_risk = 5.0 if c_code in ["RU", "CN", "IR", "KP"] else 0.0
                geo_risk_metric.labels(c_code, c_city, c_asn, c_org, c_cont, c_lat, c_lon).set(geo_risk)
                asn_risk_metric.labels(c_asn, c_org).set(5.0 if geo_risk > 0 else 0.0)
                geo_queries_per_minute.labels(c_code, c_city, c_asn, c_lat, c_lon).set(data["count"] * (60.0 / float(CONFIG.get("poll_interval", 2.0))))
                
                dim_3 = (c_code, c_city, c_asn)
                geo_unique_domains.labels(*dim_3).set(len(data["ips"]))
                geo_device_count.labels(*dim_3).set(len(data["devices"]))
                
                ent_sum = sum(_ent_fn(ip_addr) for ip_addr in data["ips"])
                geo_entropy.labels(*dim_3).set(ent_sum / max(len(data["ips"]), 1))
                if c_code != "unknown": 
                    geo_country_counts[c_code] += data["count"]

            if geo_country_counts:
                top_country = geo_country_counts.most_common(1)[0][0]
                country_density_metric.labels(country=top_country).set(geo_country_counts[top_country])

            alert_queue_metric.set(alerts.q.qsize() if hasattr(alerts, "q") else 0)
            ml_model_loaded_metric.set(1 if (ml.global_warmed_up or ml.n_device_models > 0) else 0)

            if loop_start - _last_save >= _save_interval:
                save_states(states, CONFIG.get("state_path", "state/ids_state.json"))
                _last_save = loop_start

            _SHUTDOWN_EVENT.wait(timeout=float(CONFIG.get("poll_interval", 2.0)))
        except Exception:
            LOGGER.exception("Main processing engine encountered loop fault")
            _SHUTDOWN_EVENT.wait(timeout=5)

    alerts.stop(timeout=12)
    try: 
        save_states(states, CONFIG.get("state_path", "state/ids_state.json"))
    except Exception: 
        LOGGER.exception("Error executing final engine state checkpoint flush")

if __name__ == "__main__":
    main()