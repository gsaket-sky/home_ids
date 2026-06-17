"""
main.py – Thread-Safe Home IDS Core Processing Loop with Complete Prometheus Metrics Export.

Hardened Architectural Syncs:
  • Aligns ALL geographic traffic metrics (geo_traffic_total, geo_queries_per_minute,
    geo_unique_domains, geo_entropy, geo_device_count) to their exact label configurations.
  • Corrects geo_hits_metric syntax from .set() to .inc().
  • Retains structural engine patches for threat intel and zscore behaviors.
"""

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
from alerts import AlertManager
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


def calculate_zscore(val: float, baseline) -> float:
    """Safely calculates the Z-Score of a feature using its running baseline."""
    if not baseline.initialized or baseline.n < 30:
        return 0.0
    std_dev = math.sqrt(max(baseline.var, 1e-6))
    return (val - baseline.mean) / std_dev


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


_MAX_SEEN_DOMAINS = 20_000


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
) -> tuple[float, float, float, int]:
    """
    Evaluate all IOC feeds for a device window.
    Returns (ti_risk, abuseipdb_risk, vt_risk, any_match_flag).
    """
    ti_risk = 0.0
    abuse_risk = 0.0
    vt_risk = 0.0
    any_match = 0
    checked_ips: set[str] = set()

    def _check_ip(ip: str) -> None:
        nonlocal ti_risk, abuse_risk, vt_risk, any_match
        if not ip or ip in checked_ips:
            return
        checked_ips.add(ip)

        if abuseipdb and abuseipdb.lookup(ip):
            abuse_risk = 4.0
            any_match = 1
            ti_ioc_hits_total.labels(source="abuseipdb", ioc_type="ip").inc()
            if vt:
                vt.enqueue_ip(ip, priority=2)

        ip_ti = ti.lookup_ip(ip)
        if ip_ti:
            ti_risk = max(ti_risk, ti.ioc_risk_score(ip=ip))
            any_match = 1
            ti_ioc_hits_total.labels(source="threat_intel", ioc_type="ip").inc()

        if vt:
            vt_risk = max(vt_risk, vt.risk_contribution("ip", ip))
            if vt.is_malicious("ip", ip):
                any_match = 1

    for domain_entry in st.rolling.domains.keys():
        ti_hit = safe_ti_check(ti, domain_entry)
        if ti_hit:
            ti_risk = max(ti_risk, ti.ioc_risk_score(domain=domain_entry))
            any_match = 1
            ti_ioc_hits_total.labels(source="threat_intel", ioc_type="domain").inc()
            if vt:
                vt.enqueue_domain(domain_entry, priority=2)
        elif vt and _vt_should_enqueue(domain_entry, feats):
            priority = 1 if suspicious_dga(domain_entry) else 5
            vt.enqueue_domain(domain_entry, priority=priority)

        if vt:
            vt_risk = max(vt_risk, vt.risk_contribution("domain", domain_entry))
            if vt.is_malicious("domain", domain_entry):
                any_match = 1

        _check_ip(_resolve_safe_timeout(domain_entry))

    for ip in zeek_dest_ips:
        _check_ip(ip)

    return ti_risk, abuse_risk, vt_risk, any_match


def main():
    global RUNNING

    setup_logging()
    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    _safe_ips = set(CONFIG.get("safe_ips", ["127.0.0.1"]))
    collector = PiHoleCollector(
        lookback_seconds = int(CONFIG.get("startup_lookback_seconds", 300)),
        excluded_ips     = _safe_ips,
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
    
    _alpha = float(CONFIG.get("baseline_alpha", 0.05))
    
    with STATE_LOCK:
        states = load_states(CONFIG["state_path"], alpha=_alpha)

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
        if "safe_ips" in changed:
            collector.excluded_ips = set(CONFIG.get("safe_ips", ["127.0.0.1"]))
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
            df = collector.poll()
            zeek_events = list(zeek.poll())
            for zeek_event in zeek_events:
                zeek_fx.ingest(zeek_event)

            now = loop_start
            batch_size = len(df)
            total_events_processed += batch_size
            events_processed_metric.inc(batch_size)

            if not df.empty:
                max_row_ts = df["timestamp"].max()
                collector_lag_metric.set(max(0.0, now - max_row_ts))
                
                with STATE_LOCK:
                    for _, row in df.iterrows():
                        client_ip = str(row["client_ip"])
                        dev_id    = stable_device_id(client_ip)
                        
                        if dev_id not in states:
                            states[dev_id] = DeviceState(
                                device_id = dev_id,
                                client_ip = client_ip,
                                hostname  = str(row["hostname"]),
                                alpha     = _alpha
                            )
                            trim_states(states)

                        st = states[dev_id]
                        st.client_ip = client_ip
                        st.hostname  = str(row["hostname"])
                        _apply_device_type(st, dev_id, _type_overrides)

                        raw_domain = str(row["domain"])
                        domain     = normalize_domain(raw_domain)
                        status     = int(row["status"])

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
            # Map tracking distinct active device IDs encountered per lookup dimension combo
            geo_device_tracking = {}
            # Map tracking distinct domains queried per lookup dimension combo
            geo_domain_tracking = {}

            for dev_id, st in active_devices:
                with STATE_LOCK:
                    feats = extractor.compute(st, now, int(CONFIG["window_seconds"]))
                
                if feats["total"] == 0:
                    continue

                # Generate statistical metric vectors
                feats["query_rate_z"]         = calculate_zscore(feats["query_rate"], st.rate_baseline)
                feats["entropy_avg_z"]        = calculate_zscore(feats["entropy_avg"], st.entropy_baseline)
                feats["entropy_z"]            = feats["entropy_avg_z"]
                feats["unique_domains_z"]     = calculate_zscore(feats["unique_domains"], st.unique_baseline)
                feats["nxdomain_ratio_z"]     = calculate_zscore(feats["nxdomain_ratio"], st.nxdomain_baseline)
                feats["blocked_ratio_z"]      = calculate_zscore(feats["blocked_ratio"], st.blocked_baseline)
                feats["suspicious_domains_z"] = calculate_zscore(feats["suspicious_domains"], st.dga_baseline)

                # Zeek network signals — needed before intel enrichment (Zeek dest IPs)
                zeek_feats  = zeek_fx.get_features(st.client_ip)
                zeek_alerts = zeek_fx.get_alerts(st.client_ip)
                zeek_dest_ips = zeek_fx.get_dest_ips(st.client_ip)
                feats.update(zeek_feats)

                ti_risk, abuse_risk, vt_risk, ti_match = _evaluate_intel(
                    st, feats, ti, abuseipdb, vt, zeek_dest_ips,
                )
                feats["ti_risk"] = ti_risk
                feats["abuseipdb_risk"] = abuse_risk
                feats["vt_risk"] = vt_risk

                ml_score = ml.score(dev_id, feats)

                with STATE_LOCK:
                    st.rate_baseline.update(feats["query_rate"])
                    st.entropy_baseline.update(feats["entropy_avg"])
                    st.unique_baseline.update(feats["unique_domains"])
                    st.nxdomain_baseline.update(feats["nxdomain_ratio"])
                    st.blocked_baseline.update(feats["blocked_ratio"])
                    st.dga_baseline.update(feats["suspicious_domains"])

                with STATE_LOCK:
                    risk_score = scorer.compute(feats, st, ml_score, zeek_alerts=zeek_alerts)

                ml.learn(dev_id, feats)
                zeek_fx.reset_cycle(st.client_ip)

                for domain_entry in st.rolling.domains.keys():
                    st.seen_domains.add(domain_entry)
                    while len(st.seen_domains) > _MAX_SEEN_DOMAINS:
                        st.seen_domains.pop()

                risk_velocity = calculate_zscore(risk_score, st.risk_baseline)
                with STATE_LOCK:
                    st.risk_baseline.update(risk_score)

                ti_risk_metric.labels(dev_id, st.hostname, st.device_type).set(ti_risk)
                ti_match_metric.labels(dev_id, st.hostname, st.device_type).set(ti_match)

                # GeoIP Routing Evaluation Loop
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

                    # 1. CORE GEOMAP SIGNALS
                    geo_risk_metric.labels(c_code, c_city, c_asn, c_org, c_cont, c_lat, c_lon).set(geo_risk)
                    if geo_risk > 0:
                        geo_hits_metric.labels(c_code, c_asn).inc(d_count)
                    if geo_beacon > 0:
                        geo_beacon_metric.labels(c_code, c_asn).inc(geo_beacon)
                    asn_risk_metric.labels(c_asn, c_org).set(5.0 if geo_risk > 0 else 0.0)

                    # 2. FULL TRAFFIC GEOGRAPHIC ACCUMULATORS (Aligned to exact dimension labels)
                    geo_traffic_total.labels(c_code, c_city, c_cont, c_asn, c_org, c_lat, c_lon).inc(d_count)
                    
                    # Compute window rate metric (Queries Per Minute)
                    qpm_calc = d_count * (60.0 / float(CONFIG["window_seconds"]))
                    geo_queries_per_minute.labels(c_code, c_city, c_asn, c_lat, c_lon).set(qpm_calc)
                    
                    # Tracking helper metrics for uniques/entropy/devices across intersections
                    dim_3 = (c_code, c_city, c_asn)
                    geo_domain_tracking.setdefault(dim_3, set()).add(domain_entry)
                    geo_device_tracking.setdefault(dim_3, set()).add(dev_id)

                    ent_score = FeatureExtractor()._entropy(domain_entry) if hasattr(FeatureExtractor(), "_entropy") else 3.0
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

                # Export Core & Advanced Detection Signals
                risk_metric.labels(dev_id, st.hostname, st.device_type).set(risk_score)
                query_rate_metric.labels(dev_id, st.hostname, st.device_type).set(feats["query_rate"])
                unique_domains_metric.labels(dev_id, st.hostname, st.device_type).set(feats["unique_domains"])
                entropy_metric.labels(dev_id, st.hostname, st.device_type).set(feats["entropy_avg"])
                blocked_ratio_metric.labels(dev_id, st.hostname, st.device_type).set(feats["blocked_ratio"])
                nxdomain_ratio_metric.labels(dev_id, st.hostname, st.device_type).set(feats["nxdomain_ratio"])
                suspicious_domains_metric.labels(dev_id, st.hostname, st.device_type).set(feats["suspicious_domains"])
                ml_anomaly_metric.labels(dev_id, st.hostname, st.device_type).set(ml_score)

                # Export Vector Statistical Signal Z-Scores
                zscore_query_metric.labels(dev_id, st.hostname, st.device_type).set(feats["query_rate_z"])
                zscore_entropy_metric.labels(dev_id, st.hostname, st.device_type).set(feats["entropy_avg_z"])
                zscore_unique_metric.labels(dev_id, st.hostname, st.device_type).set(feats["unique_domains_z"])
                zscore_nxdomain_metric.labels(dev_id, st.hostname, st.device_type).set(feats["nxdomain_ratio_z"])
                zscore_blocked_metric.labels(dev_id, st.hostname, st.device_type).set(feats["blocked_ratio_z"])
                zscore_dga_metric.labels(dev_id, st.hostname, st.device_type).set(feats["suspicious_domains_z"])
                risk_velocity_metric.labels(dev_id, st.hostname, st.device_type).set(risk_velocity)

                # Export Contextual Domain Telemetry Signals
                new_domains_metric.labels(dev_id, st.hostname, st.device_type).set(feats.get("new_domains", 0.0))
                deep_domains_metric.labels(dev_id, st.hostname, st.device_type).set(feats.get("deep_domains", 0.0))
                nxdomain_tld_conc_metric.labels(dev_id, st.hostname, st.device_type).set(feats.get("nxdomain_tld_conc", 0.0))
                safe_device_metric.labels(dev_id, st.hostname, st.device_type).set(1.0 if risk_score < 4.0 else 0.0)

                # Hysteresis Alert Engine & Dynamic Signature Generation
                alert_threshold = float(CONFIG["alert_threshold"])
                if risk_score >= alert_threshold:
                    z_scores = {
                        "High Query Rate": feats["query_rate_z"],
                        "Anomalous Entropy Burst": feats["entropy_z"],
                        "High Unique Domain Velocity": feats["unique_domains_z"],
                        "High NXDOMAIN Burst": feats["nxdomain_ratio_z"],
                        "Suspicious DGA Spiking": feats["suspicious_domains_z"],
                    }
                    if ti_risk > 0:
                        z_scores["Threat Intel IOC Match"] = ti_risk * 2.0
                    if abuse_risk > 0:
                        z_scores["AbuseIPDB Blacklist Match"] = abuse_risk * 2.0
                    if vt_risk > 0:
                        z_scores["VirusTotal Detection"] = vt_risk * 2.0
                    if zeek_feats.get("zeek_ja3_malicious", 0) > 0:
                        z_scores["Malicious JA3 TLS Fingerprint"] = 5.0
                    if zeek_feats.get("zeek_susp_ports", 0) > 0:
                        z_scores["Suspicious Destination Port"] = min(
                            zeek_feats["zeek_susp_ports"] * 2.0, 5.0
                        )
                    if ml_score > 0.15:
                        z_scores["ML Anomaly Exception"] = ml_score * 5.0
                    
                    sig = max(z_scores, key=z_scores.get)
                    
                    last_alert_risk = getattr(st, "last_alert_risk", 0.0)
                    last_alert_sig  = getattr(st, "last_alert_signature", "")
                    
                    risk_delta = abs(risk_score - last_alert_risk)
                    signature_changed = (sig != last_alert_sig)
                    
                    if (now - st.last_alert_time > 300) and (risk_delta >= 1.0 or signature_changed or last_alert_risk < alert_threshold):
                        st.last_alert_time = now
                        st.last_alert_risk = risk_score
                        st.last_alert_signature = sig
                        alerts_total.inc()
                        alerts.send(f"⚠️ [ALERT] Device {st.hostname} ({st.client_ip}) triggered threshold: {risk_score:.2f} ({sig})")
                else:
                    if getattr(st, "last_alert_risk", 0.0) >= alert_threshold:
                        st.last_alert_risk = 0.0
                        st.last_alert_signature = ""

            # 3. EXPORT EXPLICIT INTERSECTION GEOGRAPHIC TELEMETRY
            for dim_3, unique_domains_set in geo_domain_tracking.items():
                c_code, c_city, c_asn = dim_3
                geo_unique_domains.labels(c_code, c_city, c_asn).set(len(unique_domains_set))
                
            for dim_3, unique_devices_set in geo_device_tracking.items():
                c_code, c_city, c_asn = dim_3
                geo_device_count.labels(c_code, c_city, c_asn).set(len(unique_devices_set))

            # Push Country Density Distributions
            if geo_country_counts:
                top_country = geo_country_counts.most_common(1)[0][0]
                country_density_metric.labels(country=top_country).set(geo_country_counts[top_country])

            # Update Infrastructure Metrics
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