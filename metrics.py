"""
metrics.py - Prometheus metrics registry for Home IDS.

Centralizes all telemetry definitions to ensure consistent label structures 
and decouple metrics formatting from the main processing loop.
"""

from prometheus_client import Gauge, Counter

# =========================
# CORE IDS METRICS
# =========================

risk_metric = Gauge(
    "home_ids_risk_score",
    "Overall IDS risk score",
    ["device", "hostname", "device_type"]
)

query_rate_metric = Gauge(
    "home_ids_query_rate",
    "DNS queries per minute",
    ["device", "hostname", "device_type"]
)

unique_domains_metric = Gauge(
    "home_ids_unique_domains",
    "Unique domains queried",
    ["device", "hostname", "device_type"]
)

entropy_metric = Gauge(
    "home_ids_entropy_avg",
    "Average DNS entropy",
    ["device", "hostname", "device_type"]
)

blocked_ratio_metric = Gauge(
    "home_ids_blocked_ratio",
    "Blocked DNS ratio",
    ["device", "hostname", "device_type"]
)

nxdomain_ratio_metric = Gauge(
    "home_ids_nxdomain_ratio",
    "NXDOMAIN ratio",
    ["device", "hostname", "device_type"]
)

suspicious_domains_metric = Gauge(
    "home_ids_suspicious_domains",
    "Suspicious/DGA-like domains",
    ["device", "hostname", "device_type"]
)

# =========================
# ML METRICS
# =========================

ml_anomaly_metric = Gauge(
    "home_ids_ml_anomaly_score",
    "IsolationForest anomaly score",
    ["device", "hostname", "device_type"]
)

zscore_query_metric = Gauge(
    "home_ids_zscore_query_rate",
    "Query-rate z-score",
    ["device", "hostname", "device_type"]
)

zscore_entropy_metric = Gauge(
    "home_ids_zscore_entropy",
    "Entropy z-score",
    ["device", "hostname", "device_type"]
)

zscore_unique_metric = Gauge(
    "home_ids_zscore_unique_domains",
    "Unique-domain z-score",
    ["device", "hostname", "device_type"]
)

# =========================
# GEOIP / GEOMAP METRICS
# =========================

geo_risk_metric = Gauge(
    "home_ids_geo_risk",
    "Risk score by geolocation",
    [
        "country",
        "city",
        "asn",
        "org",
        "continent",
        "latitude",
        "longitude"
    ]
)

geo_hits_metric = Counter(
    "home_ids_geo_hits_total",
    "Threat hits by geolocation",
    ["country", "asn"]
)

asn_risk_metric = Gauge(
    "home_ids_asn_risk_score",
    "Risk score by ASN",
    ["asn", "org"]
)

country_density_metric = Gauge(
    "home_ids_country_threat_density",
    "Threat density per country",
    ["country"]
)

geo_beacon_metric = Counter(
    "home_ids_geo_beaconing_total",
    "Beaconing detections by geography",
    ["country", "asn"]
)

# =========================
# FULL TRAFFIC GEO METRICS
# =========================

geo_traffic_total = Counter(
    "home_ids_geo_traffic_total",
    "All DNS traffic by geography",
    [
        "country",
        "city",
        "continent",
        "asn",
        "org",
        "latitude",
        "longitude"
    ]
)

geo_queries_per_minute = Gauge(
    "home_ids_geo_queries_per_minute",
    "DNS query rate by geography",
    [
        "country",
        "city",
        "asn",
        "latitude",
        "longitude"
    ]
)

geo_unique_domains = Gauge(
    "home_ids_geo_unique_domains",
    "Unique domains by geography",
    [
        "country",
        "city",
        "asn"
    ]
)

geo_entropy = Gauge(
    "home_ids_geo_entropy",
    "Entropy score by geography",
    [
        "country",
        "city",
        "asn"
    ]
)

geo_device_count = Gauge(
    "home_ids_geo_device_count",
    "Device count by geography",
    [
        "country",
        "city",
        "asn"
    ]
)

# =========================
# INFRASTRUCTURE METRICS
# =========================

collector_lag_metric = Gauge(
    "home_ids_collector_lag_seconds",
    "Collector processing lag"
)

alert_queue_metric = Gauge(
    "home_ids_alert_queue_size",
    "Current alert queue size"
)

ml_model_loaded_metric = Gauge(
    "home_ids_ml_model_loaded",
    "ML model loaded state"
)

events_processed_metric = Counter(
    "home_ids_events_processed_total",
    "Processed DNS events"
)

alerts_total = Counter(
    "home_ids_alerts_total",
    "IDS alerts triggered"
)

# ══════════════════════════════════════════════════════════════════════════
# ADVANCED DETECTION SIGNAL METRICS
# ══════════════════════════════════════════════════════════════════════════

_DEV_LABELS = ["device", "hostname", "device_type"]

# ── New DNS signals ────────────────────────────────────────────────────────
new_domains_metric = Gauge(
    "home_ids_new_domains",
    "Domains seen for the first time this window (DGA burst indicator)",
    _DEV_LABELS,
)

deep_domains_metric = Gauge(
    "home_ids_deep_domains",
    "Domains with > 5 DNS labels (DNS tunnelling depth indicator)",
    _DEV_LABELS,
)

nxdomain_tld_conc_metric = Gauge(
    "home_ids_nxdomain_tld_concentration",
    "Fraction of traffic under the top TLD (DGA family clustering signal)",
    _DEV_LABELS,
)

# ── Per-device baseline z-scores ──────────────────────────────────────────
zscore_nxdomain_metric = Gauge(
    "home_ids_zscore_nxdomain_ratio",
    "NXDOMAIN ratio z-score vs device baseline",
    _DEV_LABELS,
)

zscore_blocked_metric = Gauge(
    "home_ids_zscore_blocked_ratio",
    "Blocked ratio z-score vs device baseline",
    _DEV_LABELS,
)

zscore_dga_metric = Gauge(
    "home_ids_zscore_suspicious_domains",
    "Suspicious domain count z-score vs device baseline",
    _DEV_LABELS,
)

# ── Risk velocity ──────────────────────────────────────────────────────────
risk_velocity_metric = Gauge(
    "home_ids_risk_velocity",
    "Risk score z-score vs device risk baseline (sudden spike detector)",
    _DEV_LABELS,
)

# ── Threat intelligence ────────────────────────────────────────────────────
ti_risk_metric = Gauge(
    "home_ids_ti_risk",
    "Threat intelligence risk contribution (0=clean, 4=known IOC)",
    _DEV_LABELS,
)

ti_match_metric = Gauge(
    "home_ids_ti_match",
    "Threat intelligence IOC match flag (0=clean, 1=matched)",
    _DEV_LABELS,
)

ti_ioc_hits_total = Counter(
    "home_ids_ti_ioc_hits_total",
    "Total IOC matches from all TI feeds",
    ["source", "ioc_type"],   
)

# ── Safe list ──────────────────────────────────────────────────────────────
safe_device_metric = Gauge(
    "home_ids_safe_device",
    "Device is on the safe list (1=excluded from scoring, 0=monitored)",
    _DEV_LABELS,
)

# ── Dynamic Limits ─────────────────────────────────────────────────────────
per_device_threshold_metric = Gauge(
    "home_ids_per_device_threshold",
    "Dynamic per-device threshold limit (mean + k * std_dev)",
    _DEV_LABELS,
)

# ── Zeek network signals ───────────────────────────────────────────────────
zeek_conn_count_metric = Gauge(
    "home_ids_zeek_conn_count",
    "Total TCP/UDP connections seen by Zeek this cycle",
    _DEV_LABELS,
)

zeek_new_ips_metric = Gauge(
    "home_ids_zeek_new_ips",
    "Unique destination IPs seen this cycle via Zeek conn.log",
    _DEV_LABELS,
)

zeek_ja3_metric = Gauge(
    "home_ids_zeek_ja3_malicious",
    "Malicious JA3 TLS fingerprint hits (Cobalt Strike, Meterpreter etc.)",
    _DEV_LABELS,
)

zeek_notices_metric = Gauge(
    "home_ids_zeek_notices",
    "Zeek notice/weird log events for this device this cycle",
    _DEV_LABELS,
)

zeek_susp_ports_metric = Gauge(
    "home_ids_zeek_suspicious_ports",
    "Outbound connections to suspicious ports (4444, 31337, IRC etc.)",
    _DEV_LABELS,
)

# ── Absolute Baseline Means ────────────────────────────────────────────────
query_rate_baseline_mean_metric = Gauge(
    "home_ids_query_rate_baseline_mean",
    "Per-device query rate moving average baseline (mean)",
    _DEV_LABELS,
)

# ── Dynamic Threshold Limits (Mean + k * StdDev) ───────────────────────────
query_rate_threshold_limit_metric = Gauge(
    "home_ids_query_rate_threshold_limit",
    "Per-device dynamic query rate threshold ceiling line",
    _DEV_LABELS,
)

# ══════════════════════════════════════════════════════════════════════════
# NEW: ADVANCED NDR TELEMETRY (Jitter, Evasion, Lateral Movement)
# ══════════════════════════════════════════════════════════════════════════

ndr_doh_bypass_metric = Gauge(
    "home_ids_zeek_doh_bypass",
    "Direct DoH queries or SNI lookups intercepted",
    _DEV_LABELS,
)

ndr_lateral_moves_metric = Gauge(
    "home_ids_zeek_lateral_moves",
    "Internal security lateral scanning movement actions count",
    _DEV_LABELS,
)

ndr_jitter_c2_metric = Gauge(
    "home_ids_beaconing_c2_count",
    "Highly deterministic uniform periodicity C2 channel clocks tracked",
    _DEV_LABELS,
)

ndr_exfil_z_metric = Gauge(
    "home_ids_outbound_bytes_zscore",
    "Payload outbound bytes baseline deviation Z-score",
    _DEV_LABELS,
)