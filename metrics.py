"""
metrics.py – Prometheus metrics definitions.

Changelog
─────────────────────────────────────────────────────────────────────
v1  Original: 26 metrics covering core IDS, ML, geo, and infrastructure.

v2  New detection signal metrics added (current version, 33 total):
    home_ids_new_domains           – first-seen domain count (DGA burst)
    home_ids_deep_domains          – DNS label depth > 5 (tunnelling)
    home_ids_nxdomain_tld_concentration – TLD concentration (DGA family)
    home_ids_zscore_nxdomain_ratio – NXDOMAIN z-score vs device baseline
    home_ids_zscore_blocked_ratio  – blocked ratio z-score vs baseline
    home_ids_zscore_suspicious_domains – DGA count z-score vs baseline
    home_ids_risk_velocity         – risk score z-score (sudden spikes)

    All 7 metrics carry device/hostname/device_type labels.
    All pushed once per device per poll cycle from main.py.
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

# =========================
# NEW DETECTION SIGNALS
# (added after detection logic improvements)
# =========================

new_domains_metric = Gauge(
    "home_ids_new_domains",
    "Domains seen for the first time this window (DGA new-domain burst indicator)",
    ["device", "hostname", "device_type"]
)

deep_domains_metric = Gauge(
    "home_ids_deep_domains",
    "Domains with > 5 DNS labels (DNS tunnelling depth indicator)",
    ["device", "hostname", "device_type"]
)

nxdomain_tld_conc_metric = Gauge(
    "home_ids_nxdomain_tld_concentration",
    "Fraction of traffic under the top TLD (DGA family clustering signal)",
    ["device", "hostname", "device_type"]
)

zscore_nxdomain_metric = Gauge(
    "home_ids_zscore_nxdomain_ratio",
    "NXDOMAIN ratio z-score vs device baseline",
    ["device", "hostname", "device_type"]
)

zscore_blocked_metric = Gauge(
    "home_ids_zscore_blocked_ratio",
    "Blocked ratio z-score vs device baseline",
    ["device", "hostname", "device_type"]
)

zscore_dga_metric = Gauge(
    "home_ids_zscore_suspicious_domains",
    "Suspicious domain count z-score vs device baseline",
    ["device", "hostname", "device_type"]
)

risk_velocity_metric = Gauge(
    "home_ids_risk_velocity",
    "Risk score z-score vs device risk baseline (sudden spike detector)",
    ["device", "hostname", "device_type"]
)

# =========================
# ZEEK NETWORK SIGNALS
# =========================

zeek_conn_count_metric = Gauge(
    "home_ids_zeek_conn_count",
    "Total TCP/UDP connections seen by Zeek (catches direct IP C2)",
    ["device", "hostname", "device_type"]
)

zeek_new_ips_metric = Gauge(
    "home_ids_zeek_new_ips",
    "Unique destination IPs seen this cycle via Zeek conn.log",
    ["device", "hostname", "device_type"]
)

zeek_ja3_metric = Gauge(
    "home_ids_zeek_ja3_malicious",
    "Malicious JA3 TLS fingerprint hits (Cobalt Strike, Meterpreter etc)",
    ["device", "hostname", "device_type"]
)

zeek_notices_metric = Gauge(
    "home_ids_zeek_notices",
    "Zeek notice/weird log events for this device",
    ["device", "hostname", "device_type"]
)

zeek_susp_ports_metric = Gauge(
    "home_ids_zeek_suspicious_ports",
    "Outbound connections to suspicious ports (4444, 31337, IRC etc)",
    ["device", "hostname", "device_type"]
)

# =========================
# THREAT INTELLIGENCE
# =========================

ti_risk_metric = Gauge(
    "home_ids_ti_risk",
    "Threat intelligence risk contribution (0=clean, 4=known IOC)",
    ["device", "hostname", "device_type"]
)

ti_match_metric = Gauge(
    "home_ids_ti_match",
    "Threat intelligence IOC match flag (0=clean 1=matched)",
    ["device", "hostname", "device_type"]
)

ti_ioc_hits_total = Counter(
    "home_ids_ti_ioc_hits_total",
    "Total IOC matches from all TI feeds",
    ["source", "ioc_type"]   # source=feodo/urlhaus/abuseipdb etc, ioc_type=ip/domain
)

# =========================
# SAFE LIST / ALLOWLIST
# =========================

safe_device_metric = Gauge(
    "home_ids_safe_device",
    "Device is on the safe list (1=safe, 0=monitored)",
    ["device", "hostname", "device_type"]
)
