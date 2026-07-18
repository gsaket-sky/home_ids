"""
metrics.py - Prometheus metrics registry for Home IDS.

Centralizes all telemetry definitions to ensure consistent label structures 
and decouple metrics formatting from the main processing loop.
"""
from prometheus_client import Gauge, Counter

_DEV_LABELS = ["device", "hostname", "device_type"]

# =============================================================================
# CORE IDS METRICS
# =============================================================================
risk_metric = Gauge("home_ids_risk_score", "Overall IDS risk score", _DEV_LABELS)
query_rate_metric = Gauge("home_ids_query_rate", "DNS queries per minute", _DEV_LABELS)
unique_domains_metric = Gauge("home_ids_unique_domains", "Unique domains queried", _DEV_LABELS)
entropy_metric = Gauge("home_ids_entropy_avg", "Average DNS entropy", _DEV_LABELS)
blocked_ratio_metric = Gauge("home_ids_blocked_ratio", "Blocked DNS ratio", _DEV_LABELS)
nxdomain_ratio_metric = Gauge("home_ids_nxdomain_ratio", "NXDOMAIN ratio", _DEV_LABELS)
suspicious_domains_metric = Gauge("home_ids_suspicious_domains", "Suspicious/DGA-like domains", _DEV_LABELS)

# =============================================================================
# ML & MACHINE CONTEXT REGISTRIES
# =============================================================================
ml_anomaly_metric = Gauge("home_ids_ml_anomaly_score", "IsolationForest anomaly score", _DEV_LABELS)
zscore_query_metric = Gauge("home_ids_zscore_query_rate", "Query-rate z-score", _DEV_LABELS)
zscore_entropy_metric = Gauge("home_ids_zscore_entropy", "Entropy z-score", _DEV_LABELS)
zscore_unique_metric = Gauge("home_ids_zscore_unique_domains", "Unique-domain z-score", _DEV_LABELS)

# =============================================================================
# GEOIP / GEOMAP INFRASTRUCTURE TELEMETRY
# =============================================================================
geo_risk_metric = Gauge("home_ids_geo_risk", "Risk score by geography", ["country", "city", "asn", "org", "continent", "latitude", "longitude"])
geo_hits_metric = Counter("home_ids_geo_hits_total", "Threat hits by geolocation", ["country", "asn"])
asn_risk_metric = Gauge("home_ids_asn_risk_score", "Risk score by ASN", ["asn", "org"])
country_density_metric = Gauge("home_ids_country_threat_density", "Threat density per country", ["country"])
geo_beacon_metric = Counter("home_ids_geo_beaconing_total", "Beaconing detections by geography", ["country", "asn"])
geo_traffic_total = Counter("home_ids_geo_traffic_total", "All DNS traffic by geography", ["country", "city", "continent", "asn", "org", "latitude", "longitude"])
geo_queries_per_minute = Gauge("home_ids_geo_queries_per_minute", "DNS query rate by geography", ["country", "city", "asn", "latitude", "longitude"])
geo_unique_domains = Gauge("home_ids_geo_unique_domains", "Unique domains by geography", ["country", "city", "asn"])
geo_entropy = Gauge("home_ids_geo_entropy", "Entropy score by geography", ["country", "city", "asn"])
geo_device_count = Gauge("home_ids_geo_device_count", "Device count by geography", ["country", "city", "asn"])

# =============================================================================
# CORE ENGINE HEALTH MONITORING
# =============================================================================
collector_lag_metric = Gauge("home_ids_collector_lag_seconds", "Collector processing lag")
alert_queue_metric = Gauge("home_ids_alert_queue_size", "Current alert queue size")
ml_model_loaded_metric = Gauge("home_ids_ml_model_loaded", "ML model loaded state")
events_processed_metric = Counter("home_ids_events_processed_total", "Processed DNS events")
zeek_status_metric = Gauge("home_ids_zeek_status", "Zeek collector operational status")
zeek_events_processed_metric = Counter("home_ids_zeek_events_processed_total", "Total Zeek log events parsed")
alerts_total = Counter("home_ids_alerts_total", "IDS alerts triggered")

# =============================================================================
# IPS MITIGATION FORENSICS
# =============================================================================
ips_status_metric = Gauge("home_ids_ips_enabled", "Active IPS operational state (1=active, 0=bypass)")
ips_pihole_blocks_metric = Counter("home_ids_ips_pihole_blocks_total", "Total automated domain blocks executed", ["device", "hostname", "domain"])
ips_isolations_metric = Counter("home_ids_ips_router_isolations_total", "Total automated network isolation commands triggered", ["device", "hostname", "mac"])
ips_errors_metric = Counter("home_ids_ips_errors_total", "Total failure states encountered during active mitigation runs", ["target_type"])

# =============================================================================
# ADVANCED SIGNAL TELEMETRY MATRICES
# =============================================================================
new_domains_metric = Gauge("home_ids_new_domains", "Domains seen for the first time this window", _DEV_LABELS)
deep_domains_metric = Gauge("home_ids_deep_domains", "Domains with > 5 DNS labels", _DEV_LABELS)
nxdomain_tld_conc_metric = Gauge("home_ids_nxdomain_tld_concentration", "Fraction of traffic under top TLD", _DEV_LABELS)
zscore_nxdomain_metric = Gauge("home_ids_zscore_nxdomain_ratio", "NXDOMAIN ratio z-score", _DEV_LABELS)
zscore_blocked_metric = Gauge("home_ids_zscore_blocked_ratio", "Blocked ratio z-score", _DEV_LABELS)
zscore_dga_metric = Gauge("home_ids_zscore_suspicious_domains", "Suspicious domain count z-score", _DEV_LABELS)
risk_velocity_metric = Gauge("home_ids_risk_velocity", "Risk score z-score vs risk baseline", _DEV_LABELS)
ti_risk_metric = Gauge("home_ids_ti_risk", "Threat intelligence risk contribution", _DEV_LABELS)
ti_match_metric = Gauge("home_ids_ti_match", "Threat intelligence IOC match flag", _DEV_LABELS)
ti_ioc_hits_total = Counter("home_ids_ti_ioc_hits_total", "Total IOC matches from all TI feeds", ["source", "ioc_type"])
safe_device_metric = Gauge("home_ids_safe_device", "Device is on the safe list", _DEV_LABELS)
probation_status_metric = Gauge("home_ids_probation_status", "Device is in cold-start probation", _DEV_LABELS)
baseline_poisoned_metric = Gauge("home_ids_baseline_poisoned", "Baseline update frozen this cycle due to an active threat/anomaly signal", _DEV_LABELS)
per_device_threshold_metric = Gauge("home_ids_per_device_threshold", "DEAD/DUPLICATE metric.", _DEV_LABELS)
zeek_conn_count_metric = Gauge("home_ids_zeek_conn_count", "Total TCP/UDP connections seen by Zeek", _DEV_LABELS)
zeek_new_ips_metric = Gauge("home_ids_zeek_new_ips", "Unique destination IPs seen via Zeek", _DEV_LABELS)
zeek_ja3_metric = Gauge("home_ids_zeek_ja3_malicious", "Malicious JA3 TLS fingerprint hits", _DEV_LABELS)
zeek_notices_metric = Gauge("home_ids_zeek_notices", "Zeek notice events for this device", _DEV_LABELS)
zeek_susp_ports_metric = Gauge("home_ids_zeek_suspicious_ports", "Outbound connections to suspicious ports", _DEV_LABELS)
query_rate_baseline_mean_metric = Gauge("home_ids_query_rate_baseline_mean", "Per-device query rate moving average baseline", _DEV_LABELS)
query_rate_threshold_limit_metric = Gauge("home_ids_query_rate_threshold_limit", "Per-device dynamic query rate threshold limit", _DEV_LABELS)
ndr_doh_bypass_metric = Gauge("home_ids_zeek_doh_bypass", "Direct DoH queries intercepted", _DEV_LABELS)
ndr_lateral_moves_metric = Gauge("home_ids_zeek_lateral_moves", "Internal security lateral scanning actions", _DEV_LABELS)
ndr_jitter_c2_metric = Gauge("home_ids_beaconing_c2_count", "Highly uniform periodicity C2 channels tracked", _DEV_LABELS)
ndr_delta_exfil_metric = Gauge("home_ids_outbound_bytes_total", "Total outbound network payload bytes", _DEV_LABELS)
ndr_exfil_z_metric = Gauge("home_ids_outbound_bytes_zscore", "Payload outbound bytes baseline deviation Z-score", _DEV_LABELS)
abuseipdb_risk_metric = Gauge("home_ids_abuseipdb_risk", "AbuseIPDB reputation hazard severity", _DEV_LABELS)
virustotal_risk_metric = Gauge("home_ids_virustotal_risk", "VirusTotal sandbox analysis hazard severity", _DEV_LABELS)
beaconing_volume_metric = Gauge("home_ids_beaconing_volume_score", "Single-destination traffic concentration score", _DEV_LABELS)
jitter_cv_metric = Gauge("home_ids_jitter_cv_score", "Timing uniformity coefficient of variation", _DEV_LABELS)