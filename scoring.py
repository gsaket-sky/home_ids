"""
scoring.py – Risk scoring engine.

Changelog
─────────────────────────────────────────────────────────────────────
v1  Original: simple weighted sum of 8 signals. Missing return statement
    meant compute() always returned None → risk always 0.0 (critical bug).

v2  Bug fix: added return min(risk, 10.0).

v3  Detection improvements:
    Fix F: Correlated z-score signals capped at 4.0 – qz/ez/uz are all
            caused by DGA simultaneously; triple-counting inflated risk
    Fix G: Device-type sensitivity multipliers – IoT/printer use 0.6×
            sensitivity (more alert); laptop/phone use 1.0×
    Fix H: Risk velocity bonus – if current risk >> device baseline by
            > 3 std, add up to +1.5. Sudden spikes score higher than
            stable elevated scores.
    Fix I: ML sign fixed – was checking ml_score < -0.4 (raw
            decision_function convention); corrected to ml_score > 0.15
            (score() convention where positive = anomalous).

v4  New signals wired in:
    • new_domains – first-seen domain burst (+risk if > 20)
    • deep_domains – DNS label depth > 5 (+risk per domain)
    • nxdomain_tld_conc – TLD concentration × NXDOMAIN ratio
    • Beaconing escalation tiers: tdr>0.8 adds +2.0, eps>5 adds +1.5

v5  Threat intelligence and Zeek signals:
    • ti_risk: direct IOC match adds up to +4.0
    • zeek_ja3_malicious: known-bad TLS fingerprint adds up to +4.0
    • zeek_susp_ports: suspicious destination ports add up to +3.0
    • zeek_alerts: Zeek notices add up to +2.0 each, JA3 hits +5.0
    • compute() now accepts optional zeek_alerts parameter
"""
def safe_float(v, default: float = 0.0) -> float:
    try:
        return float(v) if v is not None else default
    except Exception:
        return default


# ── Device-type sensitivity ────────────────────────────────────────────────
# Multiplier < 1.0 = more sensitive (lower effective threshold).
# IoT / printers have near-zero expected DNS variance — any deviation is suspicious.
_DEVICE_SENSITIVITY = {
    "iot":            0.6,
    "printer":        0.6,
    "camera":         0.7,
    "nas":            0.8,
    "smart_tv":       0.8,
    "gaming_console": 0.9,
    "phone":          1.0,
    "laptop":         1.0,
    "unknown":        1.0,
    # Infrastructure devices — safe-listed but if somehow scored,
    # use 0.0 sensitivity so they never alert.
    "dns_server":     0.0,
    "router":         0.0,
    "gateway":        0.0,
}


class RiskScorer:

    def compute(self, features: dict, state,
                ml_score: float,
                zeek_alerts: list = None) -> float:

        risk = 0.0

        # ── device-type amplifier (Fix G) ─────────────────────────────────
        device_type = getattr(state, "device_type", None) or "unknown"
        sens        = _DEVICE_SENSITIVITY.get(device_type, 1.0)
        amplifier   = 1.0 / max(sens, 0.1)

        qz  = safe_float(features.get("query_rate_z"),      0.0)
        ez  = safe_float(features.get("entropy_z"),         0.0)
        uz  = safe_float(features.get("unique_domains_z"),  0.0)
        nx  = safe_float(features.get("nxdomain_ratio"),    0.0)
        bl  = safe_float(features.get("blocked_ratio"),     0.0)
        sd  = safe_float(features.get("suspicious_domains"),0.0)
        tdr = safe_float(features.get("top_domain_ratio"),  0.0)
        eps = safe_float(features.get("events_per_second"), 0.0)
        nd  = safe_float(features.get("new_domains",        0),   0.0)
        dd  = safe_float(features.get("deep_domains",       0),   0.0)
        tc  = safe_float(features.get("nxdomain_tld_conc",  0.0), 0.0)

        # ── Fix F: cap correlated z-score contribution ────────────────────
        z_risk = 0.0
        if qz > 3: z_risk += min(qz, 5) * 0.8
        if ez > 3: z_risk += min(ez, 5) * 0.6
        if uz > 3: z_risk += min(uz, 5) * 0.5
        risk += min(z_risk, 4.0)

        # ── NXDOMAIN ratio ────────────────────────────────────────────────
        if nx > 0.3:
            risk += nx * 4

        # ── Blocked ratio ─────────────────────────────────────────────────
        if bl > 0.2:
            risk += bl * 3

        # ── DGA / suspicious domains ──────────────────────────────────────
        risk += min(sd, 10) * 0.4

        # ── New domain burst (Fix B) ──────────────────────────────────────
        if nd > 20:
            risk += min(nd / 10, 2.0)

        # ── DNS tunnelling depth (Fix D) ──────────────────────────────────
        if dd > 0:
            risk += min(dd * 0.5, 2.0)

        # ── NXDOMAIN TLD concentration (Fix E) ───────────────────────────
        if tc > 0.7 and nx > 0.2:
            risk += (tc - 0.7) * 5

        # ── Temporal beaconing ────────────────────────────────────────────
        if tdr > 0.6 and eps > 2:
            risk += 2.5
        if tdr > 0.8 and eps > 2:
            risk += 2.0
        if tdr > 0.6 and eps > 5:
            risk += 1.5

        # ── ML anomaly (Fix I: positive = anomalous) ──────────────────────
        if ml_score > 0.15:
            risk += min(ml_score * 8, 4)

        # ── Threat intelligence IOC match ─────────────────────────────────
        # Direct hit against live TI feeds (Feodo, URLhaus, ThreatFox, OTX).
        ti_risk = safe_float(features.get("ti_risk", 0.0), 0.0)
        if ti_risk > 0:
            risk += min(ti_risk, 4.0)

        abuse_risk = safe_float(features.get("abuseipdb_risk", 0.0), 0.0)
        if abuse_risk > 0:
            risk += min(abuse_risk, 4.0)

        vt_risk = safe_float(features.get("vt_risk", 0.0), 0.0)
        if vt_risk > 0:
            risk += min(vt_risk, 4.0)

        # ── Zeek network signals ──────────────────────────────────────────
        # JA3 malicious TLS fingerprint — very high confidence (Cobalt Strike etc.)
        zeek_ja3 = safe_float(features.get("zeek_ja3_malicious", 0), 0.0)
        if zeek_ja3 > 0:
            risk += min(zeek_ja3 * 4.0, 4.0)

        # Suspicious destination ports (4444, 31337, IRC, etc.)
        zeek_ports = safe_float(features.get("zeek_susp_ports", 0), 0.0)
        if zeek_ports > 0:
            risk += min(zeek_ports * 1.5, 3.0)

        # Zeek notices and weirdness (Zeek's own protocol anomaly detection)
        if zeek_alerts:
            for alert in (zeek_alerts or []):
                conf  = safe_float(alert.get("confidence", 0.8), 0.8)
                atype = alert.get("type", "")
                if atype == "malicious_ja3":
                    risk += conf * 5.0   # near-certain malware TLS stack
                elif atype == "zeek_notice":
                    risk += conf * 2.0   # Zeek's own detection

        # ── Fix G: device-type amplifier (cap at 1.5×) ───────────────────
        risk *= min(amplifier, 1.5)

        # ── Fix H: risk velocity bonus ────────────────────────────────────
        risk_baseline = getattr(state, "risk_baseline", None)
        if risk_baseline is not None and risk_baseline.warmed_up:
            velocity = risk_baseline.zscore(risk)
            if velocity > 3:
                risk += min(velocity * 0.3, 1.5)

        return min(risk, 10.0)
