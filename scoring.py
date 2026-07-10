"""
scoring.py - Risk scoring engine.

Keeps IDS scoring explainable: compute() returns the numeric risk, while
explain() returns the same risk plus the factors that contributed to it.

Hardened Improvements:
  - Fixed the new_domains and deep_domains count-vs-ratio evaluation bug.
  - Anchored absolute heuristic scoring rules to statistical Z-score validation.
  - Implemented an elastic low-volume dampener for quiet/sleeping windows.
"""

def safe_float(v, default: float = 0.0) -> float:
    try:
        return float(v) if v is not None else default
    except Exception:
        return default


# Multiplier < 1.0 means more sensitive. IoT devices such as Echo/Alexa are
# intentionally no longer amplified: repetitive DNS is normal for that class.
_DEVICE_SENSITIVITY = {
    "iot":            1.0,
    "printer":        0.9,
    "camera":         0.9,
    "nas":            0.9,
    "smart_tv":       1.0,
    "gaming_console": 1.0,
    "phone":          1.0,
    "laptop":         1.0,
    "unknown":        1.0,
    "dns_server":     0.0,
    "router":         0.0,
    "gateway":        0.0,
}


class RiskScorer:
    def compute(self, features: dict, state, ml_score: float,
                zeek_alerts: list = None) -> float:
        return self.explain(features, state, ml_score, zeek_alerts)["risk"]

    def explain(self, features: dict, state, ml_score: float,
                zeek_alerts: list = None) -> dict:
        factors = []

        def add(name: str, score: float, value=None, detail: str = "") -> None:
            score = safe_float(score, 0.0)
            if score <= 0:
                return
            factors.append({
                "name": name,
                "score": round(score, 3),
                "value": value,
                "detail": detail,
            })

        device_type = getattr(state, "device_type", None) or "unknown"
        sens = _DEVICE_SENSITIVITY.get(device_type, 1.0)
        if sens <= 0:
            return {
                "risk": 0.0,
                "factors": [{
                    "name": "Infrastructure device suppression",
                    "score": 0.0,
                    "value": device_type,
                    "detail": "Device type is configured not to alert",
                }],
            }
        amplifier = min(1.0 / max(sens, 0.1), 1.25)

        # Extract features and statistical Z-Scores
        qz   = safe_float(features.get("query_rate_z"), 0.0)
        ez   = safe_float(features.get("entropy_z"), 0.0)
        uz   = safe_float(features.get("unique_domains_z"), 0.0)
        nx_z = safe_float(features.get("nxdomain_ratio_z"), 0.0)
        bl_z = safe_float(features.get("blocked_ratio_z"), 0.0)
        sd_z = safe_float(features.get("suspicious_domains_z"), 0.0)
        
        # Absolute structural observations
        nx   = safe_float(features.get("nxdomain_ratio"), 0.0)
        bl   = safe_float(features.get("blocked_ratio"), 0.0)
        sd   = safe_float(features.get("suspicious_domains"), 0.0)
        tdr  = safe_float(features.get("top_domain_ratio"), 0.0)
        eps  = safe_float(features.get("events_per_second"), 0.0)
        nd   = safe_float(features.get("new_domains", 0.0), 0.0)
        dd   = safe_float(features.get("deep_domains", 0.0), 0.0)
        tc   = safe_float(features.get("nxdomain_tld_conc", 0.0), 0.0)
        total = safe_float(features.get("total", 0), 0.0)
        unique_domains = safe_float(features.get("unique_domains", 1.0), 1.0)

        # Dynamic Low-Volume Dampener Matrix
        # Protects quiet window cycles (total < 100) from ratio mathematical instability
        volume_dampener = 1.0 if total >= 100.0 else max(0.1, total / 100.0)

        # Fix count-vs-ratio evaluation error for structural domain properties
        nd_ratio = nd / max(unique_domains, 1.0)
        dd_ratio = dd / max(unique_domains, 1.0)

        z_parts = []
        z_score_count = sum([qz > 3.0, ez > 3.0, uz > 3.0])

        if qz > 3.0: z_parts.append(f"query_rate_z={qz:.2f}")
        if ez > 3.0: z_parts.append(f"entropy_z={ez:.2f}")
        if uz > 3.0: z_parts.append(f"unique_domains_z={uz:.2f}")
        if nx > 0.3 and nx_z > 3.0: z_parts.append(f"nxdomain_ratio={nx:.2f}(Z={nx_z:.1f})")
        if bl > 0.7 and bl_z > 3.0 and nx > 0.15: z_parts.append(f"blocked_ratio={bl:.2f}(Z={bl_z:.1f})")

        # Correlated anomalies must be validated against actual baseline variance
        abs_count = sum([
            nx > 0.3 and nx_z > 3.0,
            bl > 0.7 and bl_z > 3.0 and nx > 0.15,
        ])
        dns_anomaly_count = z_score_count + abs_count

        if z_score_count >= 1 and dns_anomaly_count >= 2:
            add("Correlated DNS baseline deviation", 3.0 * volume_dampener, None, ", ".join(z_parts))
            
        # Standalone Heuristics: Anchored directly to Z-scores to prevent local configuration blocking traps
        if nx > 0.5 and nx_z > 3.0:
            add("NXDOMAIN ratio", (nx - 0.5) * 4 * volume_dampener, round(nx, 3), f"Failed lookups deviating from baseline (Z={nx_z:.2f})")

        if bl > 0.85 and bl_z > 3.0 and nx > 0.2:
            add("Blocked DNS ratio", (bl - 0.85) * 4 * volume_dampener, round(bl, 3), f"Extreme block evasion behavior (Z={bl_z:.2f})")

        if sd > 0 and sd_z > 3.0:
            add("Suspicious/DGA-like domains", min(sd, 10) * 0.4 * volume_dampener, sd, f"Heuristic matches verified by anomaly spike (Z={sd_z:.2f})")

        # Evaluating true evaluated fractions instead of absolute row counts
        if nd_ratio > 0.25 and total >= 30:
            add("First-seen domain burst", min(nd_ratio * 4.0, 2.0) * volume_dampener, round(nd_ratio, 3), f"New infrastructure share expansion ({int(nd)} domains)")

        if dd_ratio > 0.10 and total >= 30:
            add("Deep DNS labels", min(dd_ratio * 4.0, 2.0) * volume_dampener, round(dd_ratio, 3), f"Deep subdomains share expansion ({int(dd)} domains)")

        if tc > 0.7 and nx > 0.2 and nx_z > 3.0:
            add("NXDOMAIN TLD concentration", (tc - 0.7) * 5 * volume_dampener, round(tc, 3), "Failures concentrated in anomalous TLD structure")

        # Beaconing evaluation loop
        beacon_score = 0.0
        if tdr > 0.90 and eps > 5:   beacon_score = 2.5
        elif tdr > 0.80 and eps > 3: beacon_score = 1.5
        elif tdr > 0.70 and eps > 5: beacon_score = 1.0
        add("High-volume single-domain beaconing", beacon_score * volume_dampener, round(tdr, 3), f"events_per_second={eps:.2f}")

        # Machine Learning Inference Parsing
        if ml_score > 0.02:
            add("ML anomaly", min(ml_score * 40.0, 4.0), round(ml_score, 4), "Per-device IsolationForest anomaly margin")

        # Threat Intelligence Feed Evaluation
        ti_risk = safe_float(features.get("ti_risk", 0.0), 0.0)
        add("Threat intelligence IOC", min(ti_risk, 4.0), round(ti_risk, 3), "Domain or IP matched loaded IOC feeds")

        abuse_risk = safe_float(features.get("abuseipdb_risk", 0.0), 0.0)
        add("AbuseIPDB blacklist", min(abuse_risk, 4.0), round(abuse_risk, 3), "Destination IP appears in AbuseIPDB blacklist")

        vt_risk = safe_float(features.get("vt_risk", 0.0), 0.0)
        add("VirusTotal detection", min(vt_risk, 4.0), round(vt_risk, 3), "Cached VirusTotal result is suspicious or malicious")

        # Zeek Network Core Signals
        zeek_ja3 = safe_float(features.get("zeek_ja3_malicious", 0), 0.0)
        add("Malicious JA3 TLS fingerprint", min(zeek_ja3 * 4.0, 4.0), zeek_ja3, "Known malware TLS fingerprint")

        zeek_ports = safe_float(features.get("zeek_susp_ports", 0), 0.0)
        add("Suspicious destination port", min(zeek_ports * 1.5, 3.0), zeek_ports, "Outbound connection to suspicious port")

        _BENIGN_ZEEK_WEIRD = frozenset({
            "weird:data_before_established",
            "weird:inappropriate_FIN",
            "weird:bad_TCP_checksum",
            "weird:above_hole_data_without_any_acks",
            "weird:connection_originator_SYN_ack",
        })

        if zeek_alerts:
            zeek_notice_total = 0.0
            for alert in (zeek_alerts or []):
                conf  = safe_float(alert.get("confidence", 0.8), 0.8)
                atype = alert.get("type", "")
                if atype == "malicious_ja3":
                    add("Zeek malicious JA3 alert", conf * 5.0, alert.get("ja3", ""), alert.get("server", ""))
                elif atype == "zeek_notice":
                    note = alert.get("note", "")
                    if note in _BENIGN_ZEEK_WEIRD:
                        continue   
                    zeek_notice_total += conf * 1.5
            
            capped_notice = min(zeek_notice_total, 2.0)
            if capped_notice > 0:
                add("Zeek notice", capped_notice, None, "Zeek protocol anomaly (capped)")

        risk = sum(f["score"] for f in factors)
        if amplifier != 1.0 and risk > 0:
            before = risk
            risk *= amplifier
            add("Device sensitivity multiplier", risk - before, round(amplifier, 3), device_type)

        # Baseline Risk Tracking Engine
        risk_baseline = getattr(state, "risk_baseline", None)
        warmed_up = bool(
            risk_baseline is not None
            and getattr(risk_baseline, "initialized", False)
            and getattr(risk_baseline, "n", 0) >= 100
        )
        if warmed_up:
            import math as _math
            _std = _math.sqrt(max(getattr(risk_baseline, "var", 1.0), 1.0))
            velocity = (risk - getattr(risk_baseline, "mean", 0.0)) / _std
            if velocity > 4.0:   
                bonus = min(velocity * 0.25, 1.0)   
                risk += bonus
                add("Risk velocity", bonus, round(velocity, 3), "Risk rose sharply above this device baseline")

        risk = min(risk, 10.0)
        factors.sort(key=lambda f: f["score"], reverse=True)
        return {"risk": round(risk, 3), "factors": factors}