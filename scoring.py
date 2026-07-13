"""
scoring.py - Risk scoring engine.

Keeps IDS scoring explainable: compute() returns the numeric risk, while
explain() returns the same risk plus the factors that contributed to it.

Hardened Improvements:
  - Fixed the new_domains and deep_domains count-vs-ratio evaluation bug.
  - Anchored absolute heuristic scoring rules to statistical Z-score validation.
  - Implemented an elastic low-volume dampener for quiet/sleeping windows.
  - Added Stateful Contextual Enrichment to dampen false-positive beaconing risks.
  - Added Probationary Guard to enforce rigid rules on unverified cold-start devices.
  - Added Diurnal Velocity checking to adapt risk to Day/Night activity cycles.
  - NDR UPGRADES: Processes Jitter coefficient scores, DoH proxy evasion actions, and Private Subnet Lateral scanner pivots.
  - CONTEXTUAL DAMPENER: Applied 80% penalty reduction to DGA and C2 Jitter rules for mobile devices to accommodate natural background telemetry.
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
        
        # Determine base context dampener for natural mobile behavior
        is_mobile = device_type in ["phone", "tablet"]
        
        # Phones naturally beacon and query messy API hashes for push notifications. 
        # We slash the penalty weight for these specific behaviors by 80% for mobile devices.
        mobile_dampener = 0.2 if is_mobile else 1.0
        
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
        volume_dampener = 1.0 if total >= 100.0 else max(0.1, total / 100.0)

        # Stateful Contextual Enrichment
        top_domain_is_familiar = bool(features.get("top_domain_is_familiar", False))
        
        if top_domain_is_familiar and tdr > 0.50:
            context_dampener = 0.35
            context_detail = " (Dampened: spike maps to familiar historical domain)"
        else:
            context_dampener = 1.0
            context_detail = ""

        # Probationary Cold-Device Detection (Day-Zero Protection)
        rate_baseline_n = sum(getattr(state.rate_baseline, "n", [0, 0]))
        is_on_probation = (rate_baseline_n < 1000)

        if is_on_probation:
            if total > 150 and unique_domains > 40:
                add("Probationary volume ceiling breach", 3.5 * context_dampener, total, f"Unverified new device generating high density out-of-the-box query volumes{context_detail}")
            if nx > 0.40:
                add("Probationary NXDOMAIN absolute breach", 3.0 * context_dampener, round(nx, 3), f"Unverified new device generating high absolute failure rates{context_detail}")
            if nd > 15:
                add("Probationary unmapped infrastructure flood", 2.5 * context_dampener, nd, f"Device contacting substantial unique external targets on first run{context_detail}")
        
        nd_ratio = nd / max(unique_domains, 1.0)
        dd_ratio = dd / max(unique_domains, 1.0)

        z_parts = []
        z_score_count = sum([qz > 3.0, ez > 3.0, uz > 3.0])

        if qz > 3.0: z_parts.append(f"query_rate_z={qz:.2f}")
        if ez > 3.0: z_parts.append(f"entropy_z={ez:.2f}")
        if uz > 3.0: z_parts.append(f"unique_domains_z={uz:.2f}")
        if nx > 0.3 and nx_z > 3.0: z_parts.append(f"nxdomain_ratio={nx:.2f}(Z={nx_z:.1f})")
        if bl > 0.7 and bl_z > 3.0 and nx > 0.15: z_parts.append(f"blocked_ratio={bl:.2f}(Z={bl_z:.1f})")

        abs_count = sum([
            nx > 0.3 and nx_z > 3.0,
            bl > 0.7 and bl_z > 3.0 and nx > 0.15,
        ])
        dns_anomaly_count = z_score_count + abs_count

        if z_score_count >= 1 and dns_anomaly_count >= 2:
            add("Correlated DNS baseline deviation", 3.0 * volume_dampener * context_dampener, None, ", ".join(z_parts) + context_detail)
            
        if not is_on_probation:
            if nx > 0.5 and nx_z > 3.0:
                add("NXDOMAIN ratio", (nx - 0.5) * 4 * volume_dampener * context_dampener, round(nx, 3), f"Failed lookups deviating from profile{context_detail}")
            if bl > 0.85 and bl_z > 3.0 and nx > 0.2:
                add("Blocked DNS ratio", (bl - 0.85) * 4 * volume_dampener * context_dampener, round(bl, 3), f"Extreme block evasion behavior (Z={bl_z:.2f}){context_detail}")
            if sd > 0 and sd_z > 3.0:
                # Dampened for mobile heuristics
                add("Suspicious/DGA-like domains", min(sd, 10) * 0.4 * volume_dampener * context_dampener * mobile_dampener, sd, f"Heuristic matches verified by anomaly spike (Z={sd_z:.2f}){context_detail}")

        if nd_ratio > 0.25 and total >= 30:
            add("First-seen domain burst", min(nd_ratio * 4.0, 2.0) * volume_dampener, round(nd_ratio, 3), f"New infrastructure share expansion ({int(nd)} domains)")

        if dd_ratio > 0.10 and total >= 30:
            add("Deep DNS labels", min(dd_ratio * 4.0, 2.0) * volume_dampener, round(dd_ratio, 3), f"Deep subdomains share expansion ({int(dd)} domains)")

        if tc > 0.7 and nx > 0.2 and nx_z > 3.0:
            add("NXDOMAIN TLD concentration", (tc - 0.7) * 5 * volume_dampener * context_dampener, round(tc, 3), f"Failures concentrated in anomalous TLD structure{context_detail}")

        beacon_score = 0.0
        if tdr > 0.90 and eps > 5:   beacon_score = 2.5
        elif tdr > 0.80 and eps > 3: beacon_score = 1.5
        elif tdr > 0.70 and eps > 5: beacon_score = 1.0
        
        add("High-volume single-domain beaconing", beacon_score * volume_dampener * context_dampener, round(tdr, 3), f"events_per_second={eps:.2f}{context_detail}")

        if ml_score > 0.02:
            if is_on_probation:
                ml_penalty = min(ml_score * 80.0, 5.0)
                add("ML absolute structural outlier (Probationary)", ml_penalty, round(ml_score, 4), "Device structure severely contradicts global home network cluster parameters")
            else:
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

        # ── NEW ADVANCED DETECTION SCORING PENALTIES ─────────────────────────
        c2_jitter_count = safe_float(features.get("beaconing_c2_count", 0), 0.0)
        if c2_jitter_count > 0:
            # Dampened for mobile natural background beaconing
            add("C2 Jitter Clock Verification", 4.0 * volume_dampener * context_dampener * mobile_dampener, c2_jitter_count, "Uniform periodicity check-in sequences tracked")

        doh_bypass_count = safe_float(features.get("zeek_doh_bypass", 0), 0.0)
        if doh_bypass_count > 0:
            add("DoH Tunneling Bypass Evasion", 5.0, doh_bypass_count, "Encrypted DNS lookup queries bypassing local network gateway filters")

        lateral_moves_count = safe_float(features.get("zeek_lateral_moves", 0), 0.0)
        if lateral_moves_count > 0:
            add("Internal Lateral Movement", 6.0, lateral_moves_count, "Subnet security scanning violations targeting core infrastructure ports")

        outbound_bytes_z = safe_float(features.get("outbound_bytes_z", 0.0), 0.0)
        if outbound_bytes_z > 5.0:
            add("Exfiltration Payload Burst", 3.5 * volume_dampener, round(outbound_bytes_z, 2), f"Outbound transfer byte metrics severely breaking distribution bounds")

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

        # Baseline Risk Tracking Engine (Diurnal Velocity)
        risk_baseline = getattr(state, "risk_baseline", None)
        if risk_baseline:
            current_hour = int(features.get("current_hour", 12))
            mean, var, init, n = risk_baseline.get_stats(current_hour)
            if init and n >= 100:
                import math as _math
                _std = _math.sqrt(max(var, 1.0))
                velocity = (risk - mean) / _std
                if velocity > 4.0:   
                    bonus = min(velocity * 0.25, 1.0)   
                    risk += bonus
                    add("Risk velocity", bonus, round(velocity, 3), f"Risk rose sharply above typical hourly index (Z={velocity:.2f})")

        risk = min(risk, 10.0)
        factors.sort(key=lambda f: f["score"], reverse=True)
        return {"risk": round(risk, 3), "factors": factors}