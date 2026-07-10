"""
scoring.py - Risk scoring engine.

Keeps IDS scoring explainable: compute() returns the numeric risk, while
explain() returns the same risk plus the factors that contributed to it.

Codex changelog 2026-06-18:
  - Added explain() so every risk score can report the factors that caused it.
  - Reduced false positives for normal IoT/Echo traffic by removing IoT amplification and non-stacking beacon tiers.
  - Corrected new_domains/deep_domains handling as ratios.
  - Standardized ML score handling: 0 means normal/unavailable, positive means anomalous.
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

        qz  = safe_float(features.get("query_rate_z"), 0.0)
        ez  = safe_float(features.get("entropy_z"), 0.0)
        uz  = safe_float(features.get("unique_domains_z"), 0.0)
        nx  = safe_float(features.get("nxdomain_ratio"), 0.0)
        bl  = safe_float(features.get("blocked_ratio"), 0.0)
        sd  = safe_float(features.get("suspicious_domains"), 0.0)
        tdr = safe_float(features.get("top_domain_ratio"), 0.0)
        eps = safe_float(features.get("events_per_second"), 0.0)
        nd  = safe_float(features.get("new_domains", 0.0), 0.0)
        dd  = safe_float(features.get("deep_domains", 0.0), 0.0)
        tc  = safe_float(features.get("nxdomain_tld_conc", 0.0), 0.0)
        total = safe_float(features.get("total", 0), 0.0)

        z_parts = []

        # FP-2 fix: the correlated anomaly signal now requires at least ONE
        # statistical z-score (qz/ez/uz > 3) to be present. Previously
        # bl>0.25 + nx>0.25 + any z-score would fire — on a Pi-hole network
        # bl>0.25 is permanently true for phones/TVs, creating constant FPs.
        #
        # FP-3 fix: blocked_ratio threshold raised from 0.25 → 0.70.
        # 80-90% blocked is the Pi-hole normal for ad-heavy consumer devices.
        # Only flag blocked_ratio if it is extreme AND paired with NXDOMAIN.
        z_score_count = sum([qz > 3, ez > 3, uz > 3])

        if qz > 3: z_parts.append(f"query_rate_z={qz:.2f}")
        if ez > 3: z_parts.append(f"entropy_z={ez:.2f}")
        if uz > 3: z_parts.append(f"unique_domains_z={uz:.2f}")
        if nx > 0.3: z_parts.append(f"nxdomain_ratio={nx:.2f}")
        if bl > 0.7 and nx > 0.15: z_parts.append(f"blocked_ratio={bl:.2f}")

        # At least one z-score must be elevated; count absolute thresholds only if
        # they corroborate existing z-score evidence (not as primary drivers).
        abs_count = sum([
            nx > 0.3,
            bl > 0.7 and nx > 0.15,  # only extreme blocked + corroborating NXDOMAIN
        ])
        dns_anomaly_count = z_score_count + abs_count

        if z_score_count >= 1 and dns_anomaly_count >= 2:
            dns_penalty = 3.0
            add("Correlated DNS baseline deviation", dns_penalty, None, ", ".join(z_parts))
            
        # FP-3 continued: standalone NXDOMAIN only fires at > 0.5 (extreme).
        # Lower values are corroborating evidence in the correlated signal above.
        if nx > 0.5:
            add("NXDOMAIN ratio", (nx - 0.5) * 4, round(nx, 3), "Many failed DNS lookups")

        # Blocked ratio standalone: only at extreme levels (>85%) AND with NXDOMAIN evidence.
        # Normal Pi-hole networks have 50-90% blocked for ad-heavy devices.
        if bl > 0.85 and nx > 0.2:
            add("Blocked DNS ratio", (bl - 0.85) * 4, round(bl, 3), "Extreme blocked+NXDOMAIN combo")

        add("Suspicious/DGA-like domains", min(sd, 10) * 0.4, sd, "Domains matched local heuristics")

        # new_domains and deep_domains are ratios from features.py, not counts.
        if nd > 0.25 and total >= 20:
            add("First-seen domain burst", min(nd * 4.0, 2.0), round(nd, 3), "Large share of domains not seen before for this device")

        if dd > 0.10 and total >= 20:
            add("Deep DNS labels", min(dd * 4.0, 2.0), round(dd, 3), "Possible DNS tunnelling label depth")

        if tc > 0.7 and nx > 0.2:
            add("NXDOMAIN TLD concentration", (tc - 0.7) * 5, round(tc, 3), "Failures concentrated in one TLD")

        # Use one beaconing tier instead of stacking three bonuses. Repetitive DNS
        # from Echo/TV/IoT devices should not become a high alert by itself.
        beacon_score = 0.0
        if tdr > 0.90 and eps > 5:
            beacon_score = 2.5
        elif tdr > 0.80 and eps > 3:
            beacon_score = 1.5
        elif tdr > 0.70 and eps > 5:
            beacon_score = 1.0
        add("High-volume single-domain beaconing", beacon_score, round(tdr, 3), f"events_per_second={eps:.2f}")

        # ML score convention: 0=normal/unavailable, positive=outlier margin.
        if ml_score > 0.02:
            add("ML anomaly", min(ml_score * 40.0, 4.0), round(ml_score, 4), "Per-device IsolationForest anomaly margin")

        ti_risk = safe_float(features.get("ti_risk", 0.0), 0.0)
        add("Threat intelligence IOC", min(ti_risk, 4.0), round(ti_risk, 3), "Domain or IP matched loaded IOC feeds")

        abuse_risk = safe_float(features.get("abuseipdb_risk", 0.0), 0.0)
        add("AbuseIPDB blacklist", min(abuse_risk, 4.0), round(abuse_risk, 3), "Destination IP appears in AbuseIPDB blacklist")

        vt_risk = safe_float(features.get("vt_risk", 0.0), 0.0)
        add("VirusTotal detection", min(vt_risk, 4.0), round(vt_risk, 3), "Cached VirusTotal result is suspicious or malicious")

        zeek_ja3 = safe_float(features.get("zeek_ja3_malicious", 0), 0.0)
        add("Malicious JA3 TLS fingerprint", min(zeek_ja3 * 4.0, 4.0), zeek_ja3, "Known malware TLS fingerprint")

        zeek_ports = safe_float(features.get("zeek_susp_ports", 0), 0.0)
        add("Suspicious destination port", min(zeek_ports * 1.5, 3.0), zeek_ports, "Outbound connection to suspicious port")

        # FP-4 fix: Zeek notices capped at 2.0 total risk.
        # Each notice was adding 0.75-1.5 risk with no cap — Aki-PC got
        # 4 notices (data_before_established + inappropriate_FIN) which are
        # common Windows TCP behaviours (NAT timing, VPN reconnects) and
        # together added 6.0 risk = the entire alert.
        # Known-benign weird types are suppressed entirely.
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
                        continue   # suppress known-harmless TCP weirdness
                    zeek_notice_total += conf * 1.5
            # Cap total notice contribution
            capped_notice = min(zeek_notice_total, 2.0)
            if capped_notice > 0:
                add("Zeek notice", capped_notice, None, "Zeek protocol anomaly (capped)")

        risk = sum(f["score"] for f in factors)
        if amplifier != 1.0 and risk > 0:
            before = risk
            risk *= amplifier
            add("Device sensitivity multiplier", risk - before, round(amplifier, 3), device_type)

        # FP-6 fix: risk velocity now requires n>=100 (matching calculate_zscore)
        # and velocity_z > 4 (raised from 3). It fired 19/27 times because
        # devices with as few as 30 samples had near-zero risk variance, so
        # any fluctuation looked like a huge spike. Combined with 2-3 other
        # small signals it pushed borderline devices over threshold.
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
            if velocity > 4:   # raised from 3 — requires a genuine spike
                bonus = min(velocity * 0.25, 1.0)   # also reduced from 0.3/1.5
                risk += bonus
                add("Risk velocity", bonus, round(velocity, 3), "Risk rose sharply above this device baseline")

        risk = min(risk, 10.0)
        factors.sort(key=lambda f: f["score"], reverse=True)
        return {"risk": round(risk, 3), "factors": factors}
