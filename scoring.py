"""
scoring.py - Risk scoring engine.

Keeps IDS scoring explainable: compute() returns the numeric risk, while
explain() returns the same risk plus the factors that contributed to it.

RECENT FIXES:
- Decoupled strict network telemetry (Zeek/NDR) from DNS volume dampeners.
- Enforced hard limits on all dynamically inserted string variables to prevent Loki indexing explosion.
- Elevated absolute threat matrices (JA3, Jitter, Lateral Moves, Exfiltration) above the 6.0 IPS trigger threshold.
- Re-architected C2 Beaconing to catch "Low-and-Slow" intervals, bypassing the volume dampener.
- Eliminated total infrastructure suppression blind spot. Absolute/deterministic threats
  are now fully monitored on routers, gateways, and DNS servers while skipping soft volume noise.
- ADDED (FEATURE): Integrated TCP Port Scan (S0/REJ) detection rules with immediate IPS trigger ceilings.
- ADDED (FEATURE): Integrated Covert Tunnel / Reverse Shell rules based on extended session durations.
- ADDED (SOC): Integrated Deception Technology (Honeypot) unmitigable 10.0 risk penalties.
- ADDED (SOC): Integrated Next-Gen Cryptography (JA4+) isolation penalties.
- ADDED (SOC): Built deterministic Sequential Kill-Chain logic evaluating Markov phase shifts.
"""
from utils import is_telemetry_domain
import math
import logging

LOGGER = logging.getLogger("home_ids.scoring")

def safe_float(v, default: float = 0.0) -> float:
    """Safely coerces metrics to floats, averting silent math exceptions during AI evaluation."""
    try:
        return float(v) if v is not None else default
    except Exception:
        return default

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
    def compute(self, features: dict, state, ml_score: float, zeek_alerts: list = None) -> float:
        """Returns only the final numeric risk score."""
        return self.explain(features, state, ml_score, zeek_alerts)["risk"]

    def explain(self, features: dict, state, ml_score: float, zeek_alerts: list = None) -> dict:
        """Computes the full risk score alongside contextual explanations for the alert JSON payload."""
        factors = []
        LOGGER.debug("Evaluating Risk Engine profile for %s (ML Score: %.4f)", getattr(state, "hostname", "unknown"), ml_score)

        def add(name: str, score: float, value=None, detail: str = "") -> None:
            """Injects a calculated risk penalty into the device's ledger."""
            score = safe_float(score, 0.0)
            if score <= 0:
                return
            factors.append({
                "name": name, "score": round(score, 3), "value": value, "detail": detail,
            })

        device_type = getattr(state, "device_type", None) or "unknown"
        is_mobile = device_type in ["phone", "tablet"]
        mobile_dampener = 0.2 if is_mobile else 1.0
        
        sens = _DEVICE_SENSITIVITY.get(device_type, 1.0)
        is_infra = (sens <= 0.0)
        amplifier = min(1.0 / max(sens, 0.1), 1.25) if not is_infra else 1.0

        # =====================================================================
        # KILL-CHAIN SEQUENCE EXTRACTION & EVALUATION
        # =====================================================================
        phase = features.get("killchain_phase", "NORMAL")
        markov_anomaly = safe_float(features.get("markov_anomaly", 0.0))

        if phase != "NORMAL":
            if not hasattr(state, "killchain_history"):
                state.killchain_history = __import__('collections').deque(maxlen=5)
            
            # Avoid spamming sequential entries if the device stays in the same phase
            if not state.killchain_history or state.killchain_history[-1] != phase:
                state.killchain_history.append(phase)
                LOGGER.warning("Device %s entered anomalous Kill-Chain phase: %s", getattr(state, "hostname", "unknown"), phase)

        history = list(getattr(state, "killchain_history", []))
        
        if len(history) >= 2:
            # Deterministic Kill-Chain Paths
            seq = " -> ".join(history[-3:])
            if "RECON -> C2" in seq or "C2 -> EXFIL" in seq or "C2 -> LATERAL" in seq:
                add("Sequential Kill-Chain Detected", 8.0, None, f"Deterministic sequence execution pattern matched: {seq}")

        if markov_anomaly > 0.95 and phase != "NORMAL":
            add("Anomalous Phase Transition (Markov)", 3.0, round(markov_anomaly, 2), f"Highly irregular behavioral phase shift to {phase} (P < 0.05)")


        # 1. Feature Extraction & Coercion
        qz   = safe_float(features.get("query_rate_z"), 0.0)
        ez   = safe_float(features.get("entropy_z"), 0.0)
        uz   = safe_float(features.get("unique_domains_z"), 0.0)
        text_nx_z = safe_float(features.get("nxdomain_ratio_z"), 0.0)
        bl_z = safe_float(features.get("blocked_ratio_z"), 0.0)
        sd_z = safe_float(features.get("suspicious_domains_z"), 0.0)
        
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

        volume_dampener = 1.0 if total >= 100.0 else max(0.1, total / 100.0)

        st_domains = getattr(state.rolling, "domains", {}) if hasattr(state, "rolling") else {}
        top_domain = max(st_domains, key=st_domains.get, default=None) if st_domains else None

        top_domain_is_familiar = bool(features.get("top_domain_is_familiar", False))
        if top_domain_is_familiar and tdr > 0.50:
            context_dampener = 0.35
            context_detail = " (Dampened: spike maps to familiar historical domain)"
        else:
            context_dampener = 1.0
            context_detail = ""

        is_telemetry = bool(top_domain and is_telemetry_domain(top_domain))

        rate_baseline_n = sum(getattr(state.rate_baseline, "n", [0, 0])) if hasattr(state, "rate_baseline") else 0
        is_on_probation = (rate_baseline_n < 288)

        # =====================================================================
        # HEURISTIC DNS SCORING (Suppressed on infrastructure to avoid noise)
        # =====================================================================
        if not is_infra:
            if is_on_probation:
                if total > 100 and unique_domains > 40:
                    add("Probationary volume ceiling breach", 3.5 * context_dampener, total, f"Unverified new device generating high density out-of-the-box query volumes{context_detail}")
                if nx > 0.40 and not is_telemetry:
                    add("Probationary NXDOMAIN absolute breach", 3.0 * context_dampener, round(nx, 3), f"Unverified new device generating high absolute failure rates{context_detail}")
                if nd > 15 and not is_telemetry:
                    add("Probationary unmapped infrastructure flood", 2.5 * context_dampener, nd, f"Device contacting substantial unique external targets on first run{context_detail}")
            
            nd_ratio = nd / max(unique_domains, 1.0)
            dd_ratio = dd / max(unique_domains, 1.0)

            z_parts = []
            z_score_count = sum([qz > 3.0, ez > 3.0, uz > 3.0])

            if qz > 3.0: z_parts.append(f"query_rate_z={qz:.2f}")
            if ez > 3.0: z_parts.append(f"entropy_z={ez:.2f}")
            if uz > 3.0: z_parts.append(f"unique_domains_z={uz:.2f}")
            if nx > 0.3 and text_nx_z > 3.0 and not is_telemetry: z_parts.append(f"nxdomain_ratio={nx:.2f}(Z={text_nx_z:.1f})")
            if bl > 0.7 and bl_z > 3.0 and nx > 0.15: z_parts.append(f"blocked_ratio={bl:.2f}(Z={bl_z:.1f})")

            abs_count = sum([
                nx > 0.3 and text_nx_z > 3.0 and not is_telemetry,
                bl > 0.7 and bl_z > 3.0 and nx > 0.15,
            ])
            dns_anomaly_count = z_score_count + abs_count

            if z_score_count >= 1 and dns_anomaly_count >= 2:
                add("Correlated DNS baseline deviation", 3.0 * volume_dampener * context_dampener, None, ", ".join(z_parts) + context_detail)
                
            if not is_on_probation:
                if nx > 0.35 and text_nx_z > 3.0 and not is_telemetry:
                    add("NXDOMAIN ratio deviation", (nx - 0.35) * 4 * volume_dampener * context_dampener, round(nx, 3), f"Failed lookups deviating from profile{context_detail}")
                if bl > 0.85 and bl_z > 3.0 and nx > 0.2:
                    add("Blocked DNS ratio deviation", (bl - 0.85) * 4 * volume_dampener * context_dampener, round(bl, 3), f"Extreme block evasion behavior (Z={bl_z:.2f}){context_detail}")
                if sd > 0 and sd_z > 3.0:
                    if is_telemetry:
                        LOGGER.debug("Suppressed DGA penalty for known SDK domain: %s", top_domain)
                        add("Telemetry SDK activity (Suppressed)", 0.0, sd, "Known background analytics SDK")
                    else:
                        add("Suspicious/DGA-like domains", min(sd, 10) * 0.4 * volume_dampener * context_dampener * mobile_dampener, sd, f"Heuristic matches verified by anomaly spike (Z={sd_z:.2f}){context_detail}")

            if nd_ratio > 0.25 and total >= 30 and not is_telemetry:
                add("First-seen domain burst", min(nd_ratio * 4.0, 2.0) * volume_dampener, round(nd_ratio, 3), f"New infrastructure share expansion ({int(nd)} domains)")

            if dd_ratio > 0.10 and total >= 30 and not is_telemetry:
                add("Deep DNS structures", min(dd_ratio * 4.0, 2.0) * volume_dampener, round(dd_ratio, 3), f"Deep subdomains share expansion ({int(dd)} domains)")

            if tc > 0.7 and nx > 0.2 and text_nx_z > 3.0 and not is_telemetry:
                add("NXDOMAIN TLD concentration", (tc - 0.7) * 5 * volume_dampener * context_dampener, round(tc, 3), f"Failures concentrated in anomalous TLD structure{context_detail}")

            # Low-and-Slow C2 Beaconing Heuristics
            beacon_score = 0.0
            if total >= 5:
                if tdr > 0.95: 
                    beacon_score = 3.5
                elif tdr > 0.85 and total >= 10: 
                    beacon_score = 2.5
                elif tdr > 0.75 and total >= 15: 
                    beacon_score = 1.5
            
            if is_telemetry:
                beacon_score *= 0.1
                
            add("Persistent single-target beaconing", beacon_score * context_dampener, round(tdr, 3), f"Concentrated tracking (total_queries={int(total)}){context_detail}")

        # Unsupervised Machine Learning Matrices
        if ml_score > 0.02 and not is_infra:
            if is_on_probation:
                ml_penalty = min(ml_score * 80.0, 5.0)
                add("ML absolute structural outlier (Probationary)", ml_penalty, round(ml_score, 4), "Device structure severely contradicts global home network cluster parameters")
            else:
                add("ML anomaly matrix alert", min(ml_score * 40.0, 4.0), round(ml_score, 4), "Per-device IsolationForest anomaly margin")

        # =====================================================================
        # DETERMINISTIC INTEL & THREAT FEEDS (Always evaluated everywhere)
        # =====================================================================
        ti_risk = safe_float(features.get("ti_risk", 0.0), 0.0)
        add("Threat intelligence IOC", min(ti_risk, 4.0), round(ti_risk, 3), "Domain or IP matched loaded IOC feeds")

        abuse_risk = safe_float(features.get("abuseipdb_risk", 0.0), 0.0)
        add("AbuseIPDB blacklist", min(abuse_risk, 4.0), round(abuse_risk, 3), "Destination IP appears in AbuseIPDB blacklist")

        vt_risk = safe_float(features.get("vt_risk", 0.0), 0.0)
        add("VirusTotal detection", min(vt_risk, 4.0), round(vt_risk, 3), "Cached VirusTotal result is suspicious or malicious")

        # =====================================================================
        # HARD CORE NETWORK TELEMETRY (ZEEK / NDR) - ABSOLUTE TRUTHS
        # =====================================================================

        outbound_bytes_z = safe_float(features.get("outbound_bytes_z", 0.0), 0.0)
        if outbound_bytes_z > 5.0:
            LOGGER.warning("Exfiltration spike factored for %s (Z=%.2f)", getattr(state, "hostname", "unknown"), outbound_bytes_z)
            add("Exfiltration Payload Burst", 6.5, round(outbound_bytes_z, 2), f"Massive outbound data anomaly severely breaking distribution bounds (Z: {outbound_bytes_z:.2f})")
        elif outbound_bytes_z > 3.5:
            add("Anomalous Outbound Traffic", 4.0, round(outbound_bytes_z, 2), f"Elevated outbound data (Z: {outbound_bytes_z:.2f})")

        lateral_moves_count = safe_float(features.get("zeek_lateral_moves", 0), 0.0)
        if lateral_moves_count > 0:
            LOGGER.warning("Internal Lateral Movement factored for %s", getattr(state, "hostname", "unknown"))
            add("Internal Lateral Movement", 7.0, min(lateral_moves_count, 1000), f"Device scanning internal restricted ports ({int(lateral_moves_count)} hits)")

        zeek_ja3 = safe_float(features.get("zeek_ja3_malicious", 0), 0.0)
        if zeek_ja3 > 0 and not zeek_alerts:
            LOGGER.critical("JA3 Malicious signature factored into risk score for %s", getattr(state, "hostname", "unknown"))
            add("Malicious TLS Fingerprint (JA3)", 7.0, min(zeek_ja3, 100), f"Known malware cryptographic handshake ({int(zeek_ja3)} hits)")
            
        zeek_ja4 = safe_float(features.get("zeek_ja4_malicious", 0), 0.0)
        if zeek_ja4 > 0:
            LOGGER.critical("JA4+ Malicious signature factored into risk score for %s", getattr(state, "hostname", "unknown"))
            add("Malicious TLS Fingerprint (JA4+)", 7.5, min(zeek_ja4, 100), f"Next-Gen malware cryptographic handshake ({int(zeek_ja4)} hits)")

        doh_bypass_count = safe_float(features.get("zeek_doh_bypass", 0), 0.0)
        if doh_bypass_count > 0:
            LOGGER.warning("DoH bypass factored for %s", getattr(state, "hostname", "unknown"))
            add("DoH Tunneling / Evasion", 5.0, min(doh_bypass_count, 100), f"Direct upstream encrypted DNS bypass ({int(doh_bypass_count)} hits)")

        zeek_ports = safe_float(features.get("zeek_susp_ports", 0), 0.0)
        if zeek_ports > 0:
            add("Suspicious destination port", 3.0, min(zeek_ports, 100), f"Connecting to non-standard external ports ({int(zeek_ports)} hits)")

        c2_jitter_count = safe_float(features.get("beaconing_c2_count", 0), 0.0)
        if c2_jitter_count > 0:
            add("C2 Jitter Clock Verification", 6.0, min(c2_jitter_count, 100), f"Uniform periodicity check-in sequences tracked ({int(c2_jitter_count)} hits)")

        s0_rej = safe_float(features.get("zeek_s0_rej_count", 0), 0.0)
        if s0_rej > 50:
            LOGGER.warning("Active TCP Port Scan factored for %s", getattr(state, "hostname", "unknown"))
            add("TCP Port Scan (S0/REJ)", 7.5, min(s0_rej, 5000), f"Massive volume of rejected/unanswered connections ({int(s0_rej)} hits)")
        elif s0_rej > 15:
            add("Suspicious Connection Failures", 3.5, min(s0_rej, 5000), f"Elevated rejected/unanswered connections ({int(s0_rej)} hits)")

        max_dur = safe_float(features.get("zeek_max_duration", 0), 0.0)
        if max_dur > 43200: 
            LOGGER.warning("Persistent long-lived connection factored for %s", getattr(state, "hostname", "unknown"))
            add("Covert Tunnel / Reverse Shell", 6.5, round(max_dur, 1), f"Extremely long connection duration ({int(max_dur)}s)")
        elif max_dur > 14400: 
            add("Long-lived Connection", 3.0, round(max_dur, 1), f"Suspiciously long session duration ({int(max_dur)}s)")

        honeypot_hits = safe_float(features.get("zeek_honeypot_hits", 0), 0.0)
        if honeypot_hits > 0:
            LOGGER.critical("HONEYPOT DECEPTION TRIGGERED by %s", getattr(state, "hostname", "unknown"))
            add("Honeypot Deception Triggered", 10.0, honeypot_hits, f"Device accessed an internal restricted decoy listener ({int(honeypot_hits)} hits)")

        # =====================================================================
        # ZEEK ANOMALY SIGNATURES
        # =====================================================================
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
                elif atype == "malicious_ja4":
                    add("Zeek malicious JA4+ alert", conf * 6.0, alert.get("ja4", ""), alert.get("server", ""))
                elif atype == "zeek_notice":
                    note = alert.get("note", "")
                    if note in _BENIGN_ZEEK_WEIRD:
                        continue   
                    zeek_notice_total += conf * 1.5
            
            capped_notice = min(zeek_notice_total, 2.0)
            if capped_notice > 0:
                add("Zeek notice", capped_notice, None, "Zeek protocol anomaly (capped)")

        # =====================================================================
        # SCORE AGGREGATION & SENSITIVITY MODIFIERS
        # =====================================================================
        risk = sum(f["score"] for f in factors)
        
        if amplifier != 1.0 and risk > 0 and not is_infra:
            before = risk
            risk *= amplifier
            add("Device sensitivity multiplier", risk - before, round(amplifier, 3), device_type)

        risk_baseline = getattr(state, "risk_baseline", None)
        if risk_baseline and not is_infra:
            current_hour = int(features.get("current_hour", 12))
            mean, var, init, n = risk_baseline.get_stats(current_hour)
            if init and n >= 50:
                import math as _math
                _std = _math.sqrt(max(var, 1e-4))
                velocity = (risk - mean) / _std
                if velocity > 4.0:   
                    bonus = min(velocity * 0.25, 1.0)   
                    risk += bonus
                    add("Risk velocity", bonus, round(velocity, 3), f"Risk rose sharply above typical hourly index (Z={velocity:.2f})")

        risk = min(risk, 10.0)
        factors.sort(key=lambda f: f["score"], reverse=True)
        return {"risk": round(risk, 3), "factors": factors}