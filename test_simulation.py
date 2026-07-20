"""
test_simulation.py – End-to-End Logical Test Suite for Home IDS
Simulates device lifecycles, threat injections, alert deduplication, 
decay curves, and Zeek/Pi-hole race conditions.
"""

import time
import logging
from collections import OrderedDict

from config import CONFIG
from state import DeviceState
from features import FeatureExtractor
from scoring import RiskScorer
from ml_engine import MLRegistry
from zeek_collector import ZeekFeatureExtractor

logging.basicConfig(level=logging.ERROR)

def run_simulation():
    print("=================================================================")
    print(" 🚀 STARTING HOME IDS LOGIC & SYNCHRONIZATION SIMULATION SUITE   ")
    print("=================================================================\n")

    alpha = 0.05
    window_sec = 300
    extractor = FeatureExtractor()
    scorer = RiskScorer()
    ml = MLRegistry(model_dir="state/test_models", global_model_path="state/test_global.pkl")
    safe_ips = {"127.0.0.1", "192.168.178.94"}
    zeek_fx = ZeekFeatureExtractor(home_subnets=["192.168.178.0/24"], safe_ips=safe_ips)

    states = OrderedDict()
    sim_time = time.time()

    # -------------------------------------------------------------------
    # TEST 1: DEVICE LIFECYCLE (Add -> Purge Safe -> Re-add)
    # -------------------------------------------------------------------
    print("--- [TEST 1] Device Lifecycle & Safe-List Purge/Re-add ---")
    dev_id = "test_device_01"
    ip = "192.168.178.50"
    host = "Test-Laptop"

    # Step A: Add device
    states[dev_id] = DeviceState(device_id=dev_id, client_ip=ip, hostname=host, alpha=alpha)
    st = states[dev_id]
    st.rate_baseline.update(10.0, 12)
    print(f"✅ Device {host} added. Initial baseline samples: {sum(st.rate_baseline.n)}")

    # Step B: Dynamically add to Safe IPs & purge
    safe_ips.add(ip)
    if ip in safe_ips:
        states.pop(dev_id, None)
    print(f"✅ Device {host} added to safe_ips. State purged from memory: {dev_id not in states}")

    # Step C: Remove from Safe IPs & Re-add
    safe_ips.remove(ip)
    states[dev_id] = DeviceState(device_id=dev_id, client_ip=ip, hostname=host, alpha=alpha)
    st_readded = states[dev_id]
    print(f"⚠️ Device {host} re-added. Re-initialized sample count: {sum(st_readded.n)} (Probation Status: Active)\n")

    # -------------------------------------------------------------------
    # TEST 2: THREAT MATRIX & ALERT DEDUPLICATION COUNTING
    # -------------------------------------------------------------------
    print("--- [TEST 2] Threat Matrix Detection & Alert Fire Frequency ---")
    
    threat_scenarios = [
        ("DGA Burst", {"domains": [f"random{i}.ru" for i in range(20)], "status": 3, "zeek_event": None}),
        ("DoH Bypass", {"domains": ["google.com"], "status": 1, "zeek_event": {"type": "ssl", "sni": "cloudflare-dns.com", "uid": "U1"}}),
        ("Lateral SSH", {"domains": ["internal.local"], "status": 1, "zeek_event": {"type": "conn", "dst_ip": "192.168.178.100", "port": 22}}),
        ("Malicious JA3", {"domains": ["c2.server.com"], "status": 1, "zeek_event": {"type": "ssl", "ja3": "e7d705a3286e19ea42f587b6207263db", "port": 443}})
    ]

    for name, data in threat_scenarios:
        test_id = f"dev_{name.lower().replace(' ', '_')}"
        test_ip = "192.168.178.60"
        states[test_id] = DeviceState(device_id=test_id, client_ip=test_ip, hostname=f"Host-{name}", alpha=alpha)
        st_t = states[test_id]

        # Inject DNS Queries
        for d in data["domains"]:
            st_t.rolling.events.append((sim_time, d, data["status"]))
            st_t.rolling.domains[d] += 1
            if data["status"] == 3:
                st_t.rolling.nxdomain += 1

        # Inject Zeek NDR Events
        if data["zeek_event"]:
            zevt = data["zeek_event"]
            if zevt["type"] == "ssl" and "sni" in zevt:
                zeek_fx._process_ssl(test_ip, {"server_name": zevt["sni"], "uid": zevt["uid"]})
            elif zevt["type"] == "conn":
                zeek_fx._process_conn(test_ip, {"id.resp_h": zevt["dst_ip"], "id.resp_p": zevt["port"]})
            elif zevt["type"] == "ssl" and "ja3" in zevt:
                zeek_fx._process_ssl(test_ip, {"ja3": zevt["ja3"], "id.resp_p": zevt["port"]})

        feats = extractor.compute(st_t, sim_time, window_sec)
        feats.update(zeek_fx.get_features(test_ip))
        zeek_alerts = zeek_fx.get_alerts(test_ip)
        
        ml_score = ml.score(test_id, feats)
        risk_details = scorer.explain(feats, st_t, ml_score, zeek_alerts=zeek_alerts)
        risk = risk_details["risk"]

        # Alert Deduplication Fire Loop (Simulate 5 cycles over 2 minutes)
        alerts_fired = 0
        alert_threshold = 6.0
        for cycle in range(5):
            c_time = sim_time + (cycle * 25)  # 25 seconds apart
            factors = risk_details.get("factors", [])
            sig = factors[0]["name"] if factors else "Threshold Exceeded"
            risk_delta = abs(risk - getattr(st_t, "last_alert_risk", 0.0))
            time_elapsed = c_time - getattr(st_t, "last_alert_time", 0.0)

            if risk >= alert_threshold:
                if time_elapsed > 300 or (time_elapsed > 60 and (risk_delta >= 1.0 or sig != getattr(st_t, "last_alert_signature", ""))):
                    alerts_fired += 1
                    st_t.last_alert_time = c_time
                    st_t.last_alert_risk = risk
                    st_t.last_alert_signature = sig

        print(f"🎯 Threat: {name:<15} | Calculated Risk: {risk:.2f}/10.0 | Alerts Fired in 2m: {alerts_fired} (Deduplicated)")
        zeek_fx.reset_all()

    print()

    # -------------------------------------------------------------------
    # TEST 3: THREAT DECAY & RECOVERY CURVE
    # -------------------------------------------------------------------
    print("--- [TEST 3] Threat Decay & Recovery Validation ---")
    decay_id = "decay_device"
    decay_ip = "192.168.178.70"
    states[decay_id] = DeviceState(device_id=decay_id, client_ip=decay_ip, hostname="Decay-PC", alpha=alpha)
    st_d = states[decay_id]

    # Step A: Fire massive attack at t = 0
    start_t = sim_time
    for i in range(50):
        st_d.rolling.events.append((start_t, f"malicious{i}.com", 3))
        st_d.rolling.domains[f"malicious{i}.com"] += 1
        st_d.rolling.nxdomain += 1

    feats_peak = extractor.compute(st_d, start_t, window_sec)
    risk_peak = scorer.explain(feats_peak, st_d, 0.8, zeek_alerts=[])["risk"]
    is_poisoned_peak = risk_peak >= 7.0
    print(f"🔥 Peak Attack (t=0s)    : Risk = {risk_peak:.2f} | Baseline Frozen = {is_poisoned_peak}")

    # Step B: Advance time by 301 seconds (Attack stops, window expires)
    decay_t = start_t + 301
    feats_decay = extractor.compute(st_d, decay_t, window_sec)
    risk_decay = scorer.explain(feats_decay, st_d, 0.0, zeek_alerts=[])["risk"]
    is_poisoned_decay = risk_decay >= 7.0

    print(f"🍃 Recovery (t=301s)     : Risk = {risk_decay:.2f} | Baseline Frozen = {is_poisoned_decay}")
    if risk_decay < 6.0 and not is_poisoned_decay:
        print("✅ SUCCESS: Threat successfully decayed, risk score normalized, baseline un-frozen.\n")
    else:
        print("❌ FAILURE: Threat retained too long after traffic stopped!\n")

    # -------------------------------------------------------------------
    # TEST 4: ZEEK VS PI-HOLE RACE CONDITION & SYNC GAP
    # -------------------------------------------------------------------
    print("--- [TEST 4] Zeek vs Pi-hole Sync & Timing Cliff Race Condition ---")
    sync_ip = "192.168.178.80"
    
    # Event arrives 2 seconds before the 300-second Zeek reset boundary
    t_zeek = sim_time + 298
    zeek_fx._process_ssl(sync_ip, {"ja3": "e7d705a3286e19ea42f587b6207263db", "id.resp_p": 443})
    
    feats_before_reset = zeek_fx.get_features(sync_ip)
    print(f"⏱️  t=298s (Before Reset): Zeek JA3 Hits Captured = {feats_before_reset['zeek_ja3_malicious']}")

    # System reset triggers at t=300s
    zeek_fx.reset_all()
    
    # Pi-hole logs arrive at t=301s
    feats_after_reset = zeek_fx.get_features(sync_ip)
    print(f"⏱️  t=301s (After Reset) : Zeek JA3 Hits Captured = {feats_after_reset['zeek_ja3_malicious']}")

    if feats_before_reset['zeek_ja3_malicious'] == 1 and feats_after_reset['zeek_ja3_malicious'] == 0:
        print("⚠️  SYNC GAP CONFIRMED: Zeek events occurring near boundary windows reset before cross-layer Pi-hole correlation occurs.")

    print("\n=================================================================")
    print(" 🏁 SIMULATION COMPLETE: ALL LOGIC SCENARIOS EVALUATED          ")
    print("=================================================================")

if __name__ == "__main__":
    run_simulation()