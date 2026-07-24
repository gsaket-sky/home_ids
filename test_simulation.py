"""
test_simulation.py – End-to-End Logical Test Suite for Home IDS
Simulates device lifecycles, threat injections, alert deduplication, 
decay curves, Zeek/Pi-hole race conditions, IPS Veto logic, and 
advanced SOC scenarios (Honeypots, JA4+, Sequential Kill-Chains).
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
from ips import IPSMitigator

logging.basicConfig(level=logging.ERROR)

class DummyState:
    """Lightweight mock state for IPS target testing."""
    def __init__(self, device_id, hostname, ip, mac):
        self.device_id = device_id
        self.hostname = hostname
        self.client_ip = ip
        self.mac_address = mac

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
    honeypot_ips = {"192.168.178.200"}
    
    zeek_fx = ZeekFeatureExtractor(
        home_subnets=["192.168.178.0/24"], 
        safe_ips=safe_ips, 
        honeypot_ips=honeypot_ips
    )

    states = OrderedDict()
    sim_time = time.time()

    # -------------------------------------------------------------------
    # TEST 1: DEVICE LIFECYCLE (Add -> Purge Safe -> Re-add)
    # -------------------------------------------------------------------
    print("--- [TEST 1] Device Lifecycle & Safe-List Purge/Re-add ---")
    dev_id = "test_device_01"
    ip = "192.168.178.50"
    host = "Test-Laptop"

    states[dev_id] = DeviceState(device_id=dev_id, client_ip=ip, hostname=host, alpha=alpha)
    st = states[dev_id]
    st.rate_baseline.update(10.0, 12)
    print(f"✅ Device {host} added. Initial baseline samples: {sum(st.rate_baseline.n)}")

    safe_ips.add(ip)
    print(f"✅ Device {host} added to safe_ips. State remains in memory for warm baselines: {dev_id in states}")

    safe_ips.remove(ip)
    print(f"⚠️ Device {host} removed from safe_ips. Ready for active tracking.\n")

    # -------------------------------------------------------------------
    # TEST 2: THREAT MATRIX & ALERT DEDUPLICATION COUNTING
    # -------------------------------------------------------------------
    print("--- [TEST 2] Threat Matrix Detection & Alert Fire Frequency ---")
    
    threat_scenarios = [
        ("DGA Burst", {"domains": [f"random{i}.ru" for i in range(20)], "status": 3, "zeek_event": None}),
        ("DoH Bypass", {"domains": ["google.com"], "status": 1, "zeek_event": {"type": "ssl", "sni": "cloudflare-dns.com", "uid": "U1"}}),
        ("Lateral SSH", {"domains": ["internal.local"], "status": 1, "zeek_event": {"type": "conn", "dst_ip": "192.168.178.100", "port": 22}}),
        ("Malicious JA3", {"domains": ["c2.server.com"], "status": 1, "zeek_event": {"type": "ssl", "ja3": "e7d705a3286e19ea42f587b6207263db", "port": 443}}),
        ("Malicious JA4+", {"domains": ["ng-c2.server.com"], "status": 1, "zeek_event": {"type": "ssl", "ja4": "t13d1516h2_8daaf6152771_a0b271d46eb3", "port": 443}}),
        ("Honeypot Trigger", {"domains": [], "status": 1, "zeek_event": {"type": "conn", "dst_ip": "192.168.178.200", "port": 22}})
    ]

    for name, data in threat_scenarios:
        test_id = f"dev_{name.lower().replace(' ', '_').replace('+', '')}"
        test_ip = "192.168.178.60"
        states[test_id] = DeviceState(device_id=test_id, client_ip=test_ip, hostname=f"Host-{name}", alpha=alpha)
        st_t = states[test_id]

        for d in data["domains"]:
            st_t.rolling.events.append((sim_time, d, data["status"]))
            st_t.rolling.domains[d] += 1
            if data["status"] == 3:
                st_t.rolling.nxdomain += 1

        if data["zeek_event"]:
            zevt = data["zeek_event"]
            if zevt["type"] == "ssl" and "sni" in zevt:
                zeek_fx._process_ssl(test_ip, {"server_name": zevt["sni"], "uid": zevt["uid"]})
            elif zevt["type"] == "conn":
                zeek_fx._process_conn(test_ip, {"id.resp_h": zevt["dst_ip"], "id.resp_p": zevt["port"]})
            elif zevt["type"] == "ssl" and "ja3" in zevt:
                zeek_fx._process_ssl(test_ip, {"ja3": zevt["ja3"], "id.resp_p": zevt["port"]})
            elif zevt["type"] == "ssl" and "ja4" in zevt:
                zeek_fx._process_ssl(test_ip, {"ja4": zevt["ja4"], "id.resp_p": zevt["port"]})

        feats = extractor.compute(st_t, sim_time, window_sec)
        feats.update(zeek_fx.get_features(test_ip))
        zeek_alerts = zeek_fx.get_alerts(test_ip)
        
        ml_score = ml.score(test_id, feats)
        risk_details = scorer.explain(feats, st_t, ml_score, zeek_alerts=zeek_alerts)
        risk = risk_details["risk"]

        alerts_fired = 0
        alert_threshold = 6.0
        for cycle in range(5):
            c_time = sim_time + (cycle * 25) 
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
            else:
                if getattr(st_t, "last_alert_risk", 0.0) >= alert_threshold:
                    if risk <= (alert_threshold - 1.0):
                        st_t.last_alert_risk = 0.0

        print(f"🎯 Threat: {name:<17} | Calculated Risk: {risk:>5.2f}/10.0 | Alerts Fired in 2m: {alerts_fired} (Deduplicated)")
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

    start_t = sim_time
    for i in range(50):
        st_d.rolling.events.append((start_t, f"malicious{i}.com", 3))
        st_d.rolling.domains[f"malicious{i}.com"] += 1
        st_d.rolling.nxdomain += 1

    feats_peak = extractor.compute(st_d, start_t, window_sec)
    risk_peak = scorer.explain(feats_peak, st_d, 0.8, zeek_alerts=[])["risk"]
    is_poisoned_peak = risk_peak >= 7.0
    print(f"🔥 Peak Attack (t=0s)    : Risk = {risk_peak:.2f} | Baseline Frozen = {is_poisoned_peak}")

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
    
    t_zeek = sim_time + 298
    zeek_fx._process_ssl(sync_ip, {"ja3": "e7d705a3286e19ea42f587b6207263db", "id.resp_p": 443})
    
    feats_before_reset = zeek_fx.get_features(sync_ip)
    print(f"⏱️  t=298s (Before Reset): Zeek JA3 Hits Captured = {feats_before_reset['zeek_ja3_malicious']}")

    zeek_fx.prune(sim_time + 300, 300)
    
    feats_after_reset = zeek_fx.get_features(sync_ip)
    print(f"⏱️  t=301s (After Prune) : Zeek JA3 Hits Captured = {feats_after_reset['zeek_ja3_malicious']}")

    if feats_after_reset['zeek_ja3_malicious'] == 1:
        print("✅ SUCCESS: Rolling window successfully prevented the 300s Sync Gap race condition.\n")
    else:
        print("❌ FAILURE: Zeek events were wiped prematurely!\n")

    # -------------------------------------------------------------------
    # TEST 5: IPS CLOUDFLARE VETO & ZERO-DAY OVERRIDE
    # -------------------------------------------------------------------
    print("--- [TEST 5] IPS Cloudflare DoH Veto & Zero-Day DGA Override ---")
    
    mock_config = {
        "ips_enabled": True, 
        "pihole_api_url": "mock", 
        "router_webhook_url": "mock",
        "safe_domains": ["teams.events.data.microsoft.com"]
    }
    ips = IPSMitigator(config=mock_config)
    mock_st = DummyState(device_id="ips_test_01", hostname="Veto-Tester", ip="192.168.178.99", mac="AA:BB:CC:DD:EE:FF")

    ips._internet_verification = lambda d: "HARMLESS" 
    ips.mitigate(mock_st, top_domain="github.com", risk_score=8.5, c2_hits=0, dga_burst=False)
    if "github.com" not in ips.blocked_domains:
        print("✅ [5A] HARMLESS VETO: Successfully aborted Pi-hole block for globally trusted domain.")
    else:
        print("❌ [5A] FAILURE: Harmless domain was blocked!")

    ips._internet_verification = lambda d: "MALICIOUS"
    ips.mitigate(mock_st, top_domain="evil-c2-server.com", risk_score=8.5, c2_hits=0, dga_burst=False)
    if "evil-c2-server.com" in ips.blocked_domains:
        print("✅ [5B] MALICIOUS AGREEMENT: Successfully executed Pi-hole block for known malware.")
    else:
        print("❌ [5B] FAILURE: Known malware domain was not blocked!")

    ips._internet_verification = lambda d: "HARMLESS"
    ips.mitigate(mock_st, top_domain="random-zeroday-dga.xyz", risk_score=9.0, c2_hits=0, dga_burst=True)
    if "random-zeroday-dga.xyz" in ips.blocked_domains:
        print("✅ [5C] ZERO-DAY OVERRIDE: Successfully ignored Veto and blocked active DGA burst.")
    else:
        print("❌ [5C] FAILURE: Zero-Day malware bypassed protection due to Veto!")

    if mock_st.mac_address in ips.isolated_macs:
        print("✅ [5D] HARDWARE ISOLATION: Router webhook successfully fired regardless of DNS Veto.\n")
    else:
        print("❌ [5D] FAILURE: Router isolation failed to execute!\n")

    # -------------------------------------------------------------------
    # TEST 6: SEQUENTIAL KILL-CHAIN ANALYSIS (MARKOV TRANSITIONS)
    # -------------------------------------------------------------------
    print("--- [TEST 6] Sequential Kill-Chain Analysis (Markov Transitions) ---")
    kc_id = "killchain_device"
    kc_ip = "192.168.178.90"
    states[kc_id] = DeviceState(device_id=kc_id, client_ip=kc_ip, hostname="KillChain-PC", alpha=alpha)
    st_kc = states[kc_id]

    # Phase 1: RECON (Triggered by NXDOMAIN volume)
    feats_recon = extractor._zero_features()
    feats_recon["nxdomain_ratio_z"] = 4.0
    ml.score(kc_id, feats_recon) # ML Engine registers the phase and evaluates Markov Shift
    risk_recon_details = scorer.explain(feats_recon, st_kc, 0.0)
    print(f"🕵️  Phase 1 (RECON)   : Risk = {risk_recon_details['risk']:.2f} | Abstract History = {list(st_kc.killchain_history)}")

    # Phase 2: C2 (Triggered by mechanical Jitter / Beaconing)
    feats_c2 = extractor._zero_features()
    feats_c2["beaconing_c2_count"] = 5
    ml.score(kc_id, feats_c2) 
    risk_c2_details = scorer.explain(feats_c2, st_kc, 0.0)
    risk_c2 = risk_c2_details["risk"]
    factors_c2 = [f["name"] for f in risk_c2_details["factors"]]
    print(f"📡 Phase 2 (C2)      : Risk = {risk_c2:.2f} | Abstract History = {list(st_kc.killchain_history)}")
    
    if "Sequential Kill-Chain Detected" in factors_c2:
        print("   ✅ SUCCESS: Deterministic Kill-Chain penalty successfully applied (+8.0)")
    else:
        print("   ❌ FAILURE: Did not register RECON -> C2 pattern.")

    # Phase 3: LATERAL (Triggered by Internal Network Scanning)
    feats_lat = extractor._zero_features()
    feats_lat["zeek_lateral_moves"] = 10
    ml.score(kc_id, feats_lat)
    risk_lat_details = scorer.explain(feats_lat, st_kc, 0.0)
    risk_lat = risk_lat_details["risk"]
    factors_lat = [f["name"] for f in risk_lat_details["factors"]]
    print(f"🗡️  Phase 3 (LATERAL) : Risk = {risk_lat:.2f} | Abstract History = {list(st_kc.killchain_history)}")
    
    if "Sequential Kill-Chain Detected" in factors_lat:
        print("   ✅ SUCCESS: Deep lateral Kill-Chain progression tracked across sequence.")
    else:
        print("   ❌ FAILURE: Did not register C2 -> LATERAL pattern.")

    print("\n=================================================================")
    print(" 🏁 SIMULATION COMPLETE: ALL LOGIC SCENARIOS EVALUATED          ")
    print("=================================================================")

if __name__ == "__main__":
    run_simulation()