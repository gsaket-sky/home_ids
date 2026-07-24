# Home IDS: Enterprise SOC Architecture Roadmap

This document outlines the strategic roadmap for evolving the Home IDS engine from a lightweight Network Detection & Response (NDR) tool into a professional-grade, automated Security Operations Center (SOC) ecosystem.

---

## Phase 1: Advanced Network Enforcement

### 1. Dynamic Micro-Segmentation (Quarantine VLANs)
*   **Current State:** The router webhook issues a hard network drop (`action: isolate`), completely severing the infected device.
*   **Target Architecture:** Network Access Control (NAC) API integration (e.g., Unifi, Omada).
*   **Implementation:** Update `ips.py` to instruct the switch/AP to bounce the client's MAC address and reassign it to a restricted "Quarantine VLAN." 
*   **Value:** Prevents lateral movement while keeping the device accessible to the admin subnet for forensic investigation and malware removal.

### 2. True Inline IPS (Stateful Packet Inspection)
*   **Current State:** Out-of-band mitigation. Zeek/Pi-hole detects the threat post-facto, and `ips.py` blocks subsequent traffic.
*   **Target Architecture:** Inline packet dropping via NFQ (Netfilter Queue).
*   **Implementation:** Deploy **Suricata** or **Snort** inline on the gateway. Have `main.py` dynamically inject block rules into the Suricata engine to drop malicious packets natively at the kernel level before they leave the network.

---

## Phase 2: Telemetry & Endpoint Expansion

### 3. XDR Expansion (Endpoint Integration)
*   **Current State:** NDR-only. The system knows *which* device generated malicious traffic, but not *what* process caused it.
*   **Target Architecture:** Integration with Open-Source EDR (Endpoint Detection & Response).
*   **Implementation:** Deploy **Wazuh** or **Osquery** agents on laptops/desktops. When `main.py` detects an NDR anomaly, it queries the EDR API to identify the specific PID/executable generating the sockets.
*   **Value:** Eliminates the guesswork between malware and legitimate background updaters.

### 4. Next-Gen Cryptographic Fingerprinting (JA4)
*   **Current State:** Zeek utilizes JA3 for TLS fingerprinting.
*   **Target Architecture:** Upgrade to JA4.
*   **Implementation:** Update the Zeek deployment and `ZeekFeatureExtractor` to utilize the **JA4+** suite. 
*   **Value:** JA3 is becoming obsolete due to TLS 1.3 and Encrypted Client Hello (ECH). JA4 provides resilient application fingerprinting despite modern encryption standard changes.

---

## Phase 3: Advanced Detection & Analytics

### 5. Deception Technology (Honeypots)
*   **Current State:** Lateral movement is detected via statistical baselines, which can trigger false positives during legitimate network administration.
*   **Target Architecture:** Active Deception.
*   **Implementation:** Deploy a lightweight honeypot (e.g., Thinkst Canary, or a Python fake SMB/SSH listener) on a spare IP address. Hardcode the ML engine to assign an immediate `10.0` Risk Score to any device that attempts to connect to it.
*   **Value:** Near-zero false positives. Any lateral scan hitting a hidden, dummy file share is definitive proof of an active worm, scanner, or ransomware infection.

### 6. Retroactive Threat Hunting (Zero-Day Sweeping)
*   **Current State:** Threat Intel feeds (VirusTotal, OTX, AbuseIPDB) evaluate traffic in real-time.
*   **Target Architecture:** Historical IOC correlation.
*   **Implementation:** Build a standalone chron job (`retro_hunter.py`) that downloads newly flagged IOCs daily and sweeps them against the historical Pi-hole and Zeek logs from the past 14-30 days.
*   **Value:** Detects Zero-Day compromises where a device communicated with a domain *before* the global security community recognized it as malicious.

### 7. Sequential Kill-Chain Analysis (LSTM ML)
*   **Current State:** Isolation Forests evaluate the *volume* and *variance* of traffic features.
*   **Target Architecture:** Time-Series Sequence Modeling.
*   **Implementation:** Train a secondary Long Short-Term Memory (LSTM) network or Markov Chain to evaluate the *order* of events (e.g., `DNS TXT Query` $\rightarrow$ `Small HTTPS Beacon` $\rightarrow$ `Large TCP Download` $\rightarrow$ `Internal Port Scan`).
*   **Value:** Identifies sophisticated, low-and-slow malware that evades volumetric threshold alerts by mimicking human traffic speeds.