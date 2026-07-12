🛡️ Home SOC IDS: AI-Powered Network Defense
A lightweight, stateful, real-time Intrusion Detection System (IDS) designed specifically to secure home networks. By fusing DNS telemetry from Pi-hole with network flow data from Zeek, this engine builds highly accurate, behavioral machine learning models for every individual device on your network.

Instead of relying solely on static blocklists, this system learns what "normal" looks like for your smart TV, your laptop, and your IoT devices, and mathematically hunts for deviations indicating zero-day malware, C2 beaconing, or data exfiltration.

🚀 Key Features
Real-Time SQLite WAL Parsing: Ingests DNS events directly from the Pi-hole database (FTL) every 2 seconds without locking or slowing down your local DNS resolution.

Zeek Protocol Integration: Monitors conn.log, notice.log, and weird.log to catch malware that bypasses DNS entirely using direct IP connections or malicious TLS handshakes (JA3 fingerprinting).

Diurnal Machine Learning: Uses Scikit-Learn's IsolationForest to build distinct Day (06:00–22:00) and Night (22:00–06:00) behavioral models for every device.

Dynamic Safe Corridors (Z-Scores): Replaces static global thresholds with per-device standard deviations, preventing high-volume devices (like streaming boxes) from generating false positives.

Day-Zero Peer Clustering: Safely evaluates brand-new devices by temporarily grading them against the established baselines of similar device types (e.g., IoT, Mobile) while they build their own history.

Anti-Poisoning Memory Guard: Automatically freezes baseline learning if a device breaches severe threat thresholds, ensuring the ML engine never learns malware behavior as "normal."

🦠 Threat Detection Capabilities
Ransomware & DGA Families: Detects Domain Generation Algorithms through a combination of NXDOMAIN ratios, unique domain bursts, high Shannon entropy, and TLD concentration mapping.

C2 Beaconing: Tracks persistent, rhythmic "check-in" traffic to unusual geographic locations or ASNs.

DNS Tunnelling: Identifies data exfiltration by hunting for abnormally deep DNS sub-labels (e.g., encoded-data.attacker.com).

Living-off-the-Land Stealth: Catches uncharacteristic volume spikes (Risk Velocity) on normally quiet devices, even if absolute query counts remain low.

Live Threat Intel Cross-Referencing: Validates queries and IP connections instantly against FeodoTracker, URLhaus, ThreatFox, and OTX.

🛠️ Tech Stack & Architecture
Language: Python 3 (Optimized with __slots__ for strict memory management and minimal RSS footprint)

Data Sources: Pi-hole (SQLite), Zeek (TSV/JSON Logs)

Machine Learning: Scikit-Learn (Isolation Forest)

Visualization: Grafana (Prometheus metrics via custom exporters)

Alerting: Telegram Webhook API

📊 Dashboard & Triage
This engine is designed to be paired with a comprehensive Grafana observability suite. The provided dashboard architecture plots dynamic Safe Baseline Corridors, visualizes exact Z-score deviations, maps geographic threat destinations, and separates underlying system health (memory leaks, database lag) from active network triage.