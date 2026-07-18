#!/usr/bin/env python3
import json
import os
import sqlite3
import time
from pathlib import Path

# CONFIGURATION SIMULATION TARGETS
TEST_DIR = Path("/tmp/ids_simulation")
ZEEK_DIR = TEST_DIR / "zeek"
PIHOLE_DB = TEST_DIR / "pihole-FTL.db"

def setup_environment():
    """Initializes isolated workspace directories and database schemas."""
    ZEEK_DIR.mkdir(parents=True, exist_ok=True)
    if PIHOLE_DB.exists():
        PIHOLE_DB.unlink()
        
    conn = sqlite3.connect(str(PIHOLE_DB))
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER,
            domain TEXT,
            client TEXT,
            status INTEGER
        );
    """)
    cursor.execute("""
        CREATE TABLE network_addresses (
            ip TEXT PRIMARY KEY,
            name TEXT
        );
    """)
    # Seed local network names
    cursor.executemany("INSERT INTO network_addresses VALUES (?, ?);", [
        ("192.168.178.50", "victim-workstation"),
        ("192.168.178.60", "compromised-nas")
    ])
    conn.commit()
    conn.close()
    print(f"[+] Isolated environment initialized at {TEST_DIR}")

def write_zeek_json(filename: str, event: dict):
    """Appends simulated event lines to targeted JSON log logs."""
    filepath = ZEEK_DIR / filename
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

def write_pihole_query(domain: str, client_ip: str, status: int):
    """Injects tracking lookup lines into the temporary Pi-hole database."""
    conn = sqlite3.connect(str(PIHOLE_DB))
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO queries (timestamp, domain, client, status) VALUES (?, ?, ?, ?);",
        (int(time.time()), domain, client_ip, status)
    )
    conn.commit()
    conn.close()

def simulate_malicious_ja3():
    """Generates a connection signature matching a known malware threat vector."""
    print(" -> Simulating Malicious JA3 Transport (Cobalt Strike)...")
    write_zeek_json("ssl.log", {
        "ts": time.time(),
        "uid": "C_JA3_TEST_01",
        "id.orig_h": "192.168.178.50",
        "id.resp_h": "203.0.113.5",
        "id.resp_p": 443,
        "ja3": "e7d705a3286e19ea42f587b6207263db",
        "server_name": "malicious-c2-infrastructure.com"
    })

def simulate_dga_burst():
    """Injects sequential failed domain resolutions matching ransomware patterns."""
    print(" -> Simulating Ransomware DGA Guessing Activity...")
    # Status 3 indicates an NXDOMAIN response code
    for i in range(15):
        domain_string = f"xkqztp{i}wvkz.ru"
        write_pihole_query(domain_string, "192.168.178.50", 3)

def simulate_c2_beacon():
    """Simulates highly regular command and control checking intervals."""
    print(" -> Simulating Robotic C2 Beaconing (Mechanical Jitter)...")
    write_pihole_query("c2-heartbeat.local", "192.168.178.50", 1)

def simulate_dns_tunneling():
    """Generates domain requests containing layered subdomain data components."""
    print(" -> Simulating Outbound DNS Tunneling (Data Leak)...")
    tunnel_domain = "base64encodedpayloadstringhere.sub.layer.three.data.exfil.site"
    write_pihole_query(tunnel_domain, "192.168.178.60", 1)

def simulate_doh_bypass():
    """Creates traffic tracking events heading towards public resolving services."""
    print(" -> Simulating Direct Upstream DoH Bypass Event...")
    write_zeek_json("conn.log", {
        "ts": time.time(),
        "uid": "C_DOH_BYPASS_01",
        "id.orig_h": "192.168.178.60",
        "id.resp_h": "1.1.1.1",
        "id.resp_p": 443,
        "orig_bytes": 4500,
        "service": "ssl"
    })
    write_zeek_json("ssl.log", {
        "ts": time.time(),
        "uid": "C_DOH_BYPASS_01",
        "id.orig_h": "192.168.178.60",
        "id.resp_h": "1.1.1.1",
        "id.resp_p": 443,
        "server_name": "cloudflare-dns.com"
    })

def simulate_lateral_movement():
    """Generates internal multi-zone traffic pointing to sensitive management layers."""
    print(" -> Simulating Internal Lateral Pivot Scan (Spread Attempt)...")
    write_zeek_json("conn.log", {
        "ts": time.time(),
        "uid": "C_LATERAL_SCAN_01",
        "id.orig_h": "192.168.178.60",
        "id.resp_h": "192.168.178.50",
        "id.resp_p": 445,
        "proto": "tcp",
        "conn_state": "S0"
    })

if __name__ == "__main__":
    print("=== STARTING HOME IDS AUTOMATED THREAT SIMULATION ENGINE ===")
    setup_environment()
    
    # Run threat vector pipelines
    simulate_malicious_ja3()
    simulate_dga_burst()
    simulate_c2_beacon()
    simulate_dns_tunneling()
    simulate_doh_bypass()
    simulate_lateral_movement()
    
    print("\n[+] Simulation run complete. Point your testing framework variables to:")
    print(f"    - Pi-hole Database Path: {PIHOLE_DB}")
    print(f"    - Zeek Log Directory:   {ZEEK_DIR}")
    print("=== PIPELINE VALIDATION READY ===")