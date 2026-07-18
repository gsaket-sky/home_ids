import urllib.request
import json
import ssl

PIHOLE_URL = "http://192.168.178.94:8080"
APP_PASSWORD = "COV80()et" # Keep your plain-text password here
DOMAIN_TO_BLOCK = "test-v6-block.local"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# 1. Authenticate and get SID
auth_url = f"{PIHOLE_URL}/api/auth"
auth_payload = json.dumps({"password": APP_PASSWORD}).encode('utf-8')

auth_req = urllib.request.Request(auth_url, data=auth_payload, method="POST")
auth_req.add_header("Content-Type", "application/json")
auth_req.add_header("Accept", "application/json")

print("Logging into Pi-hole v6...")
with urllib.request.urlopen(auth_req, timeout=5, context=ctx) as response:
    auth_data = json.loads(response.read().decode('utf-8'))
    sid = auth_data.get("session", {}).get("sid")
    print(f"✅ Successfully authenticated! SID Acquired.")

# 2. Push the domain to the specific 'deny/exact' routing path
domain_url = f"{PIHOLE_URL}/api/domains/deny/exact" 
domain_payload = json.dumps({
    "domain": DOMAIN_TO_BLOCK
}).encode('utf-8')

domain_req = urllib.request.Request(domain_url, data=domain_payload, method="POST")
domain_req.add_header("Content-Type", "application/json")
domain_req.add_header("Accept", "application/json")
domain_req.add_header("X-FTL-SID", sid)  # Secure session header

print(f"\nDispatching block request for {DOMAIN_TO_BLOCK}...")
try:
    with urllib.request.urlopen(domain_req, timeout=5, context=ctx) as response:
        print(f"✅ Success! Pi-hole v6 blocked the domain. HTTP {response.status}")
except urllib.error.HTTPError as e:
    print(f"❌ Block Failed: HTTP {e.code}")
    print(e.read().decode('utf-8'))
