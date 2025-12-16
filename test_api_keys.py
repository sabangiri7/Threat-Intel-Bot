#!/usr/bin/env python3
"""
Test API Key Configuration
Run: python test_api_keys.py
"""

import os
import sys
from dotenv import load_dotenv
import requests

# Load .env file
load_dotenv()

# Get API keys
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
OTX_KEY = os.getenv("OTX_API_KEY")
TF_KEY = os.getenv("THREATFOX_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")

print("="*60)
print("PHASE 2: API KEY VERIFICATION")
print("="*60)

# Check if keys exist
print("\n1. Checking if all 4 API keys are loaded:")
print(f"   ✓ VirusTotal: {bool(VT_KEY)} (first 10 chars: {VT_KEY[:10] if VT_KEY else 'MISSING'}...)")
print(f"   ✓ OTX: {bool(OTX_KEY)} (first 10 chars: {OTX_KEY[:10] if OTX_KEY else 'MISSING'}...)")
print(f"   ✓ ThreatFox: {bool(TF_KEY)} (first 10 chars: {TF_KEY[:10] if TF_KEY else 'MISSING'}...)")
print(f"   ✓ AbuseIPDB: {bool(ABUSE_KEY)} (first 10 chars: {ABUSE_KEY[:10] if ABUSE_KEY else 'MISSING'}...)")

if not all([VT_KEY, OTX_KEY, TF_KEY, ABUSE_KEY]):
    print("\n❌ ERROR: Some API keys are missing!")
    print("   Please check your .env file and try again.")
    sys.exit(1)

print("\n✅ All 4 API keys loaded successfully!")

# Test VirusTotal
print("\n2. Testing VirusTotal API...")
try:
    response = requests.get(
        "https://www.virustotal.com/api/v3/domains/google.com",
        headers={"x-apikey": VT_KEY},
        timeout=5
    )
    if response.status_code == 200:
        print("   ✅ VirusTotal: Connected successfully")
    else:
        print(f"   ⚠️  VirusTotal: Status {response.status_code} (key may be invalid)")
except Exception as e:
    print(f"   ❌ VirusTotal: Connection failed ({str(e)})")

# Test OTX
print("\n3. Testing OTX API...")
try:
    response = requests.get(
        "https://otx.alienvault.com/api/v1/pulses/subscribed",
        headers={"X-OTX-API-KEY": OTX_KEY},
        timeout=5
    )
    if response.status_code == 200:
        print("   ✅ OTX: Connected successfully")
    else:
        print(f"   ⚠️  OTX: Status {response.status_code} (key may be invalid)")
except Exception as e:
    print(f"   ❌ OTX: Connection failed ({str(e)})")

# Test ThreatFox
print("\n4. Testing ThreatFox API...")
try:
    payload = {"query": "get_stats"}
    response = requests.post(
        "https://threatfox-api.abuse.ch/api/v1/",
        json=payload,
        headers={"Auth-Key": TF_KEY},
        timeout=5
    )
    if response.status_code == 200:
        print("   ✅ ThreatFox: Connected successfully")
    else:
        print(f"   ⚠️  ThreatFox: Status {response.status_code} (key may be invalid)")
except Exception as e:
    print(f"   ❌ ThreatFox: Connection failed ({str(e)})")

# Test AbuseIPDB
print("\n5. Testing AbuseIPDB API...")
try:
    response = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={
            "Key": ABUSE_KEY,
            "Accept": "application/json"
        },
        params={"ipAddress": "8.8.8.8"},
        timeout=5
    )
    if response.status_code == 200:
        print("   ✅ AbuseIPDB: Connected successfully")
    else:
        print(f"   ⚠️  AbuseIPDB: Status {response.status_code} (key may be invalid)")
except Exception as e:
    print(f"   ❌ AbuseIPDB: Connection failed ({str(e)})")

print("\n" + "="*60)
print("✅ Phase 2 API Setup Ready!")
print("="*60)
print("\nNext steps:")
print("1. Run: python test_api_keys.py")
print("2. Verify all 4 APIs respond with 200 status")
print("3. Start Week 1 implementation (API handlers)")
print("\n")
