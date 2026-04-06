#!/usr/bin/env python3
"""
Test API Key Configuration
Run: python tests/test_api_keys.py
"""

import os
import sys
import logging
from pathlib import Path
from dotenv import load_dotenv
import requests

# FIX: Setup logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

def main():
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
    print(f"   VirusTotal: {'✅' if VT_KEY else '❌'} ({VT_KEY[:10] if VT_KEY else 'MISSING'}...)")
    print(f"   OTX: {'✅' if OTX_KEY else '❌'} ({OTX_KEY[:10] if OTX_KEY else 'MISSING'}...)")
    print(f"   ThreatFox: {'✅' if TF_KEY else '❌'} ({TF_KEY[:10] if TF_KEY else 'MISSING'}...)")
    print(f"   AbuseIPDB: {'✅' if ABUSE_KEY else '❌'} ({ABUSE_KEY[:10] if ABUSE_KEY else 'MISSING'}...)")
    
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
            timeout=10
        )
        print(f"   VirusTotal: {'✅' if response.status_code == 200 else '❌'} (Status: {response.status_code})")
    except Exception as e:
        print(f"   VirusTotal: ❌ Connection failed ({str(e)})")
    
    # Test OTX
    print("\n3. Testing OTX API...")
    try:
        response = requests.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            headers={"X-OTX-API-KEY": OTX_KEY},
            timeout=10
        )
        print(f"   OTX: {'✅' if response.status_code == 200 else '❌'} (Status: {response.status_code})")
    except Exception as e:
        print(f"   OTX: ❌ Connection failed ({str(e)})")
    
    # Test ThreatFox
    print("\n4. Testing ThreatFox API...")
    try:
        payload = {"query": "get_stats"}
        response = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json=payload,
            headers={"Auth-Key": TF_KEY},
            timeout=10
        )
        print(f"   ThreatFox: {'✅' if response.status_code == 200 else '❌'} (Status: {response.status_code})")
    except Exception as e:
        print(f"   ThreatFox: ❌ Connection failed ({str(e)})")
    
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
            timeout=10
        )
        print(f"   AbuseIPDB: {'✅' if response.status_code == 200 else '❌'} (Status: {response.status_code})")
    except Exception as e:
        print(f"   AbuseIPDB: ❌ Connection failed ({str(e)})")
    
    print("\n" + "="*60)
    print("Phase 2 API Setup Ready!")
    print("="*60)

if __name__ == "__main__":
    main()
