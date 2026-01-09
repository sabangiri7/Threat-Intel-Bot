#!/usr/bin/env python3
"""
Test API Key Configuration
Run: python test_api_keys.py
"""

import os
import sys
import logging
from pathlib import Path
from dotenv import load_dotenv
import requests

# Load .env file
load_dotenv()

# Get API keys
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
OTX_KEY = os.getenv("OTX_API_KEY")
TF_KEY = os.getenv("THREATFOX_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")

logging.info("="*60)
logging.info("PHASE 2: API KEY VERIFICATION")
logging.info("="*60)

# Check if keys exist
logging.info("\n1. Checking if all 4 API keys are loaded:")
logging.info(f"   VirusTotal: {bool(VT_KEY)} (first 10 chars: {VT_KEY[:10] if VT_KEY else 'MISSING'}...)")
logging.info(f"   OTX: {bool(OTX_KEY)} (first 10 chars: {OTX_KEY[:10] if OTX_KEY else 'MISSING'}...)")
logging.info(f"   ThreatFox: {bool(TF_KEY)} (first 10 chars: {TF_KEY[:10] if TF_KEY else 'MISSING'}...)")
logging.info(f"   AbuseIPDB: {bool(ABUSE_KEY)} (first 10 chars: {ABUSE_KEY[:10] if ABUSE_KEY else 'MISSING'}...)")

if not all([VT_KEY, OTX_KEY, TF_KEY, ABUSE_KEY]):
    logging.error("\nERROR: Some API keys are missing!")
    logging.error("   Please check your .env file and try again.")
    sys.exit(1)

logging.info("\nAll 4 API keys loaded successfully!")

# Test VirusTotal
logging.info("\n2. Testing VirusTotal API...")
try:
    response = requests.get(
        "https://www.virustotal.com/api/v3/domains/google.com",
        headers={"x-apikey": VT_KEY},
        timeout=5
    )
    if response.status_code == 200:
        logging.info("   VirusTotal: Connected successfully")
    else:
        logging.warning(f"   VirusTotal: Status {response.status_code} (key may be invalid)")
except Exception as e:
    logging.error(f"   VirusTotal: Connection failed ({str(e)})")

# Test OTX
logging.info("\n3. Testing OTX API...")
try:
    response = requests.get(
        "https://otx.alienvault.com/api/v1/pulses/subscribed",
        headers={"X-OTX-API-KEY": OTX_KEY},
        timeout=5
    )
    if response.status_code == 200:
        logging.info("   OTX: Connected successfully")
    else:
        logging.warning(f"   OTX: Status {response.status_code} (key may be invalid)")
except Exception as e:
    logging.error(f"   OTX: Connection failed ({str(e)})")

# Test ThreatFox
logging.info("\n4. Testing ThreatFox API...")
try:
    payload = {"query": "get_stats"}
    response = requests.post(
        "https://threatfox-api.abuse.ch/api/v1/",
        json=payload,
        headers={"Auth-Key": TF_KEY},
        timeout=5
    )
    if response.status_code == 200:
        logging.info("   ThreatFox: Connected successfully")
    else:
        logging.warning(f"   ThreatFox: Status {response.status_code} (key may be invalid)")
except Exception as e:
    logging.error(f"   ThreatFox: Connection failed ({str(e)})")

# Test AbuseIPDB
logging.info("\n5. Testing AbuseIPDB API...")
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
        logging.info("   AbuseIPDB: Connected successfully")
    else:
        logging.warning(f"   AbuseIPDB: Status {response.status_code} (key may be invalid)")
except Exception as e:
    logging.error(f"   AbuseIPDB: Connection failed ({str(e)})")

logging.info("\n" + "="*60)
logging.info("Phase 2 API Setup Ready!")
logging.info("="*60)
