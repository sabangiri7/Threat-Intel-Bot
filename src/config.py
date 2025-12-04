"""
Configuration and constants for Threat Intelligence Bot
"""

# API Configuration
VIRUSTOTAL_API_KEY = None  # Will be loaded from .env
OTX_API_KEY = None         # Will be loaded from .env
ABUSEIPDB_API_KEY = None   # Will be loaded from .env

# API Endpoints
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3"
OTX_URL = "https://otx.alienvault.com/api/v1"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2"

# IOC Types
IOC_TYPES = {
    "IP": r"^(\d{1,3}\.){3}\d{1,3}$",
    "DOMAIN": r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$",
    "URL": r"^https?://",
    "HASH": r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$"
}

# Confidence Thresholds
CONFIDENCE_HIGH = 0.95
CONFIDENCE_MEDIUM = 0.70
CONFIDENCE_LOW = 0.40

# Triage Actions
TRIAGE_ACTIONS = {
    "BLOCK": "Block immediately - high confidence malicious",
    "MONITOR": "Monitor - suspicious but uncertain",
    "QUARANTINE": "Quarantine - potential threat",
    "IGNORE": "Ignore - known legitimate or false positive"
}

# Paths
DATA_DIR = "data"
OUTPUT_DIR = "output"
LOG_FILE = "logs/bot.log"
