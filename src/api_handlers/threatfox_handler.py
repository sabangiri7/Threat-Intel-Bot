"""
ThreatFox (Abuse.ch) API Handler
Phase 2: Enrichment Module

Handles ThreatFox queries for:
- IP addresses (C2 servers)
- Domains (malware delivery)
- URLs (malicious payloads)
- File hashes (malware samples)
- Threat types and malware families
"""

import os
import requests
from typing import Dict
from dotenv import load_dotenv

load_dotenv()


class ThreatFoxHandler:
    """Handler for ThreatFox (Abuse.ch) API"""

    def __init__(self):
        self.api_key = os.getenv("THREATFOX_API_KEY") or os.getenv("THREATFOXAPIKEY") or os.getenv("THREATFOXAPI_KEY")
        self.base_url = "https://threatfox-api.abuse.ch/api/v1/"
        self.headers = {"Auth-Key": self.api_key, "Content-Type": "application/json"}

    def check(self, ioc_value: str, ioc_type: str = None) -> Dict:
        """Compatibility wrapper for orchestrator."""
        return self.enrich_ioc(ioc_value, ioc_type)

    def check_ioc(self, ioc_value: str) -> Dict:
        if not self.api_key:
            return {"status": "error", "error": "Missing THREATFOX API key", "ioc_value": ioc_value}

        payload = {"query": "search_ioc", "search_term": ioc_value, "exact_match": True}

        try:
            response = requests.post(self.base_url, json=payload, headers=self.headers, timeout=10)
            if response.status_code != 200:
                return {"status": "error", "error": f"HTTP {response.status_code}", "ioc_value": ioc_value}

            data = response.json()
            if data.get("query_status") == "ok":
                return self._normalize_response(data)

            return {"status": "not_found", "error": data.get("query_status", "no_result"), "ioc_value": ioc_value}

        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e), "ioc_value": ioc_value}

    def _normalize_response(self, data: Dict) -> Dict:
        try:
            iocs = data.get("data", []) or []
            if not iocs:
                return {"status": "not_found", "ioc_count": 0}

            ioc = iocs[0] if isinstance(iocs, list) else iocs

            return {
                "status": "success",
                "ioc_count": len(iocs) if isinstance(iocs, list) else 1,
                "ioc_value": ioc.get("ioc"),
                "ioc_type": ioc.get("ioc_type"),
                "threat_type": ioc.get("threat_type"),
                "threat_type_desc": ioc.get("threat_type_desc"),
                "malware": ioc.get("malware"),
                "malware_printable": ioc.get("malware_printable"),
                "malware_alias": ioc.get("malware_alias"),
                "confidence_level": ioc.get("confidence_level"),
                "last_submission": ioc.get("last_submission_date"),
                "tags": ioc.get("tags", []),
                "raw_data": data,
            }

        except Exception as e:
            return {"status": "error", "error": f"Parsing error: {str(e)}"}

    def get_stats(self) -> Dict:
        payload = {"query": "get_stats"}
        try:
            response = requests.post(self.base_url, json=payload, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            return {"status": "error", "error": f"HTTP {response.status_code}"}
        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e)}

    def enrich_ioc(self, ioc_value: str, ioc_type: str = None) -> Dict:
        return self.check_ioc(ioc_value)
