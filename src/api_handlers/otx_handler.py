"""
AlienVault OTX API Handler
Phase 2: Enrichment Module

Handles OTX queries for:
- IP addresses
- Domains
- URLs
- File hashes
- Threat pulses and campaigns
"""

import os
import requests
from typing import Dict
from dotenv import load_dotenv

load_dotenv()


class OTXHandler:
    """Handler for AlienVault OTX API"""

    def __init__(self):
        self.api_key = os.getenv("OTX_API_KEY") or os.getenv("OTXAPIKEY") or os.getenv("OTXAPI_KEY")
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {"X-OTX-API-KEY": self.api_key, "Accept": "application/json"}

    def check(self, ioc_value: str, ioc_type: str = None) -> Dict:
        """Compatibility wrapper for orchestrator."""
        return self.enrich_ioc(ioc_value, ioc_type or "ip")

    def check_ip(self, ip_address: str) -> Dict:
        if not self.api_key:
            return {"status": "error", "error": "Missing OTX API key", "ioc_type": "IP"}

        endpoint = f"{self.base_url}/indicators/IPv4/{ip_address}/general"
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return self._normalize_response(response.json(), "IP")
            return {"status": "error", "error": f"HTTP {response.status_code}", "ioc_type": "IP"}
        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e), "ioc_type": "IP"}

    def check_domain(self, domain: str) -> Dict:
        if not self.api_key:
            return {"status": "error", "error": "Missing OTX API key", "ioc_type": "domain"}

        endpoint = f"{self.base_url}/indicators/domain/{domain}/general"
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return self._normalize_response(response.json(), "domain")
            return {"status": "error", "error": f"HTTP {response.status_code}", "ioc_type": "domain"}
        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e), "ioc_type": "domain"}

    def check_url(self, url: str) -> Dict:
        if not self.api_key:
            return {"status": "error", "error": "Missing OTX API key", "ioc_type": "URL"}

        endpoint = f"{self.base_url}/indicators/url/general"
        try:
            payload = {"url": url}
            response = requests.post(endpoint, headers=self.headers, json=payload, timeout=10)
            if response.status_code == 200:
                return self._normalize_response(response.json(), "URL")
            return {"status": "error", "error": f"HTTP {response.status_code}", "ioc_type": "URL"}
        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e), "ioc_type": "URL"}

    def check_hash(self, file_hash: str) -> Dict:
        if not self.api_key:
            return {"status": "error", "error": "Missing OTX API key", "ioc_type": "hash"}

        endpoint = f"{self.base_url}/indicators/file/{file_hash}/general"
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return self._normalize_response(response.json(), "hash")
            return {"status": "error", "error": f"HTTP {response.status_code}", "ioc_type": "hash"}
        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e), "ioc_type": "hash"}

    def _normalize_response(self, data: Dict, ioc_type: str) -> Dict:
        try:
            pulse_info = data.get("pulse_info", {}) or {}
            pulses = pulse_info.get("pulses", []) or []
            pulse_names = [p.get("name") for p in pulses if isinstance(p, dict)]
            pulse_count = len(pulse_names)

            type_tags = data.get("type_tags", []) or []
            validation = data.get("validation", []) or []

            return {
                "status": "success",
                "ioc_type": ioc_type,
                "pulse_count": pulse_count,
                "pulses": pulse_names,
                "type_tags": type_tags,
                "validation": validation,
                "reputation": data.get("reputation"),
                "raw_data": data,
            }
        except Exception as e:
            return {"status": "error", "error": f"Parsing error: {str(e)}", "ioc_type": ioc_type}

    def enrich_ioc(self, ioc_value: str, ioc_type: str) -> Dict:
        ioc_type_lower = (ioc_type or "").lower()
        if ioc_type_lower == "ip":
            return self.check_ip(ioc_value)
        if ioc_type_lower == "domain":
            return self.check_domain(ioc_value)
        if ioc_type_lower == "url":
            return self.check_url(ioc_value)
        if ioc_type_lower == "hash":
            return self.check_hash(ioc_value)
        return {"status": "error", "error": f"Unknown IOC type: {ioc_type}", "ioc_type": ioc_type}


