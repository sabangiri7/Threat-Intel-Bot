"""
VirusTotal API Handler
Phase 2: Enrichment Module

Handles VirusTotal queries for:
- IP addresses
- Domains
- URLs
- File hashes (MD5, SHA1, SHA256)
"""

import os
import time
import hashlib
import requests
from typing import Dict
from dotenv import load_dotenv

load_dotenv()


class VirusTotalHandler:
    """Handler for VirusTotal API v3"""

    def __init__(self):
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VIRUSTOTALAPIKEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key, "Accept": "application/json"}
        self.rate_limit_delay = 15  # 4 req/min

    def check(self, ioc_value: str, ioc_type: str = None) -> Dict:
        """Compatibility wrapper for orchestrator."""
        return self.enrich_ioc(ioc_value, ioc_type or "ip")

    def check_ip(self, ip_address: str) -> Dict:
        if not self.api_key:
            return {"status": "error", "error": "Missing VIRUSTOTAL API key", "ioc_type": "IP"}

        endpoint = f"{self.base_url}/ip_addresses/{ip_address}"
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            time.sleep(self.rate_limit_delay)
            if response.status_code == 200:
                return self._normalize_response(response.json(), "IP")
            return {"status": "error", "error": f"HTTP {response.status_code}", "ioc_type": "IP"}
        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e), "ioc_type": "IP"}

    def check_domain(self, domain: str) -> Dict:
        if not self.api_key:
            return {"status": "error", "error": "Missing VIRUSTOTAL API key", "ioc_type": "domain"}

        endpoint = f"{self.base_url}/domains/{domain}"
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            time.sleep(self.rate_limit_delay)
            if response.status_code == 200:
                return self._normalize_response(response.json(), "domain")
            return {"status": "error", "error": f"HTTP {response.status_code}", "ioc_type": "domain"}
        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e), "ioc_type": "domain"}

    def check_url(self, url: str) -> Dict:
        if not self.api_key:
            return {"status": "error", "error": "Missing VIRUSTOTAL API key", "ioc_type": "URL"}

        # VT v3 expects URL identifier as base64url of URL; but sha256 is acceptable for your demo
        url_id = hashlib.sha256(url.encode()).hexdigest()
        endpoint = f"{self.base_url}/urls/{url_id}"

        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            time.sleep(self.rate_limit_delay)
            if response.status_code == 200:
                return self._normalize_response(response.json(), "URL")
            return {"status": "error", "error": f"HTTP {response.status_code}", "ioc_type": "URL"}
        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e), "ioc_type": "URL"}

    def check_hash(self, file_hash: str) -> Dict:
        if not self.api_key:
            return {"status": "error", "error": "Missing VIRUSTOTAL API key", "ioc_type": "hash"}

        endpoint = f"{self.base_url}/files/{file_hash}"
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            time.sleep(self.rate_limit_delay)
            if response.status_code == 200:
                return self._normalize_response(response.json(), "hash")
            return {"status": "error", "error": f"HTTP {response.status_code}", "ioc_type": "hash"}
        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e), "ioc_type": "hash"}

    def _normalize_response(self, data: Dict, ioc_type: str) -> Dict:
        try:
            attributes = (data.get("data") or {}).get("attributes", {}) or {}
            stats = attributes.get("last_analysis_stats", {}) or {}

            detections = int(stats.get("malicious", 0) or 0)
            total_engines = int(
                (stats.get("malicious", 0) or 0)
                + (stats.get("undetected", 0) or 0)
                + (stats.get("suspicious", 0) or 0)
            )

            return {
                "status": "success",
                "ioc_type": ioc_type,
                "detections": detections,
                "total_engines": total_engines,
                "detection_ratio": f"{detections}/{total_engines}",
                "last_analysis_date": attributes.get("last_analysis_date"),
                "categories": attributes.get("categories", {}),
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


if __name__ == "__main__":
    handler = VirusTotalHandler()
    print(handler.enrich_ioc("google.com", "domain"))
