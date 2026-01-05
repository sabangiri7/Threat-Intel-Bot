"""
AbuseIPDB API Handler
Phase 2: Enrichment Module

Handles AbuseIPDB queries for:
- IP abuse reputation scores
- Brute force, spam, and attack detections
- ISP and geolocation data
"""

import os
import requests
from typing import Dict
from dotenv import load_dotenv

load_dotenv()


class AbuseIPDBHandler:
    """Handler for AbuseIPDB API"""

    def __init__(self):
        self.api_key = (
            os.getenv("ABUSEIPDB_API_KEY")
            or os.getenv("ABUSEIPDBAPIKEY")
            or os.getenv("ABUSEIPDB_APIKEY")
        )
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {"Key": self.api_key, "Accept": "application/json"}

    def check(self, ioc_value: str, ioc_type: str = "ip") -> Dict:
        """Compatibility wrapper for orchestrator."""
        return self.enrich_ioc(ioc_value, ioc_type)

    def check_ip(self, ip_address: str, max_age_days: int = 90) -> Dict:
        if not self.api_key:
            return {"status": "error", "error": "Missing ABUSEIPDB API key", "ioc_type": "IP"}

        endpoint = f"{self.base_url}/check"
        params = {"ipAddress": ip_address, "maxAgeInDays": max_age_days, "verbose": ""}

        try:
            response = requests.get(endpoint, headers=self.headers, params=params, timeout=10)
            if response.status_code == 200:
                return self._normalize_response(response.json())

            return {"status": "error", "error": f"HTTP {response.status_code}", "ioc_type": "IP"}

        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e), "ioc_type": "IP"}

    def _normalize_response(self, data: Dict) -> Dict:
        try:
            ip_data = data.get("data", {})

            abuse_score = ip_data.get("abuseConfidenceScore", 0)
            total_reports = ip_data.get("totalReports", 0)

            # FIX: AbuseIPDB uses numDistinctUsers in responses
            distinct_users = ip_data.get("numDistinctUsers", ip_data.get("distinctUsers", 0))

            last_reported = ip_data.get("lastReportedAt")
            is_whitelisted = ip_data.get("isWhitelisted", False)

            usage_type = ip_data.get("usageType", "Unknown")
            isp = ip_data.get("isp", "Unknown")
            country = ip_data.get("countryName", "Unknown")

            reports = ip_data.get("reports", []) or []
            categories = []
            for report in reports:
                categories.extend(report.get("categories", []))
            categories = sorted(set(categories))

            return {
                "status": "success",
                "ioc_type": "IP",
                "ip_address": ip_data.get("ipAddress"),
                "abuse_confidence_score": abuse_score,
                "total_reports": total_reports,
                "distinct_users": distinct_users,
                "last_reported_at": last_reported,
                "is_whitelisted": is_whitelisted,
                "usage_type": usage_type,
                "isp": isp,
                "country": country,
                "report_categories": categories,
                "raw_data": data,
            }

        except Exception as e:
            return {"status": "error", "error": f"Parsing error: {str(e)}", "ioc_type": "IP"}

    def get_blacklist(self, name_only: bool = True) -> Dict:
        if not self.api_key:
            return {"status": "error", "error": "Missing ABUSEIPDB API key"}

        endpoint = f"{self.base_url}/blacklist"
        params = {"plaintext": "true" if name_only else "false"}

        try:
            response = requests.get(endpoint, headers=self.headers, params=params, timeout=10)
            if response.status_code == 200:
                if name_only:
                    return {"status": "success", "blacklist": response.text.strip().split("\n")}
                return response.json()

            return {"status": "error", "error": f"HTTP {response.status_code}"}

        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e)}

    def report_ip(self, ip_address: str, category: int, comment: str = None) -> Dict:
        if not self.api_key:
            return {"status": "error", "error": "Missing ABUSEIPDB API key"}

        endpoint = f"{self.base_url}/report"
        payload = {"ip": ip_address, "category": category}
        if comment:
            payload["comment"] = comment

        try:
            response = requests.post(endpoint, headers=self.headers, data=payload, timeout=10)
            if response.status_code == 200:
                return {"status": "success", "message": "IP reported successfully", "data": response.json()}
            return {"status": "error", "error": f"HTTP {response.status_code}"}

        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e)}

    def enrich_ioc(self, ioc_value: str, ioc_type: str) -> Dict:
        if (ioc_type or "").lower() != "ip":
            return {"status": "error", "error": "AbuseIPDB only supports IP addresses", "ioc_type": ioc_type}
        return self.check_ip(ioc_value)


if __name__ == "__main__":
    handler = AbuseIPDBHandler()
    result = handler.check_ip("8.8.8.8")
    print(result)
