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
        """Initialize AbuseIPDB handler with API key"""
        self.api_key = os.getenv("ABUSEIPDB_API_KEY")
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }

    def check_ip(self, ip_address: str, max_age_days: int = 90) -> Dict:
        """
        Query AbuseIPDB for IP abuse reputation
        
        Args:
            ip_address (str): IPv4 or IPv6 address
            max_age_days (int): Maximum age of reports (default 90 days)
            
        Returns:
            Dict: API response with abuse data
        """
        endpoint = f"{self.base_url}/check"
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": max_age_days,
            "verbose": ""  # Get detailed information
        }
        
        try:
            response = requests.get(
                endpoint,
                headers=self.headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._normalize_response(data)
            else:
                return {
                    "status": "error",
                    "error": f"HTTP {response.status_code}",
                    "ioc_type": "IP"
                }
        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "error": str(e),
                "ioc_type": "IP"
            }

    def _normalize_response(self, data: Dict) -> Dict:
        """
        Normalize AbuseIPDB response to common format
        
        Args:
            data (Dict): Raw API response
            
        Returns:
            Dict: Normalized response
        """
        try:
            ip_data = data.get("data", {})
            
            # Extract key fields
            abuse_score = ip_data.get("abuseConfidenceScore", 0)
            total_reports = ip_data.get("totalReports", 0)
            distinct_users = ip_data.get("distinctUsers", 0)
            last_reported = ip_data.get("lastReportedAt")
            is_whitelisted = ip_data.get("isWhitelisted", False)
            
            # Extract usage type and ISP
            usage_type = ip_data.get("usageType", "Unknown")
            isp = ip_data.get("isp", "Unknown")
            country = ip_data.get("countryName", "Unknown")
            
            # Extract report categories if available
            reports = ip_data.get("reports", [])
            categories = []
            if reports:
                for report in reports:
                    report_cats = report.get("categories", [])
                    categories.extend(report_cats)
                categories = list(set(categories))  # Remove duplicates
            
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
                "raw_data": data
            }
        except Exception as e:
            return {
                "status": "error",
                "error": f"Parsing error: {str(e)}",
                "ioc_type": "IP"
            }

    def get_blacklist(self, name_only: bool = True) -> Dict:
        """
        Get AbuseIPDB's public blacklist
        
        Args:
            name_only (bool): Return only IP addresses (default)
            
        Returns:
            Dict: Blacklist data
        """
        endpoint = f"{self.base_url}/blacklist"
        params = {
            "plaintext": "true" if name_only else "false"
        }
        
        try:
            response = requests.get(
                endpoint,
                headers=self.headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                if name_only:
                    # Plaintext format returns just IPs separated by newlines
                    return {
                        "status": "success",
                        "blacklist": response.text.strip().split("\n")
                    }
                else:
                    # JSON format
                    return response.json()
            else:
                return {
                    "status": "error",
                    "error": f"HTTP {response.status_code}"
                }
        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "error": str(e)
            }

    def report_ip(self, ip_address: str, category: int, comment: str = None) -> Dict:
        """
        Report an abusive IP (requires authentication)
        
        Args:
            ip_address (str): IP to report
            category (int): Category ID (see AbuseIPDB docs)
            comment (str, optional): Comment about the abuse
            
        Returns:
            Dict: Report submission result
        """
        endpoint = f"{self.base_url}/report"
        data = {
            "ip": ip_address,
            "category": category
        }
        if comment:
            data["comment"] = comment
        
        try:
            response = requests.post(
                endpoint,
                headers=self.headers,
                data=data,
                timeout=10
            )
            
            if response.status_code == 200:
                return {
                    "status": "success",
                    "message": "IP reported successfully",
                    "data": response.json()
                }
            else:
                return {
                    "status": "error",
                    "error": f"HTTP {response.status_code}"
                }
        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "error": str(e)
            }

    def enrich_ioc(self, ioc_value: str, ioc_type: str) -> Dict:
        """
        Main method: Enrich IOC (IP only)
        
        Args:
            ioc_value (str): The IOC value
            ioc_type (str): Type (only "IP" supported)
            
        Returns:
            Dict: Enrichment data
        """
        if ioc_type.lower() != "ip":
            return {
                "status": "error",
                "error": "AbuseIPDB only supports IP addresses",
                "ioc_type": ioc_type
            }
        
        return self.check_ip(ioc_value)


if __name__ == "__main__":
    # Test the handler
    handler = AbuseIPDBHandler()
    
    # Test with sample IP
    result = handler.check_ip("8.8.8.8")
    print("AbuseIPDB Result:")
    print(f"Status: {result.get('status')}")
    print(f"IP: {result.get('ip_address')}")
    print(f"Abuse Score: {result.get('abuse_confidence_score')}")
    print(f"Total Reports: {result.get('total_reports')}")
    print(f"Country: {result.get('country')}")
