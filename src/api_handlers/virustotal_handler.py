"""
VirusTotal API Handler
Phase 2: Enrichment Module

Handles all VirusTotal API queries for:
- IP addresses
- Domains
- URLs
- File hashes (MD5, SHA1, SHA256)
"""

import os
import requests
import time
from typing import Dict, Optional, List
from dotenv import load_dotenv

load_dotenv()


class VirusTotalHandler:
    """Handler for VirusTotal API v3"""

    def __init__(self):
        """Initialize VirusTotal handler with API key"""
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        self.rate_limit_delay = 15  # seconds (4 req/min = 15 sec per request)

    def check_ip(self, ip_address: str) -> Dict:
        """
        Query VirusTotal for IP reputation
        
        Args:
            ip_address (str): IPv4 or IPv6 address
            
        Returns:
            Dict: API response with reputation data
        """
        endpoint = f"{self.base_url}/ip_addresses/{ip_address}"
        
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            time.sleep(self.rate_limit_delay)  # Respect rate limits
            
            if response.status_code == 200:
                data = response.json()
                return self._normalize_response(data, "IP")
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

    def check_domain(self, domain: str) -> Dict:
        """
        Query VirusTotal for domain reputation
        
        Args:
            domain (str): Domain name
            
        Returns:
            Dict: API response with reputation data
        """
        endpoint = f"{self.base_url}/domains/{domain}"
        
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            time.sleep(self.rate_limit_delay)  # Respect rate limits
            
            if response.status_code == 200:
                data = response.json()
                return self._normalize_response(data, "domain")
            else:
                return {
                    "status": "error",
                    "error": f"HTTP {response.status_code}",
                    "ioc_type": "domain"
                }
        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "error": str(e),
                "ioc_type": "domain"
            }

    def check_url(self, url: str) -> Dict:
        """
        Query VirusTotal for URL reputation
        
        Args:
            url (str): Full URL
            
        Returns:
            Dict: API response with reputation data
        """
        # VT requires URL to be encoded
        import hashlib
        url_id = hashlib.sha256(url.encode()).hexdigest()
        endpoint = f"{self.base_url}/urls/{url_id}"
        
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            time.sleep(self.rate_limit_delay)  # Respect rate limits
            
            if response.status_code == 200:
                data = response.json()
                return self._normalize_response(data, "URL")
            else:
                return {
                    "status": "error",
                    "error": f"HTTP {response.status_code}",
                    "ioc_type": "URL"
                }
        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "error": str(e),
                "ioc_type": "URL"
            }

    def check_hash(self, file_hash: str) -> Dict:
        """
        Query VirusTotal for file hash reputation
        
        Args:
            file_hash (str): MD5, SHA1, or SHA256 hash
            
        Returns:
            Dict: API response with reputation data
        """
        endpoint = f"{self.base_url}/files/{file_hash}"
        
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            time.sleep(self.rate_limit_delay)  # Respect rate limits
            
            if response.status_code == 200:
                data = response.json()
                return self._normalize_response(data, "hash")
            else:
                return {
                    "status": "error",
                    "error": f"HTTP {response.status_code}",
                    "ioc_type": "hash"
                }
        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "error": str(e),
                "ioc_type": "hash"
            }

    def _normalize_response(self, data: Dict, ioc_type: str) -> Dict:
        """
        Normalize VT response to common format
        
        Args:
            data (Dict): Raw API response
            ioc_type (str): Type of IOC
            
        Returns:
            Dict: Normalized response
        """
        try:
            attributes = data.get("data", {}).get("attributes", {})
            
            # Count detections
            last_analysis = attributes.get("last_analysis_stats", {})
            detections = last_analysis.get("malicious", 0)
            total_engines = (
                last_analysis.get("malicious", 0) +
                last_analysis.get("undetected", 0) +
                last_analysis.get("suspicious", 0)
            )
            
            return {
                "status": "success",
                "ioc_type": ioc_type,
                "detections": detections,
                "total_engines": total_engines,
                "detection_ratio": f"{detections}/{total_engines}",
                "last_analysis_date": attributes.get("last_analysis_date"),
                "categories": attributes.get("categories", {}),
                "raw_data": data
            }
        except Exception as e:
            return {
                "status": "error",
                "error": f"Parsing error: {str(e)}",
                "ioc_type": ioc_type
            }

    def enrich_ioc(self, ioc_value: str, ioc_type: str) -> Dict:
        """
        Main method: Enrich IOC based on type
        
        Args:
            ioc_value (str): The IOC value
            ioc_type (str): Type (IP, domain, URL, hash)
            
        Returns:
            Dict: Enrichment data
        """
        ioc_type_lower = ioc_type.lower()
        
        if ioc_type_lower == "ip":
            return self.check_ip(ioc_value)
        elif ioc_type_lower == "domain":
            return self.check_domain(ioc_value)
        elif ioc_type_lower == "url":
            return self.check_url(ioc_value)
        elif ioc_type_lower == "hash":
            return self.check_hash(ioc_value)
        else:
            return {
                "status": "error",
                "error": f"Unknown IOC type: {ioc_type}",
                "ioc_type": ioc_type
            }


if __name__ == "__main__":
    # Test the handler
    handler = VirusTotalHandler()
    
    # Test with sample IOC
    result = handler.enrich_ioc("google.com", "domain")
    print("VirusTotal Result:")
    print(f"Status: {result.get('status')}")
    print(f"IOC Type: {result.get('ioc_type')}")
    print(f"Detections: {result.get('detections')}")
    print(f"Detection Ratio: {result.get('detection_ratio')}")
