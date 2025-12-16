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
from typing import Dict, List
from dotenv import load_dotenv

load_dotenv()


class OTXHandler:
    """Handler for AlienVault OTX API"""

    def __init__(self):
        """Initialize OTX handler with API key"""
        self.api_key = os.getenv("OTX_API_KEY")
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json"
        }

    def check_ip(self, ip_address: str) -> Dict:
        """
        Query OTX for IP reputation
        
        Args:
            ip_address (str): IPv4 or IPv6 address
            
        Returns:
            Dict: API response with reputation data
        """
        endpoint = f"{self.base_url}/indicators/IPv4/{ip_address}/general"
        
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            
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
        Query OTX for domain reputation
        
        Args:
            domain (str): Domain name
            
        Returns:
            Dict: API response with reputation data
        """
        endpoint = f"{self.base_url}/indicators/domain/{domain}/general"
        
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            
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
        Query OTX for URL reputation
        
        Args:
            url (str): Full URL
            
        Returns:
            Dict: API response with reputation data
        """
        endpoint = f"{self.base_url}/indicators/url/general"
        
        try:
            payload = {"url": url}
            response = requests.post(endpoint, headers=self.headers, json=payload, timeout=10)
            
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
        Query OTX for file hash reputation
        
        Args:
            file_hash (str): MD5, SHA1, or SHA256 hash
            
        Returns:
            Dict: API response with reputation data
        """
        endpoint = f"{self.base_url}/indicators/file/{file_hash}/general"
        
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            
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
        Normalize OTX response to common format
        
        Args:
            data (Dict): Raw API response
            ioc_type (str): Type of IOC
            
        Returns:
            Dict: Normalized response
        """
        try:
            # Extract pulses (threat campaigns)
            pulse_info = data.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])
            pulse_count = len(pulses)
            pulse_names = [p.get("name") for p in pulses]
            
            # Extract threat types/tags
            type_tags = data.get("type_tags", [])
            
            # Check validation
            validation = data.get("validation", [])
            
            return {
                "status": "success",
                "ioc_type": ioc_type,
                "pulse_count": pulse_count,
                "pulses": pulse_names,
                "type_tags": type_tags,
                "validation": validation,
                "reputation": data.get("reputation"),
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
    handler = OTXHandler()
    
    # Test with sample IOC
    result = handler.enrich_ioc("google.com", "domain")
    print("OTX Result:")
    print(f"Status: {result.get('status')}")
    print(f"IOC Type: {result.get('ioc_type')}")
    print(f"Pulse Count: {result.get('pulse_count')}")
    print(f"Pulses: {result.get('pulses')}")
