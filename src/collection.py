"""
IOC Collection Module
Fetches IOCs from files, APIs, and simulated SIEM logs
"""

import csv
import json
from typing import List, Dict
from pathlib import Path

class IOCCollector:
    """Collects IOCs from multiple sources"""
    
    def __init__(self):
        self.iocs = []
    
    def from_csv_file(self, file_path: str) -> List[Dict]:
        """
        Read IOCs from CSV file
        Expected CSV columns: ioc_value, ioc_type, source
        """
        try:
            iocs = []
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    ioc = {
                        'value': row.get('ioc_value'),
                        'type': row.get('ioc_type'),
                        'source': row.get('source', 'csv_file'),
                        'timestamp': row.get('timestamp', None),
                        'confidence': None,
                        'enrichment': {},
                        'correlation': []
                    }
                    iocs.append(ioc)
            
            self.iocs.extend(iocs)
            print(f"[SUCCESS] Collected {len(iocs)} IOCs from {file_path}")
            return iocs
        
        except Exception as e:
            print(f"[ERROR] Failed to read CSV file: {str(e)}")
            return []
    
    def from_json_file(self, file_path: str) -> List[Dict]:
        """Read IOCs from JSON file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            iocs = data if isinstance(data, list) else data.get('iocs', [])
            self.iocs.extend(iocs)
            print(f"[SUCCESS] Collected {len(iocs)} IOCs from {file_path}")
            return iocs
        
        except Exception as e:
            print(f"[ERROR] Failed to read JSON file: {str(e)}")
            return []
    
    def add_manual(self, ioc_value: str, ioc_type: str, source: str = "manual") -> Dict:
        """Manually add a single IOC"""
        ioc = {
            'value': ioc_value,
            'type': ioc_type,
            'source': source,
            'timestamp': None,
            'confidence': None,
            'enrichment': {},
            'correlation': []
        }
        self.iocs.append(ioc)
        return ioc
    
    def get_all(self) -> List[Dict]:
        """Return all collected IOCs"""
        return self.iocs
    
    def count(self) -> int:
        """Return total IOC count"""
        return len(self.iocs)


# Example usage
if __name__ == "__main__":
    collector = IOCCollector()
    
    # Manually add test IOCs
    collector.add_manual("192.168.1.1", "IP")
    collector.add_manual("malicious.com", "DOMAIN")
    collector.add_manual("https://phishing-site.com", "URL")
    
    print(f"Total IOCs: {collector.count()}")
    print(collector.get_all())
