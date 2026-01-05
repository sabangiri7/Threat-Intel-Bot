"""
IOC Classification Module
Classifies IOCs by type using regex patterns
"""

import re
from typing import Dict, Tuple
from src.config import IOC_TYPES

class IOCClassifier:
    """Classifies IOCs by type"""
    
    def __init__(self):
        self.patterns = IOC_TYPES
    
    def classify(self, ioc_value: str) -> Tuple[str, float]:
        """
        Classify an IOC and return (type, confidence)
        Returns ("UNKNOWN", 0.0) if no match
        """
        ioc_value = ioc_value.strip()
        
        for ioc_type, pattern in self.patterns.items():
            if re.match(pattern, ioc_value):
                return (ioc_type, 0.95)
        
        return ("UNKNOWN", 0.0)
    
    def classify_batch(self, iocs: list) -> list:
        """Classify multiple IOCs"""
        classified = []
        for ioc in iocs:
            ioc_type, confidence = self.classify(ioc.get('value', ''))
            ioc['type'] = ioc_type
            ioc['classification_confidence'] = confidence
            classified.append(ioc)
        
        return classified


# Example usage
if __name__ == "__main__":
    classifier = IOCClassifier()
    
    test_iocs = [
        "192.168.1.1",
        "malicious.com",
        "https://phishing.com",
        "d41d8cd98f00b204e9800998ecf8427e"
    ]
    
    for ioc in test_iocs:
        ioc_type, confidence = classifier.classify(ioc)
        print(f"{ioc} -> {ioc_type} (confidence: {confidence})")
    