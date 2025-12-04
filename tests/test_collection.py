"""
Unit tests for IOC Collection Module
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.collection import IOCCollector


def test_collector_initialization():
    """Test collector initializes correctly"""
    collector = IOCCollector()
    assert collector.count() == 0

def test_add_manual_ioc():
    """Test manually adding an IOC"""
    collector = IOCCollector()
    ioc = collector.add_manual("192.168.1.1", "IP")
    
    assert collector.count() == 1
    assert ioc['value'] == "192.168.1.1"
    assert ioc['type'] == "IP"

def test_add_multiple_iocs():
    """Test adding multiple IOCs"""
    collector = IOCCollector()
    collector.add_manual("192.168.1.1", "IP")
    collector.add_manual("malicious.com", "DOMAIN")
    collector.add_manual("https://phishing.com", "URL")
    
    assert collector.count() == 3

def test_get_all():
    """Test retrieving all IOCs"""
    collector = IOCCollector()
    collector.add_manual("192.168.1.1", "IP")
    
    all_iocs = collector.get_all()
    assert len(all_iocs) == 1
    assert all_iocs[0]['value'] == "192.168.1.1"
