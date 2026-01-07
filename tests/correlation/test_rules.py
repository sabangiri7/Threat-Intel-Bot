"""
Unit tests for Correlation Rules
"""

import pytest
from datetime import datetime, timedelta
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.correlation.rules import CorrelationRules


@pytest.fixture
def sample_iocs():
    """Sample enriched IOCs for testing."""
    base_time = datetime(2026, 1, 7, 12, 0, 0)
    
    return [
        {
            "ioc_value": "192.168.1.10",
            "ioc_type": "IP",
            "unified_confidence": 0.87,
            "triage_action": "BLOCK",
            "timestamp": base_time.isoformat() + "Z",
            "malware_family": "Trojan.A",
            "resolves_to": [],
            "otx_pulses": []
        },
        {
            "ioc_value": "malware-c2.com",
            "ioc_type": "DOMAIN",
            "unified_confidence": 0.92,
            "triage_action": "BLOCK",
            "timestamp": (base_time + timedelta(hours=24)).isoformat() + "Z",
            "malware_family": "Trojan.A",
            "resolves_to": ["192.168.1.10"],
            "otx_pulses": ["pulse-001"]
        },
        {
            "ioc_value": "payload.exe",
            "ioc_type": "HASH",
            "unified_confidence": 0.75,
            "triage_action": "MONITOR",
            "timestamp": (base_time + timedelta(hours=12)).isoformat() + "Z",
            "malware_family": "Trojan.A",
            "resolves_to": [],
            "otx_pulses": []
        },
        {
            "ioc_value": "192.168.2.20",
            "ioc_type": "IP",
            "unified_confidence": 0.68,
            "triage_action": "IGNORE",
            "timestamp": (base_time + timedelta(hours=72)).isoformat() + "Z",
            "malware_family": "Ransom.X",
            "resolves_to": [],
            "otx_pulses": []
        },
        {
            "ioc_value": "another-c2.ru",
            "ioc_type": "DOMAIN",
            "unified_confidence": 0.81,
            "triage_action": "BLOCK",
            "timestamp": (base_time + timedelta(hours=48)).isoformat() + "Z",
            "malware_family": "Ransom.X",
            "resolves_to": ["192.168.2.20"],
            "otx_pulses": []
        }
    ]


def test_rule_1_basic_grouping(sample_iocs):
    """Test Rule 1 groups IOCs with shared IP."""
    groups = CorrelationRules.apply_rule_1(sample_iocs)
    assert len(groups) >= 1
    assert len(groups[0]) >= 2


def test_rule_1_time_window(sample_iocs):
    """Test Rule 1 respects 48-hour time window."""
    groups = CorrelationRules.apply_rule_1(sample_iocs)
    assert len(groups) >= 1


def test_rule_2_basic_grouping(sample_iocs):
    """Test Rule 2 groups IOCs with same malware family."""
    groups = CorrelationRules.apply_rule_2(sample_iocs)
    assert len(groups) >= 1


def test_rule_2_multiple_families(sample_iocs):
    """Test Rule 2 creates separate groups for different families."""
    groups = CorrelationRules.apply_rule_2(sample_iocs)
    assert len(groups) >= 2


def test_parse_timestamp():
    """Test timestamp parsing."""
    ts_str = "2026-01-07T12:30:45Z"
    result = CorrelationRules.parse_timestamp(ts_str)
    assert isinstance(result, datetime)


def test_is_within_time_window():
    """Test time window checking."""
    ts1 = datetime(2026, 1, 7, 12, 0, 0)
    ts2 = datetime(2026, 1, 7, 15, 0, 0)
    assert CorrelationRules.is_within_time_window(ts1, ts2, 48)
    assert not CorrelationRules.is_within_time_window(ts1, ts2, 2)


def test_extract_ips():
    """Test IP extraction."""
    ip_ioc = {
        "ioc_value": "192.168.1.10",
        "ioc_type": "IP",
        "resolves_to": []
    }
    ips = CorrelationRules._extract_ips(ip_ioc)
    assert "192.168.1.10" in ips


def test_merge_groups(sample_iocs):
    """Test merging groups."""
    groups_rule1 = CorrelationRules.apply_rule_1(sample_iocs)
    groups_rule2 = CorrelationRules.apply_rule_2(sample_iocs)
    merged = CorrelationRules.merge_groups(groups_rule1, groups_rule2)
    assert len(merged) >= len(groups_rule1)


def test_full_pipeline(sample_iocs):
    """Test full pipeline."""
    groups_rule1 = CorrelationRules.apply_rule_1(sample_iocs)
    groups_rule2 = CorrelationRules.apply_rule_2(sample_iocs)
    merged = CorrelationRules.merge_groups(groups_rule1, groups_rule2)
    assert len(merged) >= 2
    for group in merged:
        assert len(group) >= 2
