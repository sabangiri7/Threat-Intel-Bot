"""
Unit tests for Correlation Scorer
"""

import pytest
from datetime import datetime, timedelta
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.correlation.scorer import CorrelationScorer


@pytest.fixture
def high_confidence_group():
    """High confidence IOC group (Trojan.A)."""
    base_time = datetime(2026, 1, 7, 12, 0, 0)
    return [
        {
            "ioc_value": "192.168.1.10",
            "ioc_type": "IP",
            "unified_confidence": 0.95,
            "triage_action": "BLOCK",
            "timestamp": base_time.isoformat() + "Z",
            "malware_family": "Trojan.A",
            "resolves_to": [],
            "otx_pulses": [],
            "api_results": {
                "virustotal": {"malicious": 50},
                "abuseipdb": {"is_whitelisted": False},
                "otx": {"pulse_count": 2},
                "threatfox": {"ioc_count": 1}
            }
        },
        {
            "ioc_value": "malware-c2.com",
            "ioc_type": "DOMAIN",
            "unified_confidence": 0.92,
            "triage_action": "BLOCK",
            "timestamp": (base_time + timedelta(hours=12)).isoformat() + "Z",
            "malware_family": "Trojan.A",
            "resolves_to": ["192.168.1.10"],
            "otx_pulses": ["pulse-001"],
            "api_results": {
                "virustotal": {"malicious": 55},
                "abuseipdb": {"is_whitelisted": False},
                "otx": {"pulse_count": 3},
                "threatfox": {"ioc_count": 2}
            }
        }
    ]


@pytest.fixture
def medium_confidence_group():
    """Medium confidence IOC group (Ransom.X)."""
    base_time = datetime(2026, 1, 7, 12, 0, 0)
    return [
        {
            "ioc_value": "192.168.2.20",
            "ioc_type": "IP",
            "unified_confidence": 0.65,
            "triage_action": "MONITOR",
            "timestamp": base_time.isoformat() + "Z",
            "malware_family": "Ransom.X",
            "resolves_to": [],
            "otx_pulses": [],
            "api_results": {
                "virustotal": {"malicious": 20},
                "abuseipdb": {"is_whitelisted": False},
                "otx": {"pulse_count": 0},
                "threatfox": {"ioc_count": 0}
            }
        },
        {
            "ioc_value": "ransom-server.ru",
            "ioc_type": "DOMAIN",
            "unified_confidence": 0.68,
            "triage_action": "MONITOR",
            "timestamp": (base_time + timedelta(hours=24)).isoformat() + "Z",
            "malware_family": "Ransom.X",
            "resolves_to": ["192.168.2.20"],
            "otx_pulses": [],
            "api_results": {}
        }
    ]


@pytest.fixture
def low_confidence_group():
    """Low confidence IOC group (UNKNOWN family)."""
    base_time = datetime(2026, 1, 7, 12, 0, 0)
    return [
        {
            "ioc_value": "suspicious-ip.com",
            "ioc_type": "DOMAIN",
            "unified_confidence": 0.45,
            "triage_action": "IGNORE",
            "timestamp": base_time.isoformat() + "Z",
            "malware_family": "UNKNOWN",
            "resolves_to": [],
            "otx_pulses": [],
            "api_results": {}
        },
        {
            "ioc_value": "192.168.3.30",
            "ioc_type": "IP",
            "unified_confidence": 0.42,
            "triage_action": "IGNORE",
            "timestamp": (base_time + timedelta(hours=48)).isoformat() + "Z",
            "malware_family": "UNKNOWN",
            "resolves_to": [],
            "otx_pulses": [],
            "api_results": {}
        }
    ]


def test_score_high_confidence_group(high_confidence_group):
    """Test scoring high confidence group (Trojan.A + BLOCK)."""
    score = CorrelationScorer.score_group(high_confidence_group)
    
    assert score["final_score"] > 70
    assert score["severity_level"] in ["HIGH", "CRITICAL"]
    assert score["ioc_count"] == 2
    assert score["confidence_boost"] > 15


# NEW:
def test_score_low_confidence_group(low_confidence_group):
    """Test scoring low confidence group (UNKNOWN + IGNORE)."""
    score = CorrelationScorer.score_group(low_confidence_group)
    
    assert score["final_score"] <= 50  # ✅ UNKNOWN + size_bonus + IGNORE multiplier
    assert score["severity_level"] in ["LOW", "MEDIUM"]
    assert score["base_score"] == 40  # UNKNOWN baseline


def test_score_medium_confidence_group(medium_confidence_group):
    """Test scoring medium confidence group (Ransom.X + MONITOR)."""
    score = CorrelationScorer.score_group(medium_confidence_group)
    
    assert score["final_score"] > 80  # ✅ Ransom.X is HIGH-RISK
    assert score["severity_level"] in ["HIGH", "CRITICAL"]
    assert score["base_score"] >= 80  # Ransom.X is high-risk


def test_base_score_calculation():
    """Test base score by malware family."""
    assert CorrelationScorer.MALWARE_BASE_SCORES["Trojan.A"] == 70
    assert CorrelationScorer.MALWARE_BASE_SCORES["Ransom.X"] == 85
    assert CorrelationScorer.MALWARE_BASE_SCORES["UNKNOWN"] == 40


def test_score_to_level():
    """Test score to severity level conversion."""
    assert CorrelationScorer._score_to_level(15) == "LOW"
    assert CorrelationScorer._score_to_level(45) == "MEDIUM"
    assert CorrelationScorer._score_to_level(72) == "HIGH"
    assert CorrelationScorer._score_to_level(90) == "CRITICAL"


def test_score_to_level_boundaries():
    """Test score boundaries."""
    assert CorrelationScorer._score_to_level(0) == "LOW"
    assert CorrelationScorer._score_to_level(30) == "LOW"
    assert CorrelationScorer._score_to_level(31) == "MEDIUM"
    assert CorrelationScorer._score_to_level(60) == "MEDIUM"
    assert CorrelationScorer._score_to_level(100) == "CRITICAL"


def test_action_multiplier():
    """Test triage action multipliers."""
    assert CorrelationScorer.ACTION_MULTIPLIERS["BLOCK"] == 1.2
    assert CorrelationScorer.ACTION_MULTIPLIERS["MONITOR"] == 1.0
    assert CorrelationScorer.ACTION_MULTIPLIERS["IGNORE"] == 0.8


def test_score_multiple_groups(high_confidence_group, medium_confidence_group, low_confidence_group):
    """Test scoring multiple groups at once."""
    groups = [high_confidence_group, medium_confidence_group, low_confidence_group]
    scores = CorrelationScorer.score_multiple_groups(groups)
    
    assert len(scores) == 3
    assert scores[0]["final_score"] > scores[2]["final_score"]


def test_get_high_severity_groups(high_confidence_group, medium_confidence_group, low_confidence_group):
    """Test filtering by minimum severity level."""
    groups = [high_confidence_group, medium_confidence_group, low_confidence_group]
    
    high_only = CorrelationScorer.get_high_severity_groups(groups, "HIGH")
    assert len(high_only) >= 1
    
    critical_only = CorrelationScorer.get_high_severity_groups(groups, "CRITICAL")
    assert len(critical_only) <= len(high_only)


def test_reasoning_generation(high_confidence_group):
    """Test human-readable reasoning generation."""
    score = CorrelationScorer.score_group(high_confidence_group)
    
    assert "Trojan.A" in score["reasoning"]
    assert "IOCs linked" in score["reasoning"]
    assert len(score["reasoning"]) > 10


def test_source_boost_calculation():
    """Test multi-source consensus boost."""
    group_with_sources = [
        {
            "ioc_value": "192.168.1.10",
            "ioc_type": "IP",
            "unified_confidence": 0.9,
            "triage_action": "BLOCK",
            "timestamp": "2026-01-07T12:00:00Z",
            "malware_family": "Trojan.A",
            "api_results": {
                "virustotal": {"malicious": 50},
                "abuseipdb": {"is_whitelisted": False},
                "otx": {"pulse_count": 2},
                "threatfox": {"ioc_count": 1}
            }
        }
    ]
    
    score = CorrelationScorer.score_group(group_with_sources)
    assert score["source_boost"] > 0


def test_empty_group_handling():
    """Test handling of empty IOC group."""
    empty_group = []
    score = CorrelationScorer.score_group(empty_group)
    
    assert score["final_score"] == 0
    assert score["severity_level"] == "LOW"
    assert score["ioc_count"] == 0
