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
                "threatfox": {"ioc_count": 1, "confidencelevel": 90}
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
                "threatfox": {"ioc_count": 2, "confidencelevel": 92}
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
    scorer = CorrelationScorer()
    score = scorer.scoregroup(high_confidence_group)
    assert score["final_score"] > 70
    assert score["severity_level"] in ["HIGH", "CRITICAL"]
    assert score["confidence_boost"] >= 0


def test_score_low_confidence_group(low_confidence_group):
    """Test scoring low confidence group (UNKNOWN + IGNORE)."""
    scorer = CorrelationScorer()
    score = scorer.scoregroup(low_confidence_group)
    assert score["final_score"] <= 60
    assert score["severity_level"] in ["LOW", "MEDIUM"]


def test_score_medium_confidence_group(medium_confidence_group):
    """Test scoring medium confidence group (Ransom.X + MONITOR)."""
    scorer = CorrelationScorer()
    score = scorer.scoregroup(medium_confidence_group)
    assert score["final_score"] >= 0
    assert score["severity_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def test_determine_severity():
    """Test severity level from final score (50+ = MEDIUM, 70+ = HIGH, 85+ = CRITICAL)."""
    scorer = CorrelationScorer()
    assert scorer._determine_severity(15) == "LOW"
    assert scorer._determine_severity(50) == "MEDIUM"
    assert scorer._determine_severity(72) == "HIGH"
    assert scorer._determine_severity(90) == "CRITICAL"


def test_score_multiple_groups(high_confidence_group, medium_confidence_group, low_confidence_group):
    """Test scoring multiple groups."""
    scorer = CorrelationScorer()
    groups = [high_confidence_group, medium_confidence_group, low_confidence_group]
    scores = [scorer.scoregroup(g) for g in groups]
    assert len(scores) == 3
    assert scores[0]["final_score"] > scores[2]["final_score"]


def test_reasoning_generation(high_confidence_group):
    """Test human-readable reasoning generation."""
    scorer = CorrelationScorer()
    score = scorer.scoregroup(high_confidence_group)
    assert "Trojan.A" in score["reasoning"]
    assert len(score["reasoning"]) > 10


def test_source_boost_calculation():
    """Test multi-source consensus boost."""
    scorer = CorrelationScorer()
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
    score = scorer.scoregroup(group_with_sources)
    assert score["source_boost"] >= 0


def test_empty_group_handling():
    """Test handling of empty IOC group."""
    scorer = CorrelationScorer()
    score = scorer.scoregroup([])
    assert score["final_score"] == 0
    assert score["severity_level"] == "LOW"
