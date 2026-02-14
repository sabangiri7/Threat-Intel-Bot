"""
Phase 4: Tests for incident-level decision engine (TriageEngine, RecommendationSummary).
"""

import pytest
from src.decision import (
    TriageDecision,
    TriageEngine,
    RecommendationSummary,
    BLOCK_THRESHOLD,
    QUARANTINE_THRESHOLD,
    MONITOR_THRESHOLD,
)


def _incident(incident_id: str, final_score: float, severity_level: str, group_size: int = 2, malware_families=None, api_consensus: float = None):
    out = {
        'incident_id': incident_id,
        'group_size': group_size,
        'malware_families': malware_families or ['Trojan.A'],
        'score': {
            'final_score': final_score,
            'severity_level': severity_level,
            'base_score': 50,
            'confidence_boost': 0,
            'source_boost': 0,
            'size_bonus': 0,
            'action_multiplier': 1.0,
            'reasoning': 'test',
        },
    }
    if api_consensus is not None:
        out['api_consensus'] = api_consensus
    return out


def test_high_risk_block():
    """High risk (score + severity + api_consensus) -> BLOCK."""
    engine = TriageEngine()
    # 40%*90 + 35%*100 + 25%*60 = 36+35+15 = 86 >= 85
    inc = _incident('INC-0001', 90.0, 'CRITICAL', group_size=5, api_consensus=60.0)
    decision = engine.make_decision(inc)
    assert decision.recommendation == 'BLOCK'
    assert decision.confidence >= BLOCK_THRESHOLD


def test_medium_risk_monitor():
    """Medium risk -> MONITOR (between 50 and 70)."""
    engine = TriageEngine()
    # 40%*55 + 35%*50 + 25%*50 = 22+17.5+12.5 = 52 -> MONITOR
    inc = _incident('INC-0002', 55.0, 'MEDIUM', group_size=2, api_consensus=50.0)
    decision = engine.make_decision(inc)
    assert decision.recommendation == 'MONITOR'
    assert MONITOR_THRESHOLD <= decision.confidence < QUARANTINE_THRESHOLD


def test_low_risk_ignore():
    """Low risk -> IGNORE."""
    engine = TriageEngine()
    inc = _incident('INC-0003', 20.0, 'LOW', group_size=1, malware_families=['UNKNOWN'])
    decision = engine.make_decision(inc)
    assert decision.recommendation == 'IGNORE'
    assert decision.confidence < MONITOR_THRESHOLD


def test_quarantine_range():
    """Risk in [70, 85) -> QUARANTINE."""
    engine = TriageEngine()
    # 40%*75 + 35%*80 + 25%*50 = 30+28+12.5 = 70.5 -> QUARANTINE
    inc = _incident('INC-0004', 75.0, 'HIGH', group_size=4, api_consensus=50.0)
    decision = engine.make_decision(inc)
    assert decision.recommendation == 'QUARANTINE'
    assert QUARANTINE_THRESHOLD <= decision.confidence < BLOCK_THRESHOLD


def test_batch_triage_length():
    """Batch triage returns one decision per incident."""
    engine = TriageEngine()
    incidents = [
        _incident('INC-0001', 90.0, 'CRITICAL'),
        _incident('INC-0002', 55.0, 'MEDIUM'),
        _incident('INC-0003', 20.0, 'LOW'),
    ]
    decisions = engine.batch_triage(incidents)
    assert len(decisions) == len(incidents)
    assert [d.incident_id for d in decisions] == ['INC-0001', 'INC-0002', 'INC-0003']


def test_summary_counts():
    """RecommendationSummary counts are correct."""
    decisions = [
        TriageDecision('INC-0001', 'BLOCK', 90.0, 'reason'),
        TriageDecision('INC-0002', 'BLOCK', 88.0, 'reason'),
        TriageDecision('INC-0003', 'QUARANTINE', 72.0, 'reason'),
        TriageDecision('INC-0004', 'MONITOR', 55.0, 'reason'),
        TriageDecision('INC-0005', 'IGNORE', 25.0, 'reason'),
    ]
    summary = RecommendationSummary.generate_summary(decisions)
    assert summary['total_incidents'] == 5
    assert summary['block_count'] == 2
    assert summary['quarantine_count'] == 1
    assert summary['monitor_count'] == 1
    assert summary['ignore_count'] == 1
    assert summary['immediate_action_required'] == 3
    assert summary['analyst_review_recommended'] == 1


def test_score_as_object_like():
    """Incident with score as object-like (getattr) still works."""
    class ScoreObj:
        final_score = 92.0
        severity_level = 'CRITICAL'
    inc = {
        'incident_id': 'INC-0001',
        'group_size': 3,
        'malware_families': ['Ransom.X'],
        'score': ScoreObj(),
        'api_consensus': 60.0,  # 40%*92 + 35 + 15 = 36.8+35+15 = 86.8 -> BLOCK
    }
    engine = TriageEngine()
    decision = engine.make_decision(inc)
    assert decision.recommendation == 'BLOCK'
    assert decision.confidence >= BLOCK_THRESHOLD
