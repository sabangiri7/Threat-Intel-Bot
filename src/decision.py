"""
Phase 4: Incident-level triage and decision engine.
Recommends BLOCK/QUARANTINE/MONITOR/IGNORE for correlated incidents.
IOC-level triage_action (in enrichment) is unchanged; this layer operates on incidents.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

# Thresholds (risk score 0-100)
BLOCK_THRESHOLD = 85.0
QUARANTINE_THRESHOLD = 70.0
MONITOR_THRESHOLD = 50.0
IGNORE_THRESHOLD = 30.0

SEVERITY_SCORES = {
    'CRITICAL': 100 * 0.35,
    'HIGH': 80 * 0.35,
    'MEDIUM': 50 * 0.35,
    'LOW': 20 * 0.35,
}


def _get_final_score(incident: Dict) -> float:
    """Get final_score from incident['score'] (dict or object)."""
    score = incident.get('score')
    if score is None:
        return 0.0
    if isinstance(score, dict):
        return float(score.get('final_score', 0) or 0)
    return float(getattr(score, 'final_score', getattr(score, 'getfinalscore', lambda: 0)()) or 0)


def _get_severity_level(incident: Dict) -> str:
    """Get severity_level from incident['score'] (dict or object)."""
    score = incident.get('score')
    if score is None:
        return 'LOW'
    if isinstance(score, dict):
        return str(score.get('severity_level', 'LOW') or 'LOW')
    return str(getattr(score, 'severity_level', getattr(score, 'getseveritylevel', lambda: 'LOW')()) or 'LOW')


def _get_api_consensus(incident: Dict) -> float:
    """
    Api consensus 0-100. Use incident['api_consensus'] if set.
    Else derive from score (source_boost/confidence) or 0.
    """
    if 'api_consensus' in incident and incident['api_consensus'] is not None:
        return float(incident['api_consensus'])
    score = incident.get('score')
    if isinstance(score, dict):
        # Proxy: normalize source_boost (0-10) to 0-100
        sb = float(score.get('source_boost', 0) or 0)
        cb = float(score.get('confidence_boost', 0) or 0)
        return min(100.0, (sb * 5.0) + (cb * 2.0))  # rough 0-100
    return 0.0


@dataclass
class TriageDecision:
    """Incident-level triage decision."""
    incident_id: str
    recommendation: str  # BLOCK, QUARANTINE, MONITOR, IGNORE
    confidence: float    # 0-100 risk score
    reason: str
    justification: List[str] = field(default_factory=list)


class TriageEngine:
    """
    Incident-level decision engine.
    Risk score = 40% incident score + 35% severity mapping + 25% api consensus.
    """

    BLOCK_THRESHOLD = BLOCK_THRESHOLD
    QUARANTINE_THRESHOLD = QUARANTINE_THRESHOLD
    MONITOR_THRESHOLD = MONITOR_THRESHOLD
    IGNORE_THRESHOLD = IGNORE_THRESHOLD

    def _calculate_risk_score(self, incident: Dict) -> float:
        """40% incident score + 35% severity + 25% api consensus."""
        score_val = _get_final_score(incident)
        severity = _get_severity_level(incident)
        api_consensus = _get_api_consensus(incident)

        score_component = score_val * 0.40
        severity_component = SEVERITY_SCORES.get(severity, SEVERITY_SCORES['LOW'])
        api_component = min(100.0, max(0.0, api_consensus)) * 0.25

        return min(100.0, score_component + severity_component + api_component)

    def _generate_reason(self, incident: Dict, risk_score: float) -> str:
        parts = []
        families = incident.get('malware_families') or []
        if families and families[0] != 'UNKNOWN':
            parts.append(f"Known malware family: {families[0]}")
        severity = _get_severity_level(incident)
        parts.append(f"Severity: {severity}")
        group_size = incident.get('group_size', 0)
        if group_size > 10:
            parts.append(f"Large incident group: {group_size} IOCs")
        parts.append(f"Risk confidence: {risk_score:.1f}%")
        return " | ".join(parts)

    def make_decision(self, incident: Dict) -> TriageDecision:
        risk_score = self._calculate_risk_score(incident)
        if risk_score >= self.BLOCK_THRESHOLD:
            recommendation = "BLOCK"
        elif risk_score >= self.QUARANTINE_THRESHOLD:
            recommendation = "QUARANTINE"
        elif risk_score >= self.MONITOR_THRESHOLD:
            recommendation = "MONITOR"
        else:
            recommendation = "IGNORE"
        reason = self._generate_reason(incident, risk_score)
        return TriageDecision(
            incident_id=incident.get('incident_id', 'UNKNOWN'),
            recommendation=recommendation,
            confidence=risk_score,
            reason=reason,
        )

    def batch_triage(self, incidents: List[Dict]) -> List[TriageDecision]:
        return [self.make_decision(inc) for inc in incidents]


class RecommendationSummary:
    """Summary of triage recommendations."""

    @staticmethod
    def generate_summary(decisions: List[TriageDecision]) -> Dict[str, Any]:
        return {
            'total_incidents': len(decisions),
            'block_count': sum(1 for d in decisions if d.recommendation == 'BLOCK'),
            'quarantine_count': sum(1 for d in decisions if d.recommendation == 'QUARANTINE'),
            'monitor_count': sum(1 for d in decisions if d.recommendation == 'MONITOR'),
            'ignore_count': sum(1 for d in decisions if d.recommendation == 'IGNORE'),
            'immediate_action_required': sum(1 for d in decisions if d.recommendation in ('BLOCK', 'QUARANTINE')),
            'analyst_review_recommended': sum(1 for d in decisions if d.recommendation == 'MONITOR'),
        }


def generate_incident_recommendations(incidents: List[Dict]) -> tuple:
    """
    Generate incident-level recommendations for Phase 5/6 reporting.
    Returns (decisions: List[TriageDecision], summary: Dict).
    """
    engine = TriageEngine()
    decisions = engine.batch_triage(incidents)
    summary = RecommendationSummary.generate_summary(decisions)
    return decisions, summary
