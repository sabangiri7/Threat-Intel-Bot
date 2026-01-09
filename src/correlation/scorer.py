"""
Correlation Scorer - Phase 3.1 Week 6
Implements scoring logic for incident groups
"""

import logging
from typing import List, Dict

logger = logging.getLogger(__name__)


class CorrelationScorer:
    """Scores incident groups based on multiple factors."""
    
    def scoregroup(self, ioc_cluster: List[Dict]) -> Dict:
        """
        Score an IOC cluster/incident group.
        
        Args:
            ioc_cluster: List of IOC dicts in group
            
        Returns:
            Score dictionary with breakdown
        """
        if not ioc_cluster:
            return self._default_score()
        
        # Calculate components
        base_score = self._calculate_base_score(ioc_cluster)
        confidence_boost = self._calculate_confidence_boost(ioc_cluster)
        source_boost = self._calculate_source_boost(ioc_cluster)
        size_bonus = self._calculate_size_bonus(ioc_cluster)
        action_multiplier = self._calculate_action_multiplier(ioc_cluster)
        
        # Calculate final score
        final_score = (base_score + confidence_boost + source_boost + size_bonus) * action_multiplier
        final_score = min(100.0, max(0.0, final_score))  # Clamp 0-100
        
        # Determine severity
        severity_level = self._determine_severity(final_score)
        
        # Generate reasoning
        reasoning = self._generate_reasoning(
            ioc_cluster, base_score, confidence_boost, source_boost, size_bonus
        )
        
        return {
            'base_score': base_score,
            'confidence_boost': confidence_boost,
            'source_boost': source_boost,
            'size_bonus': size_bonus,
            'action_multiplier': action_multiplier,
            'final_score': final_score,
            'severity_level': severity_level,
            'reasoning': reasoning
        }
    
    def _calculate_base_score(self, cluster: List[Dict]) -> float:
        """Calculate base score from avg unified_confidence."""
        if not cluster:
            return 0.0
        
        confidences = [ioc.get('unifiedconfidence', 0.5) for ioc in cluster]
        avg_confidence = sum(confidences) / len(confidences)
        
        return avg_confidence * 80.0  # Scale to 0-80
    
    def _calculate_confidence_boost(self, cluster: List[Dict]) -> float:
        """Boost based on high-confidence sources."""
        boost = 0.0
        
        for ioc in cluster:
            api_results = ioc.get('apiresults', {})
            
            # VirusTotal detections
            vt = api_results.get('virustotal', {})
            if vt.get('malicious', 0) > 40:
                boost += 3.0
            
            # AbuseIPDB confidence
            abuseipdb = api_results.get('abuseipdb', {})
            if abuseipdb.get('abuseconfidencescore', 0) > 75:
                boost += 2.5
            
            # ThreatFox confidence
            threatfox = api_results.get('threatfox', {})
            if threatfox.get('confidencelevel', 0) > 85:
                boost += 2.0
        
        return min(boost, 15.0)  # Cap at 15
    
    def _calculate_source_boost(self, cluster: List[Dict]) -> float:
        """Boost based on number of detection sources."""
        boost = 0.0
        
        for ioc in cluster:
            api_results = ioc.get('apiresults', {})
            source_count = len([k for k in api_results.keys() if api_results[k]])
            
            boost += source_count * 1.5
        
        return min(boost / len(cluster), 10.0)  # Normalize and cap
    
    def _calculate_size_bonus(self, cluster: List[Dict]) -> float:
        """Bonus for larger correlations."""
        size = len(cluster)
        
        if size >= 5:
            return 8.0
        elif size >= 3:
            return 5.0
        elif size >= 2:
            return 2.0
        else:
            return 0.0
    
    def _calculate_action_multiplier(self, cluster: List[Dict]) -> float:
        """Multiplier based on triage action."""
        block_count = sum(1 for ioc in cluster if ioc.get('triageaction') == 'BLOCK')
        total = len(cluster)
        
        if block_count == total:
            return 1.0  # All blocked: 1.0x
        elif block_count >= total * 0.75:
            return 0.95  # 75%+: 0.95x
        elif block_count >= total * 0.5:
            return 0.85  # 50%+: 0.85x
        else:
            return 0.75  # <50%: 0.75x
    
    def _determine_severity(self, score: float) -> str:
        """Map score to severity level."""
        if score >= 85:
            return 'CRITICAL'
        elif score >= 70:
            return 'HIGH'
        elif score >= 50:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_reasoning(self, cluster: List[Dict], base: float, conf: float, src: float, size: float) -> str:
        """Generate human-readable reasoning."""
        count = len(cluster)
        families = set(ioc.get('malwarefamily', 'UNKNOWN') for ioc in cluster if ioc.get('malwarefamily') != 'UNKNOWN')
        
        parts = []
        
        if count > 1:
            parts.append(f"Correlated {count} IOCs")
        
        if families and families != {'UNKNOWN'}:
            family_str = ', '.join(sorted(families))
            parts.append(f"Family: {family_str}")
        
        if conf > 5:
            parts.append(f"High confidence sources detected")
        
        if size > 3:
            parts.append(f"Large correlation group (x{size/2:.1f} bonus)")
        
        return '; '.join(parts) if parts else "Standard correlation group"
    
    def _default_score(self) -> Dict:
        """Return default/empty score."""
        return {
            'base_score': 0.0,
            'confidence_boost': 0.0,
            'source_boost': 0.0,
            'size_bonus': 0.0,
            'action_multiplier': 1.0,
            'final_score': 0.0,
            'severity_level': 'LOW',
            'reasoning': 'Empty cluster'
        }
