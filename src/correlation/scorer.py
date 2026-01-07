"""
Correlation Scorer
Assigns severity scores to incident groups based on IOC characteristics.
"""

from typing import List, Dict, Tuple


class CorrelationScorer:
    """Calculates severity scores for correlated IOC groups."""

    # Severity level thresholds
    SEVERITY_THRESHOLDS = {
        "LOW": (0, 30),
        "MEDIUM": (31, 60),
        "HIGH": (61, 85),
        "CRITICAL": (86, 100)
    }

    # Base scores by malware family
    MALWARE_BASE_SCORES = {
        "Trojan.A": 70,
        "Trojan.B": 68,
        "Ransom.X": 85,
        "Ransom.Y": 82,
        "Botnet.Z": 75,
        "Spyware.M": 65,
        "Worm.W": 60,
        "UNKNOWN": 40
    }

    # Triage action multipliers
    ACTION_MULTIPLIERS = {
        "BLOCK": 1.2,      # 20% boost
        "MONITOR": 1.0,    # No change
        "IGNORE": 0.8      # 20% reduction
    }

    @classmethod
    def score_group(cls, ioc_group: List[Dict]) -> Dict:
        """
        Calculate severity score for an IOC group.
        
        Returns dict with:
        - base_score: Initial score
        - confidence_boost: Confidence adjustment
        - source_boost: Multi-source consensus boost
        - action_adjustment: Triage action impact
        - final_score: Calculated final score (0-100)
        - severity_level: LOW|MEDIUM|HIGH|CRITICAL
        - reasoning: Explanation string
        """
        if not ioc_group or len(ioc_group) == 0:
            return cls._null_score()

        # Step 1: Get base score from malware family
        base_score = cls._calculate_base_score(ioc_group)

        # Step 2: Confidence boost (average confidence * 20)
        avg_confidence = cls._calculate_avg_confidence(ioc_group)
        confidence_boost = avg_confidence * 20

        # Step 3: Source consensus boost (multi-source validation)
        source_boost = cls._calculate_source_boost(ioc_group)

        # Step 4: Action multiplier (based on triage actions)
        action_multiplier = cls._calculate_action_multiplier(ioc_group)

        # Step 5: Group size bonus (more IOCs = higher confidence in campaign)
        size_bonus = min(len(ioc_group) * 2, 15)

        # Final calculation
        pre_final = base_score + confidence_boost + source_boost + size_bonus
        final_score = min(100, max(0, pre_final * action_multiplier))

        severity_level = cls._score_to_level(final_score)
        reasoning = cls._generate_reasoning(ioc_group, base_score, 
                                            confidence_boost, source_boost, 
                                            size_bonus, action_multiplier)

        return {
            "base_score": round(base_score, 1),
            "confidence_boost": round(confidence_boost, 1),
            "source_boost": round(source_boost, 1),
            "size_bonus": round(size_bonus, 1),
            "action_multiplier": round(action_multiplier, 2),
            "final_score": round(final_score, 1),
            "severity_level": severity_level,
            "reasoning": reasoning,
            "ioc_count": len(ioc_group)
        }

    @classmethod
    def _calculate_base_score(cls, ioc_group: List[Dict]) -> float:
        """Get base score from malware family (most common in group)."""
        families = [ioc.get("malware_family", "UNKNOWN") for ioc in ioc_group]
        
        # Most common family
        if families:
            most_common = max(set(families), key=families.count)
            return cls.MALWARE_BASE_SCORES.get(most_common, 40)
        
        return 40

    @classmethod
    def _calculate_avg_confidence(cls, ioc_group: List[Dict]) -> float:
        """Calculate average unified_confidence (0.0-1.0)."""
        confidences = [ioc.get("unified_confidence", 0.5) for ioc in ioc_group]
        if confidences:
            return sum(confidences) / len(confidences)
        return 0.5

    @classmethod
    def _calculate_source_boost(cls, ioc_group: List[Dict]) -> float:
        """
        Boost score if multiple sources flagged the IOCs.
        Rule 5 from design: 3+ sources = +15 points
        """
        source_boost = 0
        
        for ioc in ioc_group:
            source_count = cls._count_sources(ioc)
            if source_count >= 3:
                source_boost += 15
        
        # Cap total source boost
        return min(source_boost, 20)

    @classmethod
    def _count_sources(cls, ioc: Dict) -> int:
        """Count independent sources that flagged this IOC."""
        sources = set()
        
        api_results = ioc.get("api_results", {})
        
        if api_results.get("virustotal", {}).get("malicious", 0) > 0:
            sources.add("virustotal")
        
        if api_results.get("abuseipdb", {}).get("is_whitelisted", False) is False:
            sources.add("abuseipdb")
        
        if api_results.get("otx", {}).get("pulse_count", 0) > 0:
            sources.add("otx")
        
        if api_results.get("threatfox", {}).get("ioc_count", 0) > 0:
            sources.add("threatfox")
        
        return len(sources)

    @classmethod
    def _calculate_action_multiplier(cls, ioc_group: List[Dict]) -> float:
        """
        Calculate multiplier based on triage actions in group.
        If group contains BLOCK actions, apply multiplier boost.
        """
        actions = [ioc.get("triage_action", "MONITOR") for ioc in ioc_group]
        
        # Get multiplier for most common action
        if actions:
            most_common_action = max(set(actions), key=actions.count)
            multiplier = cls.ACTION_MULTIPLIERS.get(most_common_action, 1.0)
            
            # Extra boost if any BLOCK actions present
            if "BLOCK" in actions:
                multiplier *= 1.1
            
            return multiplier
        
        return 1.0

    @classmethod
    def _score_to_level(cls, score: float) -> str:
        """Convert numeric score to severity level."""
        for level, (low, high) in cls.SEVERITY_THRESHOLDS.items():
            if low <= score <= high:
                return level
        return "LOW"

    @classmethod
    def _generate_reasoning(cls, ioc_group: List[Dict], base_score: float,
                           confidence_boost: float, source_boost: float,
                           size_bonus: float, action_multiplier: float) -> str:
        """Generate human-readable reasoning string."""
        family = ioc_group[0].get("malware_family", "UNKNOWN")
        ioc_count = len(ioc_group)
        
        reasons = []
        reasons.append(f"{ioc_count} IOCs linked to {family}")
        
        if base_score >= 70:
            reasons.append("High-risk malware family")
        
        if confidence_boost > 10:
            reasons.append("High confidence indicators")
        
        if source_boost > 0:
            reasons.append("Multi-source consensus")
        
        if action_multiplier > 1.0:
            reasons.append("Primary action is BLOCK")
        elif action_multiplier < 1.0:
            reasons.append("Primary action is IGNORE")
        
        return "; ".join(reasons)

    @staticmethod
    def _null_score() -> Dict:
        """Return null/empty score."""
        return {
            "base_score": 0,
            "confidence_boost": 0,
            "source_boost": 0,
            "size_bonus": 0,
            "action_multiplier": 1.0,
            "final_score": 0,
            "severity_level": "LOW",
            "reasoning": "Empty group",
            "ioc_count": 0
        }

    @classmethod
    def score_multiple_groups(cls, ioc_groups: List[List[Dict]]) -> List[Dict]:
        """Score multiple groups at once."""
        return [cls.score_group(group) for group in ioc_groups]

    @classmethod
    def get_high_severity_groups(cls, ioc_groups: List[List[Dict]], 
                                 min_level: str = "HIGH") -> List[Tuple[List[Dict], Dict]]:
        """
        Filter groups by minimum severity level.
        Returns list of (group, score) tuples.
        """
        level_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        min_rank = level_order.get(min_level, 0)
        
        results = []
        for group in ioc_groups:
            score = cls.score_group(group)
            group_rank = level_order.get(score["severity_level"], 0)
            
            if group_rank >= min_rank:
                results.append((group, score))
        
        return results
