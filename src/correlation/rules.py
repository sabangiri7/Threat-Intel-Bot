"""
Correlation Rules Engine
Implements Rule 1 (Shared Infrastructure) and Rule 2 (Malware Family)
"""

from typing import List, Dict, Set
from datetime import datetime


class CorrelationRules:
    """Implements correlation rules for grouping enriched IOCs."""

    RULE1_TIME_WINDOW = 48  # hours
    RULE2_TIME_WINDOW = 72  # hours
    MIN_GROUP_SIZE = 2

    @staticmethod
    def parse_timestamp(ts_str: str) -> datetime:
        """Parse ISO 8601 timestamp to datetime."""
        try:
            return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return datetime.utcnow()

    @staticmethod
    def is_within_time_window(ts1: datetime, ts2: datetime, hours: int) -> bool:
        """Check if timestamps are within N hours."""
        delta = abs((ts1 - ts2).total_seconds() / 3600)
        return delta <= hours

    @classmethod
    def apply_rule_1(cls, enriched_iocs: List[Dict]) -> List[List[Dict]]:
        """
        Rule 1: Shared Infrastructure Correlation
        Groups IOCs sharing same IP or resolving to same IP within 48 hours.
        """
        groups = []
        used_indices = set()
        
        for i, ioc1 in enumerate(enriched_iocs):
            if i in used_indices:
                continue
            
            group = [ioc1]
            used_indices.add(i)
            
            ip1_set = cls._extract_ips(ioc1)
            ts1 = cls.parse_timestamp(ioc1.get('timestamp', ''))
            
            for j, ioc2 in enumerate(enriched_iocs):
                if j in used_indices or j == i:
                    continue
                
                ip2_set = cls._extract_ips(ioc2)
                ts2 = cls.parse_timestamp(ioc2.get('timestamp', ''))
                
                if ip1_set & ip2_set and cls.is_within_time_window(ts1, ts2, cls.RULE1_TIME_WINDOW):
                    group.append(ioc2)
                    used_indices.add(j)
            
            if len(group) >= cls.MIN_GROUP_SIZE:
                groups.append(group)
        
        return groups

    @classmethod
    def apply_rule_2(cls, enriched_iocs: List[Dict]) -> List[List[Dict]]:
        """
        Rule 2: Malware Family Correlation
        Groups IOCs with same malware family within 72 hours.
        """
        groups = []
        used_indices = set()
        
        for i, ioc1 in enumerate(enriched_iocs):
            if i in used_indices:
                continue
            
            group = [ioc1]
            used_indices.add(i)
            
            malware_family = ioc1.get('malware_family', 'UNKNOWN')
            ts1 = cls.parse_timestamp(ioc1.get('timestamp', ''))
            
            if malware_family == 'UNKNOWN':
                continue
            
            for j, ioc2 in enumerate(enriched_iocs):
                if j in used_indices or j == i:
                    continue
                
                malware_family2 = ioc2.get('malware_family', 'UNKNOWN')
                ts2 = cls.parse_timestamp(ioc2.get('timestamp', ''))
                
                if (malware_family == malware_family2 and 
                    cls.is_within_time_window(ts1, ts2, cls.RULE2_TIME_WINDOW)):
                    group.append(ioc2)
                    used_indices.add(j)
            
            if len(group) >= cls.MIN_GROUP_SIZE:
                groups.append(group)
        
        return groups

    @staticmethod
    def _extract_ips(ioc: Dict) -> Set[str]:
        """Extract all IPs from an IOC."""
        ips = set()
        
        if ioc.get('ioc_type') == 'IP':
            ips.add(ioc.get('ioc_value', ''))
        
        resolves_to = ioc.get('resolves_to', [])
        if isinstance(resolves_to, list):
            ips.update(resolves_to)
        
        return ips

    @staticmethod
    def merge_groups(groups_rule1: List[List[Dict]], 
                     groups_rule2: List[List[Dict]]) -> List[List[Dict]]:
        """Merge Rule 1 and Rule 2 groups, preventing duplicates."""
        iocs_in_rule1 = set()
        for group in groups_rule1:
            for ioc in group:
                iocs_in_rule1.add(ioc['ioc_value'])
        
        merged = groups_rule1.copy()
        for group in groups_rule2:
            filtered_group = [ioc for ioc in group 
                            if ioc['ioc_value'] not in iocs_in_rule1]
            
            if len(filtered_group) >= 2:
                merged.append(filtered_group)
                for ioc in filtered_group:
                    iocs_in_rule1.add(ioc['ioc_value'])
        
        return merged

    @staticmethod
    def get_group_stats(group: List[Dict]) -> Dict:
        """Calculate stats for a group."""
        count = len(group)
        confidences = [ioc.get('unified_confidence', 0.5) for ioc in group]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.5
        has_block = any(ioc.get('triage_action') == 'BLOCK' for ioc in group)
        malware_families = set(ioc.get('malware_family', 'UNKNOWN') for ioc in group)
        
        return {
            'count': count,
            'avg_confidence': round(avg_confidence, 2),
            'has_block': has_block,
            'malware_families': list(malware_families)
        }
