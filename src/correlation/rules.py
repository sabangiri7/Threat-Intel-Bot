"""
Correlation Rules - Phase 3.1 Week 6
Implements 2 correlation rules for IOC grouping
"""

import logging
from typing import List, Set, Dict

logger = logging.getLogger(__name__)


class CorrelationRules:
    """Implements correlation rules for IOC grouping."""
    
    @staticmethod
    def apply_rule1(iocs: List[Dict]) -> List[Set[str]]:
        """
        Rule 1: Shared Infrastructure Correlation
        Groups IOCs that resolve to the same IP or share resolves_to
        
        Args:
            iocs: List of enriched IOCs
            
        Returns:
            List of IOC value sets
        """
        groups = []
        # Accept multiple possible key names used across the codebase
        # e.g. `resolvesto` vs `resolves_to`, and `iocvalue` vs `ioc_value`.
        resolves_map = {}

        for ioc in iocs:
            raw = ioc.get('resolvesto') or ioc.get('resolves_to') or ''
            # Normalize to hashable string (may be list in some fixtures)
            if isinstance(raw, list):
                resolves_to = (raw[0] if raw else '')
            else:
                resolves_to = raw
            if not isinstance(resolves_to, str):
                resolves_to = str(resolves_to) if resolves_to else ''
            ioc_value = ioc.get('iocvalue') or ioc.get('ioc_value')

            if not ioc_value:
                continue

            if resolves_to and resolves_to not in ['', '0.0.0.0']:
                if resolves_to not in resolves_map:
                    resolves_map[resolves_to] = set()
                resolves_map[resolves_to].add(ioc_value)

        for resolves_to, ioc_set in resolves_map.items():
            if len(ioc_set) > 1:
                groups.append(ioc_set)

        return groups
    
    @staticmethod
    def apply_rule2(iocs: List[Dict]) -> List[Set[str]]:
        """
        Rule 2: Malware Family Correlation
        Groups IOCs with the same malware family
        
        Args:
            iocs: List of enriched IOCs
            
        Returns:
            List of IOC value sets
        """
        groups = []

        family_map = {}
        for ioc in iocs:
            family = ioc.get('malwarefamily') or ioc.get('malware_family') or 'UNKNOWN'
            ioc_value = ioc.get('iocvalue') or ioc.get('ioc_value')

            if not ioc_value:
                continue

            if family and family != 'UNKNOWN':
                if family not in family_map:
                    family_map[family] = set()
                family_map[family].add(ioc_value)

        for family, ioc_set in family_map.items():
            if len(ioc_set) > 1:
                groups.append(ioc_set)

        return groups

    # Backwards-compatible aliases (older code may call these)
    @staticmethod
    def apply_rule_1(iocs: List[Dict]) -> List[Set[str]]:
        return CorrelationRules.apply_rule1(iocs)

    @staticmethod
    def apply_rule_2(iocs: List[Dict]) -> List[Set[str]]:
        return CorrelationRules.apply_rule2(iocs)
