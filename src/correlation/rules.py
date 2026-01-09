"""
Correlation Rules - Phase 3.1 Week 6
Implements 2 correlation rules for IOC grouping
"""

import logging
from typing import List, Set, Dict

logger = logging.getLogger(__name__)


class CorrelationRules:
    """Implements correlation rules for IOC grouping."""
    
    def apply_rule1(self, iocs: List[Dict]) -> List[Set[str]]:
        """
        Rule 1: Shared Infrastructure Correlation
        Groups IOCs that resolve to the same IP or share resolves_to
        
        Args:
            iocs: List of enriched IOCs
            
        Returns:
            List of IOC value sets
        """
        groups = []
        processed = set()
        
        # Group by resolves_to
        resolves_map = {}
        for ioc in iocs:
            resolves_to = ioc.get('resolvesto', '')
            if resolves_to and resolves_to not in ['', '0.0.0.0']:
                if resolves_to not in resolves_map:
                    resolves_map[resolves_to] = set()
                resolves_map[resolves_to].add(ioc['iocvalue'])
                processed.add(ioc['iocvalue'])
        
        # Add groups with 2+ IOCs
        for resolves_to, ioc_set in resolves_map.items():
            if len(ioc_set) > 1:
                groups.append(ioc_set)
        
        return groups
    
    def apply_rule2(self, iocs: List[Dict]) -> List[Set[str]]:
        """
        Rule 2: Malware Family Correlation
        Groups IOCs with the same malware family
        
        Args:
            iocs: List of enriched IOCs
            
        Returns:
            List of IOC value sets
        """
        groups = []
        
        # Group by malware family
        family_map = {}
        for ioc in iocs:
            family = ioc.get('malwarefamily', 'UNKNOWN')
            if family != 'UNKNOWN':
                if family not in family_map:
                    family_map[family] = set()
                family_map[family].add(ioc['iocvalue'])
        
        # Add groups with 2+ IOCs
        for family, ioc_set in family_map.items():
            if len(ioc_set) > 1:
                groups.append(ioc_set)
        
        return groups
