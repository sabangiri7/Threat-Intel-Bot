"""
Correlation Engine - Phase 3.1 Week 6
Implements Union-Find clustering and orchestrates Rules + Scoring
"""

import logging
from typing import List, Dict, Set
from datetime import datetime, timezone

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class UnionFind:
    """
    Union-Find (Disjoint Set Union) data structure for efficient clustering.
    Used for deduplicating IOCs across multiple correlation rules.
    
    Time Complexity: O(α(n)) ≈ O(1) amortized
    Space Complexity: O(n)
    """
    
    def __init__(self, elements: List[str]):
        """
        Initialize Union-Find structure.
        
        Args:
            elements: List of IOC values to track
        """
        self.parent = {elem: elem for elem in elements}
        self.rank = {elem: 0 for elem in elements}
        self.size = {elem: 1 for elem in elements}
        logger.info(f"UnionFind initialized with {len(elements)} elements")
    
    def find(self, x: str) -> str:
        """
        Find root parent of element (path compression).
        
        Args:
            x: Element to find
            
        Returns:
            Root parent of element
        """
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])  # Path compression
        return self.parent[x]
    
    def union(self, x: str, y: str) -> bool:
        """
        Union two sets by root (union by rank).
        
        Args:
            x: First element
            y: Second element
            
        Returns:
            True if merged, False if already connected
        """
        root_x = self.find(x)
        root_y = self.find(y)
        
        if root_x == root_y:
            return False
        
        # Union by rank (attach smaller tree to larger)
        if self.rank[root_x] < self.rank[root_y]:
            self.parent[root_x] = root_y
            self.size[root_y] += self.size[root_x]
        elif self.rank[root_x] > self.rank[root_y]:
            self.parent[root_y] = root_x
            self.size[root_x] += self.size[root_y]
        else:
            self.parent[root_y] = root_x
            self.rank[root_x] += 1
            self.size[root_x] += self.size[root_y]
        
        return True
    
    def connected(self, x: str, y: str) -> bool:
        """Check if two elements are in same set."""
        return self.find(x) == self.find(y)
    
    def get_clusters(self, iocs_dict: Dict[str, Dict]) -> List[List[Dict]]:
        """
        Get clusters of IOCs based on union-find structure.
        
        Args:
            iocs_dict: Map of IOC value to IOC dict
            
        Returns:
            List of clusters (each cluster is list of IOCs)
        """
        clusters_map = {}
        
        for ioc_value, ioc_data in iocs_dict.items():
            root = self.find(ioc_value)
            if root not in clusters_map:
                clusters_map[root] = []
            clusters_map[root].append(ioc_data)
        
        return list(clusters_map.values())


class CorrelationEngine:
    """
    Main orchestrator combining Rules + Scoring + Clustering.
    Processes enriched IOCs into incident groups.
    """
    
    def __init__(self):
        """Initialize correlation engine."""
        logger.info("Initializing Correlation Engine")
        
        # Import here to avoid circular imports - use absolute imports
        from src.correlation.rules import CorrelationRules
        from src.correlation.scorer import CorrelationScorer
        
        self.rules = CorrelationRules()
        self.scorer = CorrelationScorer()
    
    def correlate(self, iocs: List[Dict]) -> List[Dict]:
        """
        Main correlation orchestrator.
        
        Args:
            iocs: List of enriched IOC dictionaries
            
        Returns:
            List of incident groups with scores
        """
        logger.info(f"Starting correlation for {len(iocs)} IOCs")
        
        # Step 1: Apply correlation rules
        correlation_groups = self._apply_rules(iocs)
        
        # Step 2: Merge and deduplicate
        merged_groups = self._merge_and_deduplicate(correlation_groups, iocs)
        
        # Step 3: Apply Union-Find clustering
        final_clusters = self._apply_clustering(iocs, merged_groups)
        
        # Step 4: Score incident groups
        incidents = self._score_incidents(final_clusters, iocs)
        
        logger.info(f"Total incidents processed: {len(incidents)}")
        
        return incidents
    
    def _apply_rules(self, iocs: List[Dict]) -> List[Set[str]]:
        """
        Apply all correlation rules.
        
        Args:
            iocs: List of enriched IOCs
            
        Returns:
            List of IOC value sets (groups)
        """
        groups = []
        
        # Rule 1: Shared Infrastructure
        logger.info("Applying Rule 1: Shared Infrastructure Correlation")
        rule1_groups = self.rules.apply_rule1(iocs)
        logger.info(f"Rule 1 generated {len(rule1_groups)} groups")
        groups.extend(rule1_groups)
        
        # Rule 2: Malware Family
        logger.info("Applying Rule 2: Malware Family Correlation")
        rule2_groups = self.rules.apply_rule2(iocs)
        logger.info(f"Rule 2 generated {len(rule2_groups)} groups")
        groups.extend(rule2_groups)
        
        return groups
    
    def _merge_and_deduplicate(self, groups: List[Set[str]], iocs: List[Dict]) -> List[Set[str]]:
        """
        Merge overlapping groups and deduplicate.
        
        Args:
            groups: List of IOC value sets
            iocs: Original IOC list
            
        Returns:
            Deduplicated groups
        """
        logger.info("Merging rules and deduplicating")
        
        if not groups:
            logger.info("No groups from rules, using individual IOCs")
            return []
        
        # Create Union-Find for merging
        all_values = set()
        for group in groups:
            all_values.update(group)
        
        if not all_values:
            return []
        
        all_values_list = list(all_values)
        uf = UnionFind(all_values_list)
        
        # Merge overlapping groups
        for group in groups:
            group_list = list(group)
            if len(group_list) > 0:
                first = group_list[0]
                for i in range(1, len(group_list)):
                    uf.union(first, group_list[i])
        
        # Extract merged groups - use dict with string keys
        merged = {}
        for value in all_values_list:
            root = uf.find(value)
            if root not in merged:
                merged[root] = set()
            merged[root].add(value)
        
        result = list(merged.values())
        logger.info(f"After merge: {len(result)} groups")
        
        return result
    
    def _apply_clustering(self, iocs: List[Dict], rule_groups: List[Set[str]]) -> List[List[Dict]]:
        """
        Apply Union-Find clustering including unclustered IOCs.
        
        Args:
            iocs: Original IOC list
            rule_groups: Groups from rules
            
        Returns:
            List of IOC clusters
        """
        logger.info("Applying Union-Find clustering")
        
        # Get all IOC values
        ioc_values = [ioc['iocvalue'] for ioc in iocs]
        uf = UnionFind(ioc_values)
        
        # Union based on rule groups
        for group in rule_groups:
            group_list = list(group)
            if len(group_list) > 0:
                first = group_list[0]
                for i in range(1, len(group_list)):
                    uf.union(first, group_list[i])
        
        # Create iocs dict by value
        iocs_dict = {ioc['iocvalue']: ioc for ioc in iocs}
        
        # Get clusters
        clusters = uf.get_clusters(iocs_dict)
        
        logger.info(f"After Union-Find: {len(clusters)} final groups")
        
        return clusters
    
    def _score_incidents(self, clusters: List[List[Dict]], all_iocs: List[Dict]) -> List[Dict]:
        """
        Score incident groups.
        
        Args:
            clusters: List of IOC clusters
            all_iocs: Original IOC list
            
        Returns:
            List of scored incidents
        """
        logger.info("Scoring incident groups")
        
        incidents = []
        
        for idx, cluster in enumerate(clusters):
            incident_id = f"INC-{idx+1:04d}"
            
            # Extract group info
            ioc_values = [ioc['iocvalue'] for ioc in cluster]
            ioc_types = list(set(ioc['ioctype'] for ioc in cluster))
            malware_families = list(set(
                ioc['malwarefamily'] for ioc in cluster 
                if ioc.get('malwarefamily', 'UNKNOWN') != 'UNKNOWN'
            ))
            
            if not malware_families:
                malware_families = ['UNKNOWN']
            
            # Score the group
            score = self.scorer.scoregroup(cluster)
            
            incident = {
                'incident_id': incident_id,
                'group_size': len(cluster),
                'ioc_values': ioc_values,
                'ioc_types': ioc_types,
                'malware_families': malware_families,
                'score': score
            }
            
            incidents.append(incident)
        
        logger.info(f"Generated {len(incidents)} incident groups")
        
        return incidents


def correlate_iocs(iocs: List[Dict]) -> List[Dict]:
    """
    Public API for IOC correlation.
    
    Args:
        iocs: List of enriched IOC dictionaries
        
    Returns:
        List of incident groups with scores
    """
    engine = CorrelationEngine()
    return engine.correlate(iocs)
