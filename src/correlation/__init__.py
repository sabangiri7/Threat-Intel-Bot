"""
Correlation Module
Orchestrates IOC correlation, clustering, and scoring
"""

from src.correlation.rules import CorrelationRules
from src.correlation.scorer import CorrelationScorer
from src.correlation.engine.engine import correlate_iocs, CorrelationEngine

__all__ = ['CorrelationRules', 'CorrelationScorer', 'correlate_iocs', 'CorrelationEngine']
