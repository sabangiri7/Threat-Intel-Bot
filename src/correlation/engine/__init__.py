"""
Correlation Engine Module
Orchestrates IOC correlation, clustering, and scoring
"""

from src.correlation.engine.engine import correlate_iocs, CorrelationEngine

__all__ = ['correlate_iocs', 'CorrelationEngine']
