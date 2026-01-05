"""Unit tests for Phase 2 IOC Enrichment Engine"""

import pytest
from src.enrichment.enrichment import IOCEnricher


class TestIOCEnricher:
    """Test suite for IOCEnricher class"""

    @pytest.fixture
    def enricher(self):
        """Create enricher instance for each test"""
        return IOCEnricher()

    def test_enrich_ip_returns_valid_schema(self, enricher):
        """Test enriching IP returns all required fields"""
        result = enricher.enrich_ioc("8.8.8.8", "ip")
        
        required_fields = [
            "ioc_value", "ioc_type", "unified_confidence",
            "triage_action", "timestamp", "api_results"
        ]
        
        for field in required_fields:
            assert field in result, f"Missing field: {field}"

    def test_confidence_always_in_valid_range(self, enricher):
        """Confidence score must be [0.0, 1.0]"""
        test_iocs = [
            ("8.8.8.8", "ip"),
            ("google.com", "domain"),
            ("192.168.1.1", "ip"),
        ]
        
        for ioc_value, ioc_type in test_iocs:
            result = enricher.enrich_ioc(ioc_value, ioc_type)
            conf = result["unified_confidence"]
            assert 0.0 <= conf <= 1.0, f"Invalid confidence: {conf}"

    def test_triage_action_matches_confidence(self, enricher):
        """Triage action must follow confidence thresholds"""
        result = enricher.enrich_ioc("192.168.1.1", "ip")
        
        conf = result["unified_confidence"]
        action = result["triage_action"]
        
        if conf >= 0.70:
            assert action == "BLOCK", f"conf={conf} should be BLOCK, got {action}"
        elif conf >= 0.30:
            assert action == "MONITOR", f"conf={conf} should be MONITOR, got {action}"
        else:
            assert action == "IGNORE", f"conf={conf} should be IGNORE, got {action}"

    def test_batch_enrichment_returns_list(self, enricher):
        """Batch enrichment should return list of enriched IOCs"""
        iocs = [
            {"ioc_value": "8.8.8.8", "ioc_type": "ip"},
            {"ioc_value": "google.com", "ioc_type": "domain"},
        ]
        
        results = enricher.enrich_batch(iocs)
        
        assert isinstance(results, list), "Batch should return list"
        assert len(results) == len(iocs), "Output count should match input"

    def test_batch_enrichment_preserves_ioc_identity(self, enricher):
        """Each enriched IOC should preserve original value and type"""
        iocs = [
            {"ioc_value": "8.8.8.8", "ioc_type": "ip"},
            {"ioc_value": "google.com", "ioc_type": "domain"},
        ]
        
        results = enricher.enrich_batch(iocs)
        
        for original, enriched in zip(iocs, results):
            assert enriched["ioc_value"] == original["ioc_value"]
            assert enriched["ioc_type"] == original["ioc_type"]

    def test_cache_stats_structure(self, enricher):
        """Cache statistics should have required fields"""
        stats = enricher.get_cache_stats()
        
        required = ["hits", "misses", "hit_rate", "current_size", "max_size"]
        for field in required:
            assert field in stats, f"Missing stats field: {field}"

    def test_api_results_structure(self, enricher):
        """API results should have entries for each handler"""
        result = enricher.enrich_ioc("8.8.8.8", "ip")
        
        api_results = result["api_results"]
        expected_sources = ["virustotal", "otx", "threatfox", "abuseipdb"]
        
        for source in expected_sources:
            assert source in api_results, f"Missing source: {source}"
            assert "status" in api_results[source], f"Missing status for {source}"

    def test_error_handling_invalid_ioc_type(self, enricher):
        """Error handling for invalid IOC types"""
        # Test with invalid IOC type
        result = enricher.enrich_ioc("8.8.8.8", "invalid_type")
        
        # Should still return a result, but may have errors in API results
        assert "ioc_value" in result
        assert "ioc_type" in result
        # API handlers may return errors, but structure should be valid
        assert "api_results" in result
