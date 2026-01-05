"""
Tests for Enrichment Module API Handlers
Tests VirusTotal, OTX, ThreatFox, and AbuseIPDB handlers
"""

import sys
from pathlib import Path

# Add project root to sys.path FIRST
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone

# NOW import src modules (after path is set)
from src.enrichment import IOCEnricher
from src.api_handlers.virustotal_handler import VirusTotalHandler
from src.api_handlers.otx_handler import OTXHandler
from src.api_handlers.threatfox_handler import ThreatFoxHandler
from src.api_handlers.abuseipdb_handler import AbuseIPDBHandler

@pytest.mark.api
@pytest.mark.unit
def test_virustotal_handler_normalize(mock_virustotal_response):
    """Test VirusTotal response normalization."""
    from src.api_handlers.virustotal_handler import VirusTotalHandler
    
    handler = VirusTotalHandler()
    normalized = handler.normalize_response(mock_virustotal_response, 'hash')
    
    assert normalized['status'] == 'success'
    assert normalized['ioc_type'] == 'hash'
    assert normalized['detections'] == 5
    assert 'last_analysis_date' in normalized


@pytest.mark.api
@pytest.mark.unit
def test_otx_handler_normalize(mock_otx_response):
    """Test OTX response normalization."""
    from src.api_handlers.otx_handler import OTXHandler
    
    handler = OTXHandler()
    normalized = handler.normalize_response(mock_otx_response, 'IP')
    
    assert normalized['status'] == 'success'
    assert normalized['ioc_type'] == 'IP'
    assert normalized['pulse_count'] == 2
    assert len(normalized['pulses']) == 2


@pytest.mark.api
@pytest.mark.unit
def test_otx_clean_response(mock_otx_clean_response):
    """Test OTX clean response (no threats)."""
    from src.api_handlers.otx_handler import OTXHandler
    
    handler = OTXHandler()
    normalized = handler.normalize_response(mock_otx_clean_response, 'domain')
    
    assert normalized['status'] == 'success'
    assert normalized['pulse_count'] == 0
    assert normalized['pulses'] == []


@pytest.mark.api
@pytest.mark.unit
def test_threatfox_handler_normalize(mock_threatfox_response):
    """Test ThreatFox response normalization."""
    from src.api_handlers.threatfox_handler import ThreatFoxHandler
    
    handler = ThreatFoxHandler()
    normalized = handler.normalize_response(mock_threatfox_response)
    
    assert normalized['status'] == 'success'
    assert normalized['ioc_count'] == 1
    assert normalized['malware'] == 'Emotet'
    assert normalized['confidence_level'] == 100


@pytest.mark.api
@pytest.mark.unit
def test_threatfox_not_found(mock_threatfox_not_found):
    """Test ThreatFox not found response."""
    from src.api_handlers.threatfox_handler import ThreatFoxHandler
    
    handler = ThreatFoxHandler()
    normalized = handler.normalize_response(mock_threatfox_not_found)
    
    assert normalized['status'] == 'not_found' or normalized['ioc_count'] == 0


@pytest.mark.api
@pytest.mark.unit
def test_abuseipdb_handler_normalize(mock_abuseipdb_response):
    """Test AbuseIPDB response normalization."""
    from src.api_handlers.abuseipdb_handler import AbuseIPDBHandler
    
    handler = AbuseIPDBHandler()
    normalized = handler.normalize_response(mock_abuseipdb_response)
    
    assert normalized['status'] == 'success'
    assert normalized['ioc_type'] == 'IP'
    assert normalized['abuse_confidence_score'] == 75
    assert normalized['total_reports'] == 12


@pytest.mark.api
@pytest.mark.unit
def test_abuseipdb_clean_ip(mock_abuseipdb_clean):
    """Test AbuseIPDB clean IP response."""
    from src.api_handlers.abuseipdb_handler import AbuseIPDBHandler
    
    handler = AbuseIPDBHandler()
    normalized = handler.normalize_response(mock_abuseipdb_clean)
    
    assert normalized['status'] == 'success'
    assert normalized['abuse_confidence_score'] == 0
    assert normalized['total_reports'] == 0


@pytest.mark.enrichment
@pytest.mark.unit
def test_enrichment_with_mock_responses(
    sample_ioc_malicious_ip,
    mock_virustotal_response,
    mock_otx_response,
    mock_threatfox_response,
    mock_abuseipdb_response
):
    """Test enrichment with all mock API responses."""
    from src.enrichment import IOCEnricher
    
    enricher = IOCEnricher()
    
    # Mock the API calls
    with patch('src.api_handlers.virustotal_handler.requests.get') as mock_vt, \
         patch('src.api_handlers.otx_handler.requests.get') as mock_otx, \
         patch('src.api_handlers.threatfox_handler.requests.post') as mock_tf, \
         patch('src.api_handlers.abuseipdb_handler.requests.get') as mock_abuse:
        
        mock_vt.return_value.json.return_value = mock_virustotal_response
        mock_otx.return_value.json.return_value = mock_otx_response
        mock_tf.return_value.json.return_value = mock_threatfox_response
        mock_abuse.return_value.json.return_value = mock_abuseipdb_response
        
        # Enrich IOC
        result = enricher.enrich_ioc(
            sample_ioc_malicious_ip['ioc_value'],
            sample_ioc_malicious_ip['ioc_type']
        )
        
        assert result is not None
        assert 'unified_confidence' in result


@pytest.mark.enrichment
@pytest.mark.unit
def test_confidence_scoring(enriched_result_malicious):
    """Test confidence scoring logic."""
    from src.enrichment import IOCEnricher
    
    enricher = IOCEnricher()
    
    # Test malicious scoring
    assert enriched_result_malicious['unified_confidence'] == 0.75
    assert enriched_result_malicious['triage_action'] == 'BLOCK'


@pytest.mark.enrichment
@pytest.mark.unit
def test_triage_action_malicious(enriched_result_malicious):
    """Test triage action for malicious IOC."""
    assert enriched_result_malicious['triage_action'] == 'BLOCK'
    assert enriched_result_malicious['unified_confidence'] >= 0.7


@pytest.mark.enrichment
@pytest.mark.unit
def test_triage_action_clean(enriched_result_clean):
    """Test triage action for clean IOC."""
    assert enriched_result_clean['triage_action'] == 'IGNORE'
    assert enriched_result_clean['unified_confidence'] < 0.1


@pytest.mark.enrichment
@pytest.mark.unit
def test_triage_action_suspicious(enriched_result_suspicious):
    """Test triage action for suspicious IOC."""
    assert enriched_result_suspicious['triage_action'] == 'MONITOR'
    assert 0.3 <= enriched_result_suspicious['unified_confidence'] < 0.7
