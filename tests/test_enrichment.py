import pytest

@pytest.mark.unit
def test_virustotal_mock_shape(mock_virustotal_response):
    """Test VirusTotal mock response structure."""
    assert 'data' in mock_virustotal_response
    assert 'attributes' in mock_virustotal_response['data']
    stats = mock_virustotal_response['data']['attributes']['last_analysis_stats']
    assert stats['malicious'] == 5

@pytest.mark.api
def test_otx_mock_has_pulses(mock_otx_response):
    """Test OTX mock has pulse data."""
    assert mock_otx_response['pulse_info']['count'] == 2
    assert len(mock_otx_response['pulse_info']['pulses']) == 2

@pytest.mark.api
def test_threatfox_mock_response(mock_threatfox_response):
    """Test ThreatFox mock response structure."""
    assert mock_threatfox_response['query_status'] == 'ok'
    assert mock_threatfox_response['data']['malware'] == 'Emotet'
    assert mock_threatfox_response['data']['confidence_level'] == 100

@pytest.mark.api
def test_abuseipdb_mock_abuse_score(mock_abuseipdb_response):
    """Test AbuseIPDB mock abuse score."""
    assert mock_abuseipdb_response['data']['abuseConfidenceScore'] == 75
    assert mock_abuseipdb_response['data']['totalReports'] == 12

@pytest.mark.unit
def test_enriched_result_malicious(enriched_result_malicious):
    """Test enriched malicious result."""
    assert enriched_result_malicious['triage_action'] == 'BLOCK'
    assert enriched_result_malicious['unified_confidence'] == 0.75

@pytest.mark.unit
def test_enriched_result_clean(enriched_result_clean):
    """Test enriched clean result."""
    assert enriched_result_clean['triage_action'] == 'IGNORE'
    assert enriched_result_clean['unified_confidence'] == 0.05

@pytest.mark.unit
def test_sample_ioc_malicious(sample_ioc_malicious_ip):
    """Test sample malicious IP IOC."""
    assert sample_ioc_malicious_ip['ioc_type'] == 'IP'
    assert '192.168.1.100' in sample_ioc_malicious_ip['ioc_value']
