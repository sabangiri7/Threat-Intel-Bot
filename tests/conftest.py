"""
Pytest Configuration and Fixtures
Mock API responses for Phase 2 enrichment testing
"""

import pytest
import json
from unittest.mock import Mock, patch
from datetime import datetime, timezone


# ============================================================================
# VIRUSTOTAL MOCK RESPONSES
# ============================================================================

@pytest.fixture
def mock_virustotal_response():
    """Mock VirusTotal API response."""
    return {
        'data': {
            'attributes': {
                'last_analysis_stats': {
                    'malicious': 5,
                    'suspicious': 2,
                    'undetected': 60
                },
                'last_analysis_date': 1672531200,
                'categories': {
                    'Avast': 'malware'
                }
            }
        }
    }


@pytest.fixture
def mock_virustotal_ip_response():
    """Mock VirusTotal IP lookup response."""
    return {
        'data': {
            'attributes': {
                'last_analysis_stats': {
                    'malicious': 3,
                    'suspicious': 1,
                    'undetected': 70
                },
                'last_analysis_date': 1672531200,
                'country': 'US'
            }
        }
    }


@pytest.fixture
def mock_virustotal_error():
    """Mock VirusTotal error response."""
    return {
        'error': {
            'code': 'NotFoundError',
            'message': 'Resource not found'
        }
    }


# ============================================================================
# ALIENAULT OTX MOCK RESPONSES
# ============================================================================

@pytest.fixture
def mock_otx_response():
    """Mock AlienVault OTX API response."""
    return {
        'pulse_info': {
            'count': 2,
            'pulses': [
                {
                    'name': 'Malware Campaign Alpha',
                    'description': 'Known malware distribution'
                },
                {
                    'name': 'Botnet Infrastructure',
                    'description': 'C2 server indicators'
                }
            ]
        },
        'validation': [],
        'reputation': -1,
        'type_tags': ['malware', 'c2']
    }


@pytest.fixture
def mock_otx_domain_response():
    """Mock OTX domain response."""
    return {
        'pulse_info': {
            'count': 1,
            'pulses': [
                {
                    'name': 'Phishing Campaign Beta',
                    'description': 'Phishing infrastructure'
                }
            ]
        },
        'validation': [],
        'reputation': -2
    }


@pytest.fixture
def mock_otx_clean_response():
    """Mock OTX clean response (no pulses)."""
    return {
        'pulse_info': {
            'count': 0,
            'pulses': []
        },
        'validation': [],
        'reputation': 0
    }


# ============================================================================
# THREATFOX MOCK RESPONSES
# ============================================================================

@pytest.fixture
def mock_threatfox_response():
    """Mock ThreatFox API response."""
    return {
        'query_status': 'ok',
        'data': {
            'ioc': '192.168.1.1',
            'ioc_type': 'ip:port',
            'threat_type': 'botnet_cc',
            'threat_type_desc': 'Botnet C&C Server',
            'malware': 'Emotet',
            'malware_printable': 'Emotet',
            'malware_alias': 'Win32.Emotet',
            'confidence_level': 100,
            'last_submission_date': '2024-01-15T10:30:00+00:00',
            'tags': ['botnet', 'banking-trojan']
        }
    }


@pytest.fixture
def mock_threatfox_url_response():
    """Mock ThreatFox URL response."""
    return {
        'query_status': 'ok',
        'data': {
            'ioc': 'http://malicious.com/payload',
            'ioc_type': 'url',
            'threat_type': 'malware_download',
            'threat_type_desc': 'Malware Download URL',
            'malware': 'TrickBot',
            'malware_printable': 'TrickBot',
            'confidence_level': 95,
            'last_submission_date': '2024-01-14T08:15:00+00:00',
            'tags': ['malware', 'trojan']
        }
    }


@pytest.fixture
def mock_threatfox_not_found():
    """Mock ThreatFox not found response."""
    return {
        'query_status': 'ok',
        'data': []
    }


# ============================================================================
# ABUSEIPDB MOCK RESPONSES
# ============================================================================

@pytest.fixture
def mock_abuseipdb_response():
    """Mock AbuseIPDB API response."""
    return {
        'data': {
            'ipAddress': '192.168.1.100',
            'abuseConfidenceScore': 75,
            'totalReports': 12,
            'distinctUsers': 8,
            'lastReportedAt': '2024-01-15T14:30:00+00:00',
            'isWhitelisted': False,
            'usageType': 'Commercial',
            'isp': 'Example ISP',
            'countryName': 'United States',
            'reports': [
                {
                    'reportedAt': '2024-01-15T14:30:00+00:00',
                    'comment': 'SSH brute force attempt',
                    'categories': [18, 22]
                }
            ]
        }
    }


@pytest.fixture
def mock_abuseipdb_clean():
    """Mock AbuseIPDB clean IP response."""
    return {
        'data': {
            'ipAddress': '8.8.8.8',
            'abuseConfidenceScore': 0,
            'totalReports': 0,
            'distinctUsers': 0,
            'lastReportedAt': None,
            'isWhitelisted': False,
            'usageType': 'Data Center',
            'isp': 'Google',
            'countryName': 'United States'
        }
    }


@pytest.fixture
def mock_abuseipdb_error():
    """Mock AbuseIPDB error response."""
    return {
        'errors': [
            {
                'detail': 'Invalid IP address'
            }
        ]
    }


# ============================================================================
# SAMPLE IOC DATA
# ============================================================================

@pytest.fixture
def sample_ioc_malicious_ip():
    """Sample malicious IP IOC."""
    return {
        'ioc_value': '192.168.1.100',
        'ioc_type': 'IP',
        'source': 'test'
    }


@pytest.fixture
def sample_ioc_clean_ip():
    """Sample clean IP IOC."""
    return {
        'ioc_value': '8.8.8.8',
        'ioc_type': 'IP',
        'source': 'test'
    }


@pytest.fixture
def sample_ioc_malicious_domain():
    """Sample malicious domain IOC."""
    return {
        'ioc_value': 'malicious.com',
        'ioc_type': 'domain',
        'source': 'test'
    }


@pytest.fixture
def sample_ioc_clean_domain():
    """Sample clean domain IOC."""
    return {
        'ioc_value': 'google.com',
        'ioc_type': 'domain',
        'source': 'test'
    }


@pytest.fixture
def sample_ioc_malicious_url():
    """Sample malicious URL IOC."""
    return {
        'ioc_value': 'http://malicious.com/payload',
        'ioc_type': 'URL',
        'source': 'test'
    }


@pytest.fixture
def sample_ioc_malicious_hash():
    """Sample malicious hash IOC."""
    return {
        'ioc_value': 'd41d8cd98f00b204e9800998ecf8427e',
        'ioc_type': 'hash',
        'source': 'test'
    }


# ============================================================================
# ENRICHMENT RESULT FIXTURES
# ============================================================================

@pytest.fixture
def enriched_result_malicious():
    """Sample enriched malicious IOC result."""
    return {
        'ioc_value': '192.168.1.100',
        'ioc_type': 'IP',
        'unified_confidence': 0.75,
        'triage_action': 'BLOCK',
        'api_results': {
            'virustotal': {'status': 'success', 'confidence': 0.6},
            'otx': {'status': 'success', 'confidence': 0.8},
            'threatfox': {'status': 'success', 'confidence': 0.9},
            'abuseipdb': {'status': 'success', 'confidence': 0.75}
        },
        'timestamp': datetime.now(timezone.utc).isoformat()
    }


@pytest.fixture
def enriched_result_clean():
    """Sample enriched clean IOC result."""
    return {
        'ioc_value': '8.8.8.8',
        'ioc_type': 'IP',
        'unified_confidence': 0.05,
        'triage_action': 'IGNORE',
        'api_results': {
            'virustotal': {'status': 'success', 'confidence': 0.0},
            'otx': {'status': 'success', 'confidence': 0.0},
            'threatfox': {'status': 'success', 'confidence': 0.1},
            'abuseipdb': {'status': 'success', 'confidence': 0.0}
        },
        'timestamp': datetime.now(timezone.utc).isoformat()
    }


@pytest.fixture
def enriched_result_suspicious():
    """Sample enriched suspicious IOC result."""
    return {
        'ioc_value': 'example.com',
        'ioc_type': 'domain',
        'unified_confidence': 0.45,
        'triage_action': 'MONITOR',
        'api_results': {
            'virustotal': {'status': 'success', 'confidence': 0.4},
            'otx': {'status': 'success', 'confidence': 0.5},
            'threatfox': {'status': 'success', 'confidence': 0.45},
            'abuseipdb': {'status': 'success', 'confidence': 0.0}
        },
        'timestamp': datetime.now(timezone.utc).isoformat()
    }


# ============================================================================
# PYTEST MARKERS
# ============================================================================

def pytest_configure(config):
    """Register custom pytest markers."""
    config.addinivalue_line("markers", "unit: unit test")
    config.addinivalue_line("markers", "integration: integration test")
    config.addinivalue_line("markers", "api: API-related test")
    config.addinivalue_line("markers", "cache: cache-related test")
    config.addinivalue_line("markers", "enrichment: enrichment-related test")