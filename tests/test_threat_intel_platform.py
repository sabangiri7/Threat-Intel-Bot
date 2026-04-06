"""
Tests for Threat Intelligence Platform generator.

Covers:
  - Top-level schema validation
  - Summary accuracy vs IOC/incident counts
  - IOC entry required fields
  - Incident entry required fields
  - No-correlation mode produces zero incidents
  - Load helpers accept multiple formats
  - Malware family extraction
"""

import json
import os
import tempfile
from datetime import datetime, timezone

import pytest

from src.platform.threat_intel_platform import (
    generate_platform_json,
    load_iocs_from_file,
    generate_demo_iocs,
    save_platform_json,
    _build_ioc_entry,
    _build_summary,
    PLATFORM_VERSION,
    SOURCE_SYSTEM,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_enriched_iocs():
    """Minimal enriched IOC list in underscore-key format."""
    return [
        {
            "ioc_value": "10.0.0.1",
            "ioc_type": "ip",
            "unified_confidence": 0.85,
            "triage_action": "BLOCK",
            "api_results": {
                "virustotal": {"status": "success", "detections": 20},
                "threatfox": {"status": "success", "malware": "Emotet", "confidence_level": 95},
                "otx": {"status": "success", "pulse_count": 3},
                "abuseipdb": {"status": "success", "abuse_confidence_score": 90},
            },
            "malware_family": "Emotet",
            "resolves_to": "",
            "timestamp": "2026-03-01T12:00:00+00:00",
        },
        {
            "ioc_value": "evil.example.com",
            "ioc_type": "domain",
            "unified_confidence": 0.40,
            "triage_action": "MONITOR",
            "api_results": {
                "virustotal": {"status": "success", "detections": 2},
                "otx": {"status": "success", "pulse_count": 1},
                "threatfox": {"status": "not_found"},
            },
            "timestamp": "2026-03-01T12:05:00+00:00",
        },
        {
            "ioc_value": "8.8.8.8",
            "ioc_type": "ip",
            "unified_confidence": 0.0,
            "triage_action": "IGNORE",
            "api_results": {
                "virustotal": {"status": "success", "detections": 0},
                "otx": {"status": "success", "pulse_count": 0},
                "threatfox": {"status": "not_found"},
                "abuseipdb": {"status": "success", "abuse_confidence_score": 0},
            },
            "timestamp": "2026-03-01T12:10:00+00:00",
        },
    ]


# ── Tests ────────────────────────────────────────────────────────────────────

class TestTopLevelSchema:
    """The platform JSON must contain all required top-level fields."""

    def test_required_fields_present(self, sample_enriched_iocs):
        platform = generate_platform_json(sample_enriched_iocs, run_correlation=False)
        for key in ("platform_version", "generated_at", "source_system", "summary", "iocs", "incidents"):
            assert key in platform, f"Missing top-level key: {key}"

    def test_version_and_source(self, sample_enriched_iocs):
        platform = generate_platform_json(sample_enriched_iocs, run_correlation=False)
        assert platform["platform_version"] == PLATFORM_VERSION
        assert platform["source_system"] == SOURCE_SYSTEM

    def test_generated_at_is_iso(self, sample_enriched_iocs):
        platform = generate_platform_json(sample_enriched_iocs, run_correlation=False)
        datetime.fromisoformat(platform["generated_at"])


class TestSummaryAccuracy:
    """Summary counts must match the actual IOC and incident arrays."""

    def test_total_iocs_matches(self, sample_enriched_iocs):
        platform = generate_platform_json(sample_enriched_iocs, run_correlation=False)
        assert platform["summary"]["total_iocs"] == len(platform["iocs"])

    def test_no_correlation_zero_incidents(self, sample_enriched_iocs):
        platform = generate_platform_json(sample_enriched_iocs, run_correlation=False)
        assert platform["summary"]["total_incidents"] == 0
        assert platform["incidents"] == []


class TestIOCEntryFields:
    """Each IOC entry must have all required fields."""

    REQUIRED_FIELDS = [
        "ioc_value", "ioc_type", "unified_confidence",
        "triage_action", "malware_family", "api_results",
        "cached_at", "stale",
    ]

    def test_all_fields_present(self, sample_enriched_iocs):
        platform = generate_platform_json(sample_enriched_iocs, run_correlation=False)
        for ioc in platform["iocs"]:
            for field in self.REQUIRED_FIELDS:
                assert field in ioc, f"IOC entry missing field: {field}"

    def test_malware_family_extracted(self, sample_enriched_iocs):
        platform = generate_platform_json(sample_enriched_iocs, run_correlation=False)
        families = [ioc["malware_family"] for ioc in platform["iocs"]]
        assert "Emotet" in families


class TestIncidentEntryFields:
    """Incident entries must have all required fields when correlation runs."""

    REQUIRED_FIELDS = [
        "incident_id", "severity", "risk_score", "ioc_count",
        "malware_family", "rules_matched", "recommended_action", "reasoning",
    ]

    def test_incident_fields_from_demo(self):
        iocs = generate_demo_iocs(20)
        platform = generate_platform_json(iocs, run_correlation=True)
        assert len(platform["incidents"]) > 0
        for inc in platform["incidents"]:
            for field in self.REQUIRED_FIELDS:
                assert field in inc, f"Incident entry missing field: {field}"


class TestLoadHelpers:
    """load_iocs_from_file must accept multiple JSON formats."""

    def test_load_dict_with_iocs_key(self, tmp_path):
        data = {"iocs": [{"ioc_value": "1.2.3.4", "ioc_type": "ip"}]}
        f = tmp_path / "test.json"
        f.write_text(json.dumps(data))
        result = load_iocs_from_file(str(f))
        assert len(result) == 1

    def test_load_flat_list(self, tmp_path):
        data = [{"ioc_value": "1.2.3.4", "ioc_type": "ip"}]
        f = tmp_path / "test.json"
        f.write_text(json.dumps(data))
        result = load_iocs_from_file(str(f))
        assert len(result) == 1


class TestSaveAndLoad:
    """Platform JSON round-trips through save + file read."""

    def test_save_creates_valid_json(self, sample_enriched_iocs, tmp_path):
        platform = generate_platform_json(sample_enriched_iocs, run_correlation=False)
        out = tmp_path / "out.json"
        save_platform_json(platform, str(out))
        reloaded = json.loads(out.read_text())
        assert reloaded["platform_version"] == PLATFORM_VERSION
        assert len(reloaded["iocs"]) == len(sample_enriched_iocs)
