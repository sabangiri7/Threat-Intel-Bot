# PLATFORM_JSON_SCHEMA

This document describes the structure of `output/platform_snapshot.json`.

The schema is inspired by STIX concepts (indicator intelligence, malware context, incident/campaign-style grouping), but it is intentionally **project-specific** for this FYP implementation.

## Top-Level Structure

```json
{
  "platform_version": "1.0.0",
  "generated_at": "2026-03-11T07:43:29.198097+00:00",
  "source_system": "FYP-ThreatIntelBot",
  "summary": { ... },
  "iocs": [ ... ],
  "incidents": [ ... ]
}
```

### Top-Level Field Notes

- `platform_version`: schema version
- `generated_at`: UTC generation timestamp (ISO 8601)
- `source_system`: producer identifier
- `summary`: aggregate counts/statistics
- `iocs`: enriched IOC records
- `incidents`: correlated incident records

## `summary` Schema

Typical fields:

- `total_iocs`
- `total_incidents`
- `critical_incidents`
- `high_incidents`
- `medium_incidents`
- `low_incidents`
- `campaigns_detected`
- `unique_malware_families`

## `iocs` Array Schema

Each object in `iocs` represents one enriched IOC.

```json
{
  "ioc_value": "malware-c2-0.com",
  "ioc_type": "domain",
  "unified_confidence": 85.0,
  "triage_action": "BLOCK",
  "malware_family": "Trojan.A",
  "resolves_to": "192.168.1.10",
  "api_results": { ... },
  "cached_at": "2026-01-07T12:00:00Z",
  "stale": false
}
```

### IOC Field Notes

- `ioc_value`, `ioc_type`: indicator identity
- `unified_confidence`: normalized confidence output
- `triage_action`: IOC-level recommendation
- `malware_family`: inferred/known family (or unknown)
- `resolves_to`: optional infrastructure resolution
- `api_results`: per-source enrichment payload
- `cached_at`, `stale`: permanent-cache metadata

## `incidents` Array Schema

Each object in `incidents` represents one correlated incident group.

```json
{
  "incident_id": "INC-0001",
  "severity": "CRITICAL",
  "risk_score": 100.0,
  "ioc_count": 5,
  "ioc_values": [
    "malware-c2-0.com",
    "malware-c2-1.com"
  ],
  "malware_family": "UNKNOWN",
  "rules_matched": ["shared_infrastructure"],
  "recommended_action": "Severity: CRITICAL | Risk confidence: 90.0%",
  "reasoning": "Correlated 5 IOCs; High confidence sources detected"
}
```

### Incident Field Notes

- `incident_id`: group identifier
- `severity`, `risk_score`: triage and prioritization signals
- `ioc_count`, `ioc_values`: incident membership
- `malware_family`: primary family label (if available)
- `rules_matched`: correlation rules that contributed
- `recommended_action`: analyst-facing guidance
- `reasoning`: explainable score narrative

