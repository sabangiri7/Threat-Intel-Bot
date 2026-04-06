# Threat-Intel-Bot: Full Comprehensive Project Overview

This document is a consolidated, code-aligned overview of the repository, generated from:

- Project documentation (`README.md`, `CHANGELOG.md`, `LIMITATIONS.md`, `PLATFORM_JSON_SCHEMA.md`, `WAZUH_INTEGRATION.md`, docs and reports markdown files)
- Core implementation code in `src/` and `scripts/`

It is intended as a single internal reference for understanding what the project does, how it works, and what is implemented vs planned.

---

## 1) Project purpose and scope

Threat-Intel-Bot is a Python Final Year Project focused on SOC-style intelligence workflow automation:

1. Accept IOCs (IP/domain/URL/hash)
2. Enrich from multiple OSINT providers
3. Compute a unified confidence score and IOC triage action
4. Correlate related IOCs into incidents
5. Export a platform snapshot JSON artifact
6. Optionally convert incidents to Wazuh-friendly NDJSON log lines

### In-scope

- OSINT enrichment and normalization
- IOC triage recommendation (BLOCK/MONITOR/IGNORE)
- Incident correlation and scoring
- Incident-level recommendation generation
- Persistent cache with staleness metadata
- Streamlit dashboard for analyst workflow
- Lab-only Wazuh integration
- Report export helpers (JSON/PDF/CSV)

### Out-of-scope / constraints

- No binary reverse engineering or malware detonation
- No production SIEM hardening and no enterprise HA/governance pipeline
- No autonomous blocking/remediation actions (advisory system)
- External API dependence and rate-limit constraints

---

## 2) High-level architecture

Main data path:

`IOC input -> Enrichment -> Cache -> Correlation -> Decision -> Platform snapshot -> Wazuh NDJSON (optional)`

### Layers

- **IOC ingestion / classification**
  - Manual input, uploaded text/csv, or demo data
- **Enrichment engine**
  - `src/enrichment/enrichment.py`
  - Providers: VirusTotal, OTX, ThreatFox, AbuseIPDB
- **Permanent cache**
  - `src/cache/cache.py`
  - JSON persistence with freshness/stale metadata
- **Correlation engine**
  - `src/correlation/engine/engine.py`
  - Rules + Union-Find clustering + scoring
- **Decision engine**
  - `src/decision.py`
  - Incident-level recommendations
- **Platform JSON generator**
  - `src/platform/threat_intel_platform.py`
- **UI and integration**
  - Streamlit dashboard: `scripts/dashboard.py`
  - Wazuh log conversion: `scripts/generate_wazuh_logs.py`

---

## 3) Repository structure and responsibilities

## Core source

- `src/enrichment/`
  - `enrichment.py`: IOC enrichment orchestrator
  - `api.py`: stable wrapper API (`enrich_single`, `enrich_batch`, cache stats)
  - `ENRICHMENT_SCHEMA.md`: enrichment contract and scoring rules
- `src/api_handlers/`
  - `virustotal_handler.py`, `otx_handler.py`, `threatfox_handler.py`, `abuseipdb_handler.py`
- `src/cache/`
  - `cache.py`: `PermanentCache` implementation and compatibility helpers
  - `__init__.py`: exported cache APIs
- `src/cache_tools/`
  - `__main__.py`: cache CLI (`--stats`, `--purge`, `--clear`, `--export`)
- `src/correlation/`
  - `rules.py`: Rule 1 infrastructure + Rule 2 family grouping
  - `scorer.py`: incident score/severity computation
  - `engine/engine.py`: orchestration + clustering
  - `engine/demo_cli.py`: end-to-end correlation demo script
- `src/platform/`
  - `threat_intel_platform.py`: platform snapshot generation and helper mappers
  - `__main__.py`: `python -m src.platform` CLI
- `src/decision.py`
  - incident triage/recommendation engine
- `src/reporting/`
  - `report_exporter.py`: report export API wrapper

## Scripts and integration

- `scripts/dashboard.py`: Streamlit frontend
- `scripts/generate_wazuh_logs.py`: platform JSON -> NDJSON conversion
- `scripts/verify_metrics.py`: quick metrics verification utility

## Data and output

- `data/`: sample/enriched IOC input and cache files
- `output/`: generated artifacts (`platform_snapshot.json`, `intel.log`, etc.)
- `examples/`: sample platform snapshot
- `wazuh_integration/local_rules.xml`: Wazuh custom rules

## Tests

- `tests/`: enrichment, correlation, platform, cache, decision, and manual test scripts

---

## 4) Runtime entry points and commands

### Platform snapshot generation

```bash
python -m src.platform --demo 20 --output output/platform_snapshot.json
python -m src.platform --input data/sample_enriched_iocs.json --output output/platform_snapshot.json
python -m src.platform --demo 20 --no-correlation --output output/platform_snapshot.json
```

### Wazuh log generation

```bash
python scripts/generate_wazuh_logs.py --input output/platform_snapshot.json --output output/intel.log
```

### Dashboard

```bash
streamlit run scripts/dashboard.py
```

### Cache operations

```bash
python -m src.cache_tools --stats
python -m src.cache_tools --purge
python -m src.cache_tools --clear
python -m src.cache_tools --export output/cache_export.json
```

### Correlation demo

```bash
python -m src.correlation.engine.demo_cli --iocs 20
python src/correlation/engine/demo_cli.py --iocs 20
```

### Metrics helper

```bash
python scripts/verify_metrics.py
python scripts/verify_metrics.py --mock
python scripts/verify_metrics.py --clear-cache
```

---

## 5) Enrichment internals

Main class: `IOCEnricher` in `src/enrichment/enrichment.py`.

### Enrichment flow per IOC

1. Normalize IOC type to lowercase
2. Build cache key: `"{ioc_type}::{ioc_value}"`
3. Check cache (`cache_get`)
4. If miss, call handlers with `_safe_check`
5. Aggregate to `unified_confidence`
6. Map triage action:
   - `>= 0.70` -> `BLOCK`
   - `>= 0.30` -> `MONITOR`
   - `< 0.30` -> `IGNORE`
7. Save in cache (`cache_set`) and periodically persist

### Reliability behavior

- Each handler uses network timeouts (typically 10 seconds)
- Handler exceptions are normalized to structured error objects
- One failed provider does not crash the full IOC enrichment
- AbuseIPDB is queried only for IP IOC type

### Confidence model

From `IOCEnricher._compute_unified_confidence`:

- VirusTotal detections -> tiered contribution (0.00/0.25/0.45/0.60)
- OTX pulse count -> tiered contribution (0.00/0.20/0.35)
- ThreatFox success -> +0.50
- AbuseIPDB (IP only, not whitelisted) -> normalized abuse confidence
- Final score clamped to [0.0, 1.0]

Canonical schema documentation is in `src/enrichment/ENRICHMENT_SCHEMA.md`.

---

## 6) Cache internals

Cache implementation: `PermanentCache` in `src/cache/cache.py`.

### Storage format

JSON file (default `data/enrichment_cache.json`) with top-level:

```json
{
  "entries": {
    "ip::8.8.8.8": {
      "enrichment_data": { "...": "..." },
      "cached_at": "ISO timestamp",
      "stale": false
    }
  }
}
```

### Freshness and retention policy

- Default stale threshold: 7 days
- Default purge threshold: 30 days
- `get()` marks entries stale when age exceeds stale threshold
- Stale entries are still returned
- `purge_expired()` removes entries over purge threshold

### Operational features

- Legacy cache migration support from older format
- Session stats: hits, misses, stale_hits, hit_rate
- Max-size eviction of oldest entry if cache is full
- Module-level singleton APIs preserve backward compatibility

---

## 7) Correlation and incident generation

Core orchestrator: `CorrelationEngine` in `src/correlation/engine/engine.py`.

### Rule set (`src/correlation/rules.py`)

- **Rule 1: Shared infrastructure**
  - Group IOCs with same `resolvesto` / `resolves_to`
- **Rule 2: Malware family**
  - Group IOCs with same non-UNKNOWN family

### Clustering strategy

- Rules return sets of IOC values
- Overlapping groups are merged with Union-Find
- Final clustering includes ungrouped IOCs as singleton incidents

### Scoring (`src/correlation/scorer.py`)

Incident score components include:

- Base score from average confidence
- Confidence/source boosts from provider evidence
- Group size bonus
- Triage action multiplier
- Severity mapping (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
- Human-readable scoring reason string

### Incident output shape

Per incident:

- `incident_id`
- `group_size`
- `ioc_values`
- `ioc_types`
- `malware_families`
- `score` (breakdown + final score + severity + reasoning)

---

## 8) Decision engine (incident recommendations)

Implemented in `src/decision.py`.

### Recommendation classes

- `BLOCK`
- `QUARANTINE`
- `MONITOR`
- `IGNORE`

### Risk model

Combines:

- Incident score component
- Severity weight
- API consensus proxy (or provided value)

### Outputs

- Per-incident `TriageDecision`
- Aggregated `RecommendationSummary` counters

These decisions are optionally integrated into platform snapshot incident entries.

---

## 9) Platform snapshot generation

Main builder: `generate_platform_json` in `src/platform/threat_intel_platform.py`.

### Top-level schema

- `platform_version`
- `generated_at`
- `source_system`
- `summary`
- `iocs`
- `incidents`

### IOC entry composition

Built via `_build_ioc_entry`:

- Identity, confidence, triage, family, `api_results`
- Optional infrastructure resolution (`resolves_to`)
- Cache metadata (`cached_at`, `stale`) when available

### Incident entry composition

Built via `_build_incident_entry`:

- Severity, risk score, IOC count and values
- Family and matched-rule labels
- Recommended action and reasoning

Detailed schema notes are documented in `PLATFORM_JSON_SCHEMA.md`.

---

## 10) Dashboard (Streamlit) behavior

Dashboard file: `scripts/dashboard.py`.

### Current tabs

1. IOC Search
2. Upload
3. IOCs
4. API Gateway
5. SIEM Integration

### Implemented capabilities

- Load and visualize platform snapshot
- Live IOC enrichment using backend function import fallbacks
- Upload IOC file and run enrichment + platform pipeline
- Show provider-level details and raw JSON
- Track searched IOC table with CSV export
- Generate/store local API keys in `output/auth_keys.json`
- Show Wazuh script/rules content in UI panels

### Important note

- REST API commands shown in the dashboard are explicitly mock/demo style unless a separate API backend is implemented.

---

## 11) Wazuh lab integration internals

Script: `scripts/generate_wazuh_logs.py`  
Rules: `wazuh_integration/local_rules.xml`  
Guide: `WAZUH_INTEGRATION.md`

### Pipeline

1. Read platform snapshot
2. Convert each incident into one flat JSON event
3. Append events as NDJSON lines to `output/intel.log`
4. Wazuh agent tails the log and forwards to manager
5. Local rules classify alerts by source/severity/family/triage action

### Event mapping highlights

- Source fixed to `FYP-ThreatIntelBot`
- `ioc_type` inferred from IOC lookup or pattern fallback
- Triage action derived from recommended action text or severity fallback

---

## 12) Testing and validation

Representative automated coverage includes:

- `tests/test_enrichment.py`
- `tests/test_enrichment_handlers.py`
- `tests/correlation/test_rules.py`
- `tests/correlation/test_scorer.py`
- `tests/test_decision.py`
- `tests/test_permanent_cache.py`
- `tests/test_threat_intel_platform.py`

Manual and utility testing:

- `tests/manual_test_enrichment.py`
- `tests/manual_test_correlation.py`
- `tests/manual_test_integration.py`
- `scripts/verify_metrics.py`
- `reports/VALIDATION.md` checklist

---

## 13) Implemented vs planning documents

Repository contains both:

- **Implemented code paths** under `src/` and `scripts/`
- **Roadmap/planning docs** under `docs/` (implementation plan and phase plans)

Use code files as source of truth for current behavior, and phase-plan docs as historical planning context.

---

## 14) Known limitations and operational caveats

From code and docs (`LIMITATIONS.md`, handler behavior):

- External API key and quota dependency
- Partial enrichment possible when providers fail or time out
- No production-grade SIEM deployment hardening in repo
- Advisory recommendations only; no auto-remediation actions
- Synthetic/public IOC usage emphasized for ethics and safety

---

## 15) Suggested “quick start” workflow for full demo

1. Activate environment
2. Generate platform snapshot
3. Convert to Wazuh log lines
4. Open dashboard

Example:

```bash
./venv/Scripts/Activate.ps1
python -m src.platform --demo 20 --output output/platform_snapshot.json
python scripts/generate_wazuh_logs.py --input output/platform_snapshot.json --output output/intel.log
streamlit run scripts/dashboard.py
```

---

## 16) Version and documentation references

- `README.md` (main usage)
- `CHANGELOG.md` (release-level changes)
- `PLATFORM_JSON_SCHEMA.md` (snapshot structure)
- `WAZUH_INTEGRATION.md` (SIEM lab integration)
- `LIMITATIONS.md` (scope and ethics boundaries)
- `src/enrichment/ENRICHMENT_SCHEMA.md` (enrichment contract)

---

## 17) Final summary

Threat-Intel-Bot is a modular threat-intelligence pipeline prototype that moves from IOC enrichment to correlated incident intelligence, with persistent caching, explainable scoring, platform JSON export, dashboard visualization, and lab-only SIEM handoff. The implementation is practical for academic SOC workflow demonstration, while explicitly documenting production and deep-malware-analysis boundaries.

