# Automated Threat Intelligence Bot for SOC Analysts

A Python-based Final Year Project (FYP) that enriches indicators of compromise (IOCs), correlates related activity into incidents, and exports a STIX-inspired platform JSON for analyst workflows and SIEM lab integration.

## Architecture

The current architecture includes the following layers:

1. IOC intake and normalization
2. Multi-source enrichment (VirusTotal, OTX, ThreatFox, AbuseIPDB)
3. Permanent cache with persistence and staleness metadata
4. Correlation engine for incident grouping and scoring
5. Platform JSON output generation
6. Wazuh SIEM lab feed (one JSON event per line)

### New Components (Phase 4/5)

- **Permanent Cache** (`src/cache/cache.py`)
  - Persistent storage
  - Age-aware staleness metadata
  - Cache stats CLI via `python -m src.cache_tools --stats`
- **JSON Platform Output** (`output/platform_snapshot.json`)
  - Generated via `python -m src.platform`
  - Schema documented in `PLATFORM_JSON_SCHEMA.md`
- **Wazuh SIEM Lab Integration**
  - Log generator: `scripts/generate_wazuh_logs.py`
  - Custom rules: `wazuh_integration/local_rules.xml`

## Quick Demo

Run from project root:

```bash
# 1) Activate virtual environment (Windows PowerShell)
./venv/Scripts/Activate.ps1

# 2) Generate a platform snapshot
python -m src.platform --demo 20 --output output/platform_snapshot.json

# 3) Convert incidents to Wazuh-ready NDJSON log lines
python scripts/generate_wazuh_logs.py --input output/platform_snapshot.json --output output/intel.log

# 4) View cache stats
python -m src.cache_tools --stats
```

## Performance Metrics (Placeholder)

| Metric | 60 IOCs | 200 IOCs | 500 IOCs |
|---|---:|---:|---:|
| Enrichment Time | TBD | TBD | TBD |
| Correlation Time | TBD | TBD | TBD |
| Cache Hit Rate | TBD | TBD | TBD |

## Documentation

- `CHANGELOG.md`
- `PLATFORM_JSON_SCHEMA.md`
- `WAZUH_INTEGRATION.md`
- `LIMITATIONS.md`

