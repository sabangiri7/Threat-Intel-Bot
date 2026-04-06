# Final Year Project: Complete Implementation Plan

**Student:** Saban Raj Giri (LC00017002234)  
**Project:** Automated Threat Intelligence Bot for SOC Analysts  
**Timeline:** 2–3 weeks (18–21 days)  
**Status:** Phase 1 (Enrichment) and Phase 2 (Correlation) complete

---

## Current Status

- **35 passing tests**, 98.3% API success rate, 67% cache hit rate on 60 IOCs
- **Remaining:** 7 implementation phases (dataset expansion, permanent cache, platform JSON, Wazuh SIEM, docs, thesis, testing)

---

## Phase Overview

| Phase | Days | Key Deliverables |
|-------|------|------------------|
| 1. Permanent Cache | 1–2 | `PermanentCache` class, 8–10 tests, cache stats CLI |
| 2. Dataset Expansion | 3–5 | 200–500 IOCs from public feeds, `expand_dataset.py` |
| 3. JSON Platform | 6–7 | `PLATFORM_JSON_SCHEMA.md`, platform generator, sample JSON |
| 4. Wazuh Lab | 8–10 | Lab setup, custom rules, `generate_wazuh_logs.py` |
| 5. Documentation | 11–12 | README, CHANGELOG, ARCHITECTURE, LIMITATIONS |
| 6. Thesis Updates | 13–15 | Chapters 3–7 updated |
| 7. Testing & Evidence | 16–18 | 20–30 new tests, benchmarks, screenshots |

---

## Phase 1: Permanent Cache (Days 1–2)

### Objective
Replace 24-hour TTL cache with persistent storage and age-aware staleness.

### Technical Design

**New `PermanentCache` class in `src/cache/`:**

- **Storage:** JSON (`cache/ioc_cache.json`) or SQLite (`cache/ioc_cache.db`)
- **Entry structure:**
  ```json
  {
    "ioc_value": "203.0.113.10",
    "ioc_type": "ip",
    "enrichment_data": {...},
    "cached_at": "2026-02-22T19:30:00Z",
    "stale": false
  }
  ```
- **Methods:** `load_cache()`, `save_cache()`, `get()`, `set()`, `invalidate_ioc()`, `stats()`
- **Staleness:** 7–30 days → `stale: true`; >30 days → eligible for manual purge

### Tasks
1. Refactor cache layer (4h)
2. Add staleness checks (2h)
3. Create cache statistics + CLI `python -m src.cache_tools --stats` (2h)
4. Update unit tests (3h)
5. Documentation (1h)

---

## Phase 2: Dataset Expansion (Days 3–5)

### Objective
Expand from 60 to 200–500 IOCs using public threat feeds only.

### Target Composition (200 IOCs min)
- IPs: 80 (40%)
- Domains: 60 (30%)
- Hashes: 40 (20%)
- URLs: 20 (10%)

### Sources
- abuse.ch ThreatFox, URLhaus, Malware Bazaar
- AlienVault OTX public pulses

### Deliverables
- `scripts/expand_dataset.py`
- `data/testthreats200.json`, `data/testthreats500.json`

---

## Phase 3: JSON Threat Intel Platform (Days 6–7)

### Objective
Produce a consumable platform JSON (STIX-inspired, project-specific).

### Schema
- Top-level: `platform_version`, `generated_at`, `summary`, `iocs`, `incidents`
- IOC array: value, type, confidence, triage_action, malware_family, api_results
- Incident array: incident_id, severity, risk_score, ioc_count, recommended_action

### Deliverables
- `PLATFORM_JSON_SCHEMA.md`
- `threat_intel_platform.py` or `scripts/generate_platform_json.py`
- `output/platform_snapshot.json`

---

## Phase 4: Wazuh SIEM Lab Integration (Days 8–10)

### Objective
Lab-only demo of SIEM consuming platform JSON.

### Components
- Wazuh manager + agent (local/Docker)
- Custom log: `/var/ossec/logs/intel/intel.log`
- Custom rules: `local_rules.xml`
- `scripts/generate_wazuh_logs.py`

### Deliverables
- `WAZUH_INTEGRATION.md` (with LAB-ONLY DISCLAIMER)
- Custom rules, screenshots

---

## Phase 5: Documentation (Days 11–12)

- README.md, CHANGELOG.md v4.0.0
- ARCHITECTURE.md, LIMITATIONS.md
- PLATFORM_JSON_SCHEMA.md, WAZUH_INTEGRATION.md

---

## Phase 6: Thesis Updates (Days 13–15)

- Chapter 3: Dataset expansion methodology
- Chapter 4: Platform + SIEM architecture
- Chapter 5: Implementation (cache, platform, Wazuh)
- Chapter 6: Testing with expanded dataset
- Chapter 7: Limitations and future work

---

## Phase 7: Testing & Evidence (Days 16–18)

- 20–30 new unit tests (55+ total)
- Performance benchmarks (60 vs 200 vs 500 IOCs)
- 15–20 screenshots
- TESTING.md updated

---

## Boundary Compliance Checklist

- [ ] Lab-only data: IOCs from public feeds only
- [ ] Advisory-only: no auto-blocking or production changes
- [ ] API rate limits: heavy caching, mock mode for bulk tests
- [ ] No scope creep: STIX/TAXII and production SIEM in Future Work only

---

## Success Criteria

- 55+ passing tests
- 200–500 IOCs processed
- Permanent cache persists across restarts
- Platform JSON validates against schema
- Wazuh custom rules trigger in lab
- Full pipeline runs in <10 minutes

---

## Next Steps (Immediate)

1. Start Phase 1 (Permanent Cache)
2. Begin collecting public IOC data for Phase 2
3. Set up Wazuh lab (Docker)
4. Commit daily, update CHANGELOG
