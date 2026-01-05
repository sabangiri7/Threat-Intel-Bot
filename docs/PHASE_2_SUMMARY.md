## Phase 2 Enrichment Engine – Technical Summary (Week 6)

### 1. Overview

Phase 2 adds a full IOC enrichment and triage layer to the Threat Intelligence
Bot. Given raw indicators of compromise (IOCs) such as IP addresses, domains,
URLs, and file hashes, the enrichment engine queries multiple external OSINT
sources, normalizes their responses, computes a unified confidence score, and
derives an actionable triage decision (`BLOCK`, `MONITOR`, or `IGNORE`). This
stage turns low-level raw indicators into structured, decision-ready objects
that downstream components (correlation, decision, reporting) can consume in a
uniform way.

The implementation centers on the `IOCEnricher` class in `src/enrichment/enrichment.py`,
backed by a JSON cache and dedicated API handlers for VirusTotal, AlienVault
OTX, ThreatFox (Abuse.ch), and AbuseIPDB. The engine is designed to be
deterministic and reproducible: given the same upstream responses, the same
IOC will always yield the same `unified_confidence` and `triage_action`.

### 2. System Architecture

High-level data flow:

```text
             +---------------------+
             |  Raw IOC(s) input   |
             |  (IP/domain/URL)    |
             +----------+----------+
                        |
                        v
               +--------+---------+
               |    IOCEnricher   |
               |  (enrichment.py) |
               +--------+---------+
                        |
        +---------------+-----------------------+
        |               |                       |
        v               v                       v
   +----+----+     +----+----+            +----+-----+
   |VirusTotal|    |   OTX   |            |ThreatFox |
   +----+----+     +----+----+            +----+-----+
        \              |                       /
         \             |                      /
          \            |                     /
           v           v                    v
              +--------+---------+
              |  AbuseIPDB (IP) |
              +--------+--------+
                       |
                       v
             +---------+----------+
             |  Aggregation &     |
             | unified_confidence |
             +---------+----------+
                       |
                       v
             +---------+----------+
             |  Triage decision   |
             | BLOCK/MONITOR/IGNORE
             +--------------------+
```

The cache layer (`src/cache.py`) sits alongside the enricher and is consulted
before any outbound API calls.

### 3. Features

- **Multi-source aggregation**: Queries VirusTotal, OTX, ThreatFox, and
  AbuseIPDB (for IPs) and stores normalized responses in `api_results`.
- **Unified confidence scoring**: Uses concrete signals (detections, pulses,
  ThreatFox presence, AbuseIPDB abuse score) to compute a single score in
  \[0.0, 1.0\], as documented in `ENRICHMENT_SCHEMA.md`.
- **Triage decisions**: Maps confidence to triage actions:
  - `BLOCK` for high-risk IOCs (`>= 0.70`)
  - `MONITOR` for medium-risk (`>= 0.30` and `< 0.70`)
  - `IGNORE` for low-risk (`< 0.30`)
- **Caching**: Avoids redundant API calls by caching enriched results on disk
  keyed by `"<ioc_type>::<ioc_value>"`.
- **Error handling**: Normalizes API failures and missing keys to structured
  error objects; such errors do not contribute to confidence.

### 4. Implementation Status

- Core enricher (`IOCEnricher`) is implemented and integrated with all four API
  handlers.
- Unified confidence computation and triage mapping are implemented and
  documented.
- A dedicated schema reference (`src/enrichment/ENRICHMENT_SCHEMA.md`) defines
  input/output formats and scoring rules.
- Unit tests in `tests/test_enrichment.py` validate schema shape, confidence
  bounds, triage thresholds, batch behavior, cache statistics, and API result
  structure. These tests are designed to be stable even when live API keys are
  absent (handlers will return errors but schema remains valid).

### 5. Known Limitations

- **Rate limiting**: External APIs enforce rate limits. The handlers include
  basic sleeps and timeouts but sustained high-volume enrichment will require
  batching, backoff, or asynchronous scheduling in later phases.
- **API key availability**: If environment variables for a given provider are
  missing, that provider contributes no confidence. This can lower overall
  scores for some environments.
- **Timeouts and partial data**: Network issues or upstream outages will result
  in `status="error"` entries in `api_results`. Confidence is conservative in
  these cases, favoring lower scores rather than guessing.
- **Enrichment-only scope**: Phase 2 does not attempt correlation across IOCs,
  incident grouping, or temporal analysis; it focuses strictly on single-IOC
  enrichment and triage.

### 6. Phase 3 Integration

Phase 3 (correlation and decision engine) will consume enriched IOC records
from three primary sources:

1. The on-disk enrichment cache (e.g. `data/enrichment_cache.json` or
   `data/sample_enriched_iocs.json`).
2. The public API wrapper (`src/enrichment/api.py`) for on-demand enrichment
   (e.g. `enrich_single` / `enrich_batch`).
3. Streaming outputs from the collection module once wired together.

Phase 3 is expected to:

- Use `unified_confidence` and `triage_action` as primary decision features.
- Optionally inspect `api_results` for richer context (malware families,
  campaign names, categories).
- Treat the schema in `ENRICHMENT_SCHEMA.md` as the contract for persisted and
  streamed enrichment output.

### 7. Git History

Phase 2 work is grouped under commits similar to:

- `Phase 2: Add enrichment engine and handlers`
- `Phase 2: Implement unified confidence and triage`
- `Phase 2: Add documentation, tests, samples, and API wrapper`

These commits can be referenced during viva to demonstrate progressive
development, refactoring, and test-driven improvements.

### 8. Performance Baseline

Approximate baseline timings on a development laptop (live API keys, limited
sample set):

```text
+----------------------+----------------------------+
| Operation            | Approx. Time per IOC      |
+----------------------+----------------------------+
| Cold enrich (4 APIs) | 1.5 – 3.0 seconds         |
| Warm cache hit       | < 5 milliseconds          |
| Batch (10 IOCs)      | 15 – 25 seconds (cold)    |
+----------------------+----------------------------+
```

These numbers are dominated by external API latency. The internal processing
and cache lookups are negligible by comparison.

### 9. Conclusion

Phase 2 delivers a production-ready enrichment and triage engine that turns
raw IOCs into actionable, normalized intelligence objects. It abstracts away
the complexity of multiple third‑party APIs, consolidates their signals into a
single confidence score, and applies clear triage thresholds suitable for
automation. With documentation, tests, and a clean public API in place, Phase 2
provides a solid foundation for Phase 3 correlation, decision logic, and
reporting layers to build on.

