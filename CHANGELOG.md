# Changelog

All notable changes to this project are documented in this file.

## [4.0.0] - 2026-03-29

### Added

- Permanent cache with age metadata, persistence, staleness tracking, and stats tooling.
- STIX-inspired (project-specific) JSON threat intel platform output.
- `PLATFORM_JSON_SCHEMA.md` to document the platform snapshot structure.
- Wazuh SIEM lab integration:
  - `scripts/generate_wazuh_logs.py` for one-line JSON event generation.
  - `wazuh_integration/local_rules.xml` with custom MITRE-mapped rules.
- Dataset expansion readiness for 60 -> 200 -> 500 IOC benchmarking.

### Updated

- Architecture and workflow documentation to include cache, platform output, and SIEM lab pipeline.

