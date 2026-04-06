# LIMITATIONS

This document defines the operational and ethical boundaries for the FYP Automated Threat Intelligence Bot.

## API Rate Limits

The enrichment pipeline depends on public/free OSINT APIs, each with request quotas and throttling behavior.

- Rate limits can slow enrichment during large IOC runs.
- Provider-side failures/timeouts can produce partial source coverage.
- The permanent cache mitigates this by reducing repeated API calls and preserving prior enrichment.

Caching is therefore a core reliability mechanism, not an optimization-only feature.

## Lab-Only Environment

The current SIEM integration is validated in a local academic lab setup.

- Configuration is designed for demonstration, not production hardening.
- No enterprise HA, change-control, or security governance pipeline is included.
- Rule tuning is educational and may require significant adjustment in real SOC environments.

This project should be treated as proof-of-concept in a controlled environment.

## Synthetic/Public Data

The project intentionally avoids real organizational telemetry.

- IOC datasets are synthetic or sourced from public threat-intel feeds.
- No private endpoint logs, internal network telemetry, or confidential incident data is processed.
- This preserves privacy and complies with academic ethics boundaries.

Results should be interpreted as lab evidence, not production efficacy claims.

## Advisory-Only System

The bot provides recommendations (including `BLOCK`) but does not execute automated response actions.

- No automatic firewall changes
- No autonomous host isolation
- No direct endpoint remediation

Human analyst review remains mandatory before any operational action.

