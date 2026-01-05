## Enriched IOC Schema (Phase 2)

This document defines the canonical schema and scoring logic for the Phase 2 IOC
enrichment engine. Phase 3 components MUST treat this as the source of truth
for how enriched IOCs are structured and how `unified_confidence` and
`triage_action` are derived.

---

## 1. Input Schema

The enrichment engine primarily exposes:
- `IOCEnricher.enrich_ioc(ioc_value, ioc_type)` – single IOC
- `IOCEnricher.enrich_batch(iocs)` – batch of IOCs

### 1.1 Single IOC input

```json
{
  "ioc_value": "string - the raw IOC (IP, domain, URL, hash)",
  "ioc_type": "string - case-insensitive; one of: ip, domain, url, hash"
}
```

- **`ioc_value`**: Required. The literal indicator to enrich (e.g. `8.8.8.8`,
  `evil.example.com`, `https://example.com/malware.exe`,
  `d41d8cd98f00b204e9800998ecf8427e`).
- **`ioc_type`**: Required. Normalized internally to lowercase
  (`"ip"`, `"domain"`, `"url"`, `"hash"`).

### 1.2 Batch input

```json
[
  {
    "ioc_value": "string",
    "ioc_type": "string"
  }
]
```

Each element in the list follows the single-IOC schema above. Invalid or
missing `ioc_value` entries are skipped with a warning.

---

## 2. Output Schema (Single Enriched IOC)

The enrichment engine returns the following structure per IOC:

```json
{
  "ioc_value": "string",
  "ioc_type": "string (normalized to lowercase: ip|domain|url|hash)",
  "unified_confidence": 0.0,
  "triage_action": "BLOCK | MONITOR | IGNORE",
  "timestamp": "ISO 8601 UTC string",
  "api_results": {
    "virustotal": {
      "status": "success | error",
      "ioc_type": "IP|domain|URL|hash",
      "detections": 0,
      "total_engines": 0,
      "detection_ratio": "0/0",
      "last_analysis_date": 0,
      "categories": {},
      "raw_data": {}
    },
    "otx": {
      "status": "success | error",
      "ioc_type": "IP|domain|URL|hash",
      "pulse_count": 0,
      "pulses": [],
      "type_tags": [],
      "validation": [],
      "reputation": null,
      "raw_data": {}
    },
    "threatfox": {
      "status": "success | not_found | error",
      "ioc_count": 0,
      "ioc_value": "string",
      "ioc_type": "string",
      "threat_type": "string|null",
      "threat_type_desc": "string|null",
      "malware": "string|null",
      "malware_printable": "string|null",
      "malware_alias": "string|null",
      "confidence_level": 0,
      "last_submission": "string|null",
      "tags": [],
      "raw_data": {}
    },
    "abuseipdb": {
      "status": "success | error",
      "ioc_type": "IP",
      "ip_address": "string",
      "abuse_confidence_score": 0,
      "total_reports": 0,
      "distinct_users": 0,
      "last_reported_at": "string|null",
      "is_whitelisted": false,
      "usage_type": "string",
      "isp": "string",
      "country": "string",
      "report_categories": [],
      "raw_data": {}
    }
  }
}
```

Notes:
- For non-IP IOCs, the `abuseipdb` handler is **not invoked** and will simply
  be absent from `api_results`.
- `raw_data` fields contain the full parsed JSON response from the
  corresponding API and may change as upstream APIs evolve.

---

## 3. Confidence Scoring Logic

The enrichment engine **does not** use per-handler `"confidence"` fields.
Instead, it derives a **single** `unified_confidence` value in \[0.0, 1.0\] from
real API signals using the rules below (implemented in
`IOCEnricher._compute_unified_confidence`).

Let `score` start at `0.0`. For each source:

### 3.1 VirusTotal (IP / domain / URL / hash)

Based on `detections` (number of engines classifying the IOC as malicious):

- **0 detections** → `+0.00`
- **1–3 detections** → `+0.25`
- **4–9 detections** → `+0.45`
- **10+ detections** → `+0.60`

### 3.2 OTX (IP / domain / URL / hash)

Based on `pulse_count`:

- **0 pulses** → `+0.00`
- **1–4 pulses** → `+0.20`
- **5+ pulses** → `+0.35`

(In the current implementation, `pulse_count >= 5` yields `0.35`, and any
positive pulse count below 5 yields `0.20`.)

### 3.3 ThreatFox (all IOC types)

If the IOC is found (`status == "success"`):

- **Found in ThreatFox** → `+0.50`
- **Not found / error** → `+0.00`

### 3.4 AbuseIPDB (IP-only)

Only applied when `ioc_type == "ip"` and `abuseipdb.status == "success"`:

- If `is_whitelisted == true` → contributes `+0.00` regardless of score.
- Else, use `abuse_confidence_score` \[0–100\] and normalize:

  \[
  \text{abuse\_component} = \min(\text{abuse\_confidence\_score} / 100.0,\ 1.0)
  \]

  and add this to `score` if `abuse_confidence_score > 0`.

### 3.5 Clamping

After aggregating all contributions:

\[
\text{unified\_confidence} = \min(\max(\text{score}, 0.0), 1.0)
\]

The value is typically rounded to three decimal places when stored:
`round(unified_confidence, 3)`.

---

## 4. Triage Rules

The `triage_action` is derived **only** from `unified_confidence`:

- **BLOCK**: `unified_confidence >= 0.70`
- **MONITOR**: `0.30 <= unified_confidence < 0.70`
- **IGNORE**: `unified_confidence < 0.30`

These thresholds are stable Phase 2 semantics and should be respected by
Phase 3 consumers for routing, alerting, or policy decisions.

---

## 5. Cache, API Keys, and Timeouts

### 5.1 Cache behavior

- The enrichment engine uses a JSON-backed cache keyed as
  `"<ioc_type>::<ioc_value>"` (with `ioc_type` lowercased).
- On a **cache hit**, the previously enriched IOC object is returned verbatim
  (including `unified_confidence` and `triage_action`) without re-contacting
  any external APIs.
- On a **cache miss**, APIs are queried, `unified_confidence` and
  `triage_action` are computed, and the result is written back to the cache.
  The cache is periodically flushed to disk; Phase 3 should treat disk writes
  as eventual, not immediate.

### 5.2 API key requirements

- **VirusTotal**: requires `VIRUSTOTAL_API_KEY` (or legacy env var aliases).
- **OTX**: requires `OTX_API_KEY` (or compatible aliases).
- **ThreatFox**: requires `THREATFOX_API_KEY` (or compatible aliases).
- **AbuseIPDB**: requires `ABUSEIPDB_API_KEY` (or compatible aliases).

If an API key is missing, the corresponding handler returns
`{"status": "error", "error": "Missing ... API key"}` and contributes **no**
confidence to `unified_confidence`.

### 5.3 Timeout and error handling

- Each HTTP call uses a finite timeout (typically 10 seconds). Network or HTTP
  failures are normalized to:

  ```json
  {
    "status": "error",
    "error": "string description"
  }
  ```

- Errors and `not_found` responses do **not** contribute to
  `unified_confidence`; only `status == "success"` counts for scoring.
- Phase 3 should be resilient to missing or erroring `api_results` entries and
  rely primarily on `unified_confidence` and `triage_action` for decisions.

