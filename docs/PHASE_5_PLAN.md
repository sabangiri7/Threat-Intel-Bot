# Phase 5 – Visual Dashboard (Streamlit)

**Goal:** Interactive SOC dashboard for threat monitoring and incident recommendations.  
**Timeline:** ~1 week.  
**Stack:** Streamlit, Plotly, Pandas; data from correlation + Phase 4 decision engine.

---

## 1. Outcomes

- One Streamlit app: **Overview | Incidents | Analysis | Recommendations**.
- Metrics: total incidents, critical count, avg risk score, correlated IOC count.
- Incidents table with filters (severity, min score, malware family) and CSV export.
- Charts: severity distribution, risk score distribution, top malware families, IOC type distribution.
- Recommendations tab: BLOCK/QUARANTINE/MONITOR/IGNORE counts + table (from `TriageEngine` + `RecommendationSummary`).
- Data source: run correlation + decision once (e.g. from saved JSON or demo), pass incidents/decisions into the app.

---

## 2. Data Shape (already in place)

- **Incidents** (from `correlate_iocs()`): each has `incident_id`, `group_size`, `ioc_values`, `ioc_types`, `malware_families`, `score` (dict with `final_score`, `severity_level`, `base_score`, etc.).
- **Decisions** (from `TriageEngine().batch_triage(incidents)`): list of `TriageDecision` (incident_id, recommendation, confidence, reason).
- **Summary** (from `RecommendationSummary.generate_summary(decisions)`): dict with `block_count`, `quarantine_count`, `monitor_count`, `ignore_count`, `immediate_action_required`, etc.

Use **score as dict**: e.g. `incident['score']['final_score']`, `incident['score']['severity_level']` (no top-level `incident['severity_level']` or numeric `incident['score']`).

---

## 3. File Layout

| Item | Location |
|------|----------|
| Streamlit app | `dashboard/app.py` (or `src/dashboard.py`; pick one as main entry) |
| Run command | `streamlit run dashboard/app.py` |
| Deps | Add `streamlit`, `plotly` to `requirements.txt` |

---

## 4. Implementation Steps

### Step 1 – Dependencies
- Add to `requirements.txt`: `streamlit>=1.28.0`, `plotly>=5.18.0`.
- Run: `pip install -r requirements.txt` (with venv activated).

### Step 2 – Data loading
- Option A: Load from a saved JSON (e.g. `reports/incident_recommendations.json` from demo `--output`) with keys `incidents`, `decisions`, `recommendation_summary`.
- Option B: In-app: run `DemoDataGenerator.generate_sample_iocs()` → `correlate_iocs(iocs)` → `TriageEngine().batch_triage(incidents)` and `RecommendationSummary.generate_summary(decisions)`.
- Normalize incident fields for UI: helper that returns `severity_level = incident['score']['severity_level']`, `final_score = incident['score']['final_score']`, so the rest of the app can use a single shape.

### Step 3 – App shell ✅
- `st.set_page_config(title="Threat Intelligence SOC Dashboard", layout="wide")`.
- Title + short description.
- Four metric cards: Total Incidents, Critical Count, Avg Risk Score, Correlated IOCs (sum of `group_size`).
- Tabs: **Overview** | **Incidents** | **Analysis** | **Recommendations**.
- **Done:** KPI row + 4 tabs in `dashboard/app.py`; Overview/Incidents/Analysis/Recommendations placeholders; Incidents tab shows dataframe (ID, Severity, Risk Score, Group Size).

### Step 4 – Tab: Overview ✅
- Severity distribution: pie chart (counts by `incident['score']['severity_level']`).
- Risk score distribution: histogram of `incident['score']['final_score']`.
- **Done:** Two-column layout; left: severity pie (`px.pie`); right: risk score histogram (`px.histogram`, 20 bins).

### Step 5 – Tab: Incidents ✅
- Filters: multiselect severity, slider min score, text input malware family.
- Filter list using `incident['score']['severity_level']`, `incident['score']['final_score']`, `incident['malware_families']`.
- Table columns: Incident ID, Severity, Risk Score, Group Size, Families, IOC Types.
- Download button: table as CSV.
- **Done:** Severity multiselect (default CRITICAL/HIGH), min risk score slider (0–100, step 0.5), malware family text filter; filtered table; “Showing N / M incidents”; CSV download.

### Step 6 – Tab: Analysis ✅
- Left: bar chart – top malware families (by group_size or IOC count).
- Right: pie chart – IOC type distribution.
- **Done:** Two-column layout; left: top 10 malware families bar (weighted by `group_size`; UNKNOWN excluded); right: IOC type pie (weighted by `group_size`). Fallback info messages when no data.

### Step 7 – Tab: Recommendations ✅
- Four metrics: BLOCK, QUARANTINE, MONITOR, IGNORE from `summary`.
- One line: “Immediate action required: {summary['immediate_action_required']}”.
- Table: Incident ID, Recommendation, Confidence, Reason (from `decisions`).
- **Done:** Four metric cards; warning if `immediate_action_required`, info if `analyst_review_recommended`; decisions table; "Download decisions CSV" button. Fallback info when no summary/decisions.

### Step 8 – Wiring and run ✅
- If loading from file: sidebar or startup load of JSON path; else generate sample data once and cache with `st.cache_data` (or session state) so reruns don’t re-correlate every time.
- Document in README: “Run dashboard: `streamlit run dashboard/app.py`”.
- **8.1 Report generators:** `reports/jsonexport.py` (default in/out: incident_recommendations.json → threat_report.json), `reports/pdfgenerator.py` (→ threat_report.pdf). Both support `--input` / `--output`. PDF uses reportlab.
- **8.2 Dashboard downloads (Recommendations tab):** “Download full JSON report”, “Download PDF report”, “Download combined CSV” (incidents + decisions joined by incident_id).

---

## 5. Checklist

- [ ] `streamlit` and `plotly` in `requirements.txt`; install and run app without import errors.
- [ ] Data loading (file or generated) and normalization for `score` (dict) and severity/score fields.
- [x] **Step 3:** App shell – KPI row (Total Incidents, Critical Count, Avg Risk Score, Correlated IOCs) + 4 tabs (Overview | Incidents | Analysis | Recommendations); Incidents tab has dataframe.
- [x] **Step 4:** Overview tab: severity pie, score histogram.
- [x] **Step 5:** Incidents tab: filters, table, CSV export.
- [x] **Step 6:** Analysis tab: malware families bar, IOC types pie.
- [x] **Step 7:** Recommendations tab: summary metrics + decisions table (Phase 4 engine).
- [ ] Entry point: `streamlit run dashboard/app.py` (or chosen path).
- [ ] README updated with dashboard run command.
- [ ] Optional: 1–2 screenshots for report.

---

## 6. Step 4 — Live Pipeline

Plugs Phase 2 (enrichment) + Phase 3 (correlation) + Phase 4 (decisions) into the Streamlit UI so analysts can process their own IOCs end-to-end.

### Flow

1. Analyst pastes IOCs in the **Step 1** sidebar and clicks **Build context payload** (classification).
2. Analyst clicks **Run LIVE enrichment + correlation + decisions** (Step 4).
3. Each IOC is enriched via `IOCEnricher.enrich_batch()` (Phase 2).  A normalization bridge (`_normalize_enriched_for_engine`) converts the enrichment output keys to the format the correlation engine expects.
4. Enriched IOCs are correlated via `correlate_iocs()` (Phase 3).
5. Incidents are triaged via `generate_incident_recommendations()` (Phase 4).
6. The resulting artifact (`context`, `incidents`, `decisions`, `recommendation_summary`) is stored in `st.session_state["live_artifact"]` and displayed as JSON with a download button.
7. The main dashboard area automatically switches to the live artifact for all charts, tables, and metrics.  **Reload** clears it.

### Key normalization

The enrichment module returns underscore-separated keys (`ioc_value`, `unified_confidence`, `api_results`), while the correlation engine accesses no-underscore keys (`iocvalue`, `unifiedconfidence`, `apiresults`).  The `_normalize_enriched_for_engine()` helper bridges both top-level and inner `api_results` keys.

### Graceful degradation

Missing API keys do not crash the pipeline — handlers return error status and contribute 0 to confidence.  The correlation and decision layers still produce valid incidents from whatever signals are available.

---

## 7. Optional Later

- Sidebar file upload (JSON) to switch datasets.
- Time range filter if you add timestamps to incidents.
- Drill-down: click incident → show IOCs in that group.

---

## 7. Reference – our incident shape

```python
# One incident from correlate_iocs()
{
    "incident_id": "INC-0001",
    "group_size": 5,
    "ioc_values": ["a.com", "b.com", ...],
    "ioc_types": ["DOMAIN", "IP"],
    "malware_families": ["Trojan.A"],
    "score": {
        "final_score": 85.0,
        "severity_level": "CRITICAL",
        "base_score": 72.0,
        "confidence_boost": 5.0,
        "source_boost": 4.0,
        "size_bonus": 8.0,
        "action_multiplier": 1.0,
        "reasoning": "..."
    }
}
```

Use `incident['score']['final_score']` and `incident['score']['severity_level']` everywhere in the dashboard.
