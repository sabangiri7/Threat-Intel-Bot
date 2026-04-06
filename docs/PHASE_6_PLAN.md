# Phase 6 – Reporting

**Goal:** Generate threat intelligence reports in PDF, JSON, and CSV.  
**Timeline:** Week 7 (per master plan).  
**Stack:** reportlab (PDF), stdlib json/csv; outputs under `reports/output/`.

---

## 1. Outcomes

- PDF report with Executive Summary, Summary, Incidents table, Decisions table.
- JSON export (incidents + decisions + recommendation_summary + metadata).
- CSV export (combined incidents + decisions, one row per incident).
- Sample reports written to `reports/output/` with timestamped filenames.
- Single API (`ReportExporter`) to generate all formats from one artifact.

---

## 2. Checklist

- [x] **PDF report** – `reports/pdfgenerator.py`; Executive Summary, Summary, Incidents, Decisions.
- [x] **JSON export** – `reports/jsonexport.py`; metadata (exported_at, total_incidents, total_decisions).
- [x] **CSV export** – `reports/csvexport.py`; columns: Incident ID, Severity, Risk Score, Group Size, Families, IOC Types, Recommendation, Confidence, Reason.
- [x] **Executive summary** – In PDF: totals, top families, recommendation counts.
- [x] **Sample reports** – All outputs under `reports/output/threat_report_<timestamp>.(pdf|json|csv)`.
- [x] **Dashboard downloads** – Recommendations tab: Download full JSON, PDF, combined CSV.
- [x] **ReportExporter API** – `src.reporting.ReportExporter`; `export_all()` or `export_json()` / `export_pdf()` / `export_csv()`.

---

## 3. CLI commands (from project root)

```powershell
python reports/jsonexport.py
python reports/pdfgenerator.py
python reports/csvexport.py
```

Default input: `reports/incident_recommendations.json`. Default output dir: `reports/output/`.

---

## 4. Programmatic use

```python
from src.reporting import ReportExporter

exporter = ReportExporter("reports/incident_recommendations.json")
paths = exporter.export_all()  # -> {"json": Path, "pdf": Path, "csv": Path}
```

---

## 5. Validation

- **JSON** – Loads with `json.load()`; keys: incidents, decisions, recommendation_summary, metadata.
- **CSV** – Opens in Excel; UTF-8-BOM.
- **PDF** – Sections: Executive Summary, Summary, Incidents, Decisions.

See `reports/VALIDATION.md` for a quick checklist.
