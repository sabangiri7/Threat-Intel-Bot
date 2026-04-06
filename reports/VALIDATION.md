# Report format validation (quick checklist)

- **JSON** – Loads with `json.load()`. Structure: `incidents`, `decisions`, `recommendation_summary` (and optional `metadata`). Valid UTF-8.
- **CSV** – Opens in Excel; columns: Incident ID, Severity, Risk Score, Group Size, Families, IOC Types, Recommendation, Confidence, Reason. UTF-8-BOM for Excel compatibility.
- **PDF** – Opens in any viewer; contains **Executive Summary** (totals, top families, recommendation counts), **Summary**, **Incidents** table, **Decisions** table.

Sample validation (from project root after generating reports):

- **JSON:** `python -c "import json; f=next(__import__('pathlib').Path('reports/output').glob('threat_report_*.json')); json.load(open(f)); print('JSON OK')"`
- **CSV:** Open any `reports/output/threat_report_*.csv` in Excel; confirm columns: Incident ID, Severity, Risk Score, Group Size, Families, IOC Types, Recommendation, Confidence, Reason.
- **PDF:** Open any `reports/output/threat_report_*.pdf`; confirm Executive Summary, Summary, Incidents table, Decisions table.
