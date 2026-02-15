"""
PDF report generator – threat intelligence summary report.

Usage:
  python reports/pdfgenerator.py
  python reports/pdfgenerator.py --input reports/incident_recommendations.json --output reports/threat_report.pdf

Also provides generate_pdf_bytes(incidents, decisions, summary) for in-memory use (e.g. Streamlit).
"""

from __future__ import annotations

import argparse
import io
import json
from datetime import datetime, timezone
import sys
from pathlib import Path
from typing import Any, Dict, List

# Ensure project root on path when run as python reports/pdfgenerator.py
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from reports.report_utils import timestamped_path

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.pdfgen import canvas
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from reportlab.lib import colors
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

DEFAULT_INPUT = "reports/incident_recommendations.json"


def _severity(inc: Dict[str, Any]) -> str:
    s = inc.get("score") or {}
    return s.get("severity_level") or inc.get("_severity") or "UNKNOWN"


def _final_score(inc: Dict[str, Any]) -> float:
    s = inc.get("score") or {}
    return float(s.get("final_score") or inc.get("_final_score") or 0.0)


def _top_families(incidents: List[Dict[str, Any]], top_n: int = 5) -> List[tuple]:
    """Return list of (family_name, weighted_count) sorted by count desc, weighted by group_size."""
    fam_counts: Dict[str, int] = {}
    for inc in incidents:
        fams = inc.get("malware_families") or []
        weight = int(inc.get("group_size", 1) or 1)
        for fam in fams:
            if not fam or str(fam).upper() == "UNKNOWN":
                continue
            fam_counts[str(fam)] = fam_counts.get(str(fam), 0) + weight
    return sorted(fam_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]


def generate_pdf_bytes(
    incidents: List[Dict[str, Any]],
    decisions: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> bytes:
    """Generate PDF report as bytes (for Streamlit download)."""
    if not HAS_REPORTLAB:
        raise RuntimeError("reportlab is required for PDF export. Install with: pip install reportlab")
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Heading1"],
        fontSize=18,
        spaceAfter=12,
    )
    body = []

    body.append(Paragraph("Threat Intelligence Report", title_style))
    body.append(Paragraph(
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        styles["Normal"],
    ))
    body.append(Spacer(1, 0.3 * inch))

    # --- Executive Summary (1-page style) ---
    body.append(Paragraph("Executive Summary", styles["Heading2"]))
    total_incidents = len(incidents)
    total_iocs = sum(int(inc.get("group_size", 0) or 0) for inc in incidents)
    body.append(Paragraph(f"Total incidents: {total_incidents}", styles["Normal"]))
    body.append(Paragraph(f"Total correlated IOCs: {total_iocs}", styles["Normal"]))
    top_fams = _top_families(incidents, 5)
    if top_fams:
        fam_line = "Top malware families: " + ", ".join(f"{n} ({c})" for n, c in top_fams)
        body.append(Paragraph(fam_line, styles["Normal"]))
    if isinstance(summary, dict) and summary:
        body.append(Paragraph(
            "Recommendation counts — BLOCK: %s | QUARANTINE: %s | MONITOR: %s | IGNORE: %s"
            % (
                summary.get("block_count", 0),
                summary.get("quarantine_count", 0),
                summary.get("monitor_count", 0),
                summary.get("ignore_count", 0),
            ),
            styles["Normal"],
        ))
        if summary.get("immediate_action_required"):
            body.append(Paragraph("Immediate action required (BLOCK/QUARANTINE present).", styles["Normal"]))
        if summary.get("analyst_review_recommended"):
            body.append(Paragraph("Analyst review recommended (MONITOR present).", styles["Normal"]))
    body.append(Spacer(1, 0.3 * inch))

    # Summary (detailed)
    body.append(Paragraph("Summary", styles["Heading2"]))
    body.append(Paragraph(f"Total incidents: {total_incidents}", styles["Normal"]))
    if isinstance(summary, dict) and summary:
        body.append(Paragraph(
            f"BLOCK: {summary.get('block_count', 0)} | "
            f"QUARANTINE: {summary.get('quarantine_count', 0)} | "
            f"MONITOR: {summary.get('monitor_count', 0)} | "
            f"IGNORE: {summary.get('ignore_count', 0)}",
            styles["Normal"],
        ))
    body.append(Spacer(1, 0.25 * inch))

    # Incidents table (compact)
    body.append(Paragraph("Incidents", styles["Heading2"]))
    headers = ["Incident ID", "Severity", "Risk", "Group", "Families"]
    rows = [headers]
    for inc in incidents[:50]:  # cap for PDF size
        fams = inc.get("malware_families") or []
        rows.append([
            str(inc.get("incident_id", "")),
            _severity(inc),
            f"{_final_score(inc):.1f}",
            str(inc.get("group_size", "")),
            ", ".join(str(f) for f in fams[:3]) or "-",
        ])
    if len(incidents) > 50:
        rows.append([f"... and {len(incidents) - 50} more", "", "", "", ""])
    t = Table(rows, colWidths=[1.2 * inch, 1 * inch, 0.6 * inch, 0.5 * inch, 2 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.gray),
    ]))
    body.append(t)
    body.append(Spacer(1, 0.25 * inch))

    # Decisions table
    if decisions:
        body.append(Paragraph("Decisions", styles["Heading2"]))
        d_headers = ["Incident ID", "Recommendation", "Confidence", "Reason"]
        d_rows = [d_headers]
        for d in decisions[:30]:
            d_rows.append([
                str(d.get("incident_id") or d.get("incidentid", "")),
                str(d.get("recommendation", "")),
                f"{float(d.get('confidence') or 0):.1f}%",
                (str(d.get("reason", "")) or "")[:60] + ("..." if len(str(d.get("reason", ""))) > 60 else ""),
            ])
        if len(decisions) > 30:
            d_rows.append([f"... and {len(decisions) - 30} more", "", "", ""])
        dt = Table(d_rows, colWidths=[1.2 * inch, 1.2 * inch, 0.8 * inch, 2.5 * inch])
        dt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.gray),
        ]))
        body.append(dt)

    doc.build(body)
    buffer.seek(0)
    return buffer.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate threat report PDF")
    parser.add_argument("--input", "-i", default=DEFAULT_INPUT, help="Input JSON path")
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output PDF path (default: reports/output/threat_report_<timestamp>.pdf)",
    )
    args = parser.parse_args()
    if not HAS_REPORTLAB:
        print("Error: reportlab is required. Install with: pip install reportlab")
        return 1
    inp = Path(args.input)
    if not inp.exists():
        print(f"Error: Input not found: {inp}")
        return 1
    with inp.open("r", encoding="utf-8") as f:
        data = json.load(f)
    incidents = data.get("incidents", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
    decisions = data.get("decisions", []) if isinstance(data, dict) else []
    summary = data.get("recommendation_summary", {}) if isinstance(data, dict) else {}
    pdf_bytes = generate_pdf_bytes(incidents, decisions, summary)
    out = Path(args.output) if args.output else timestamped_path("pdf")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(pdf_bytes)
    print(f"Generated: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
