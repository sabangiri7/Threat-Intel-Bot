"""
Phase 6 – ReportExporter: single API to generate PDF, JSON, and CSV reports from one artifact.

Usage:
  from src.reporting import ReportExporter
  exporter = ReportExporter("reports/incident_recommendations.json")
  paths = exporter.export_all()
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

# Project root is expected on path when using src.reporting
from reports.report_utils import OUTPUT_DIR, get_report_timestamp
from reports import jsonexport
from reports import pdfgenerator
from reports import csvexport


class ReportExporter:
    """Export threat intelligence data in PDF, JSON, and CSV from one artifact."""

    def __init__(self, artifact_path: str | Path) -> None:
        self.artifact_path = Path(artifact_path)
        if not self.artifact_path.exists():
            raise FileNotFoundError(f"Artifact not found: {self.artifact_path}")

    def _out_path(self, ext: str, output_path: Optional[str | Path] = None) -> Path:
        if output_path is not None:
            return Path(output_path)
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        return OUTPUT_DIR / f"threat_report_{get_report_timestamp()}.{ext.lstrip('.')}"

    def export_json(self, output_path: Optional[str | Path] = None) -> Path:
        """Export artifact as JSON. Returns path to written file."""
        out = self._out_path("json", output_path)
        jsonexport.export_json(self.artifact_path, out, add_metadata=True)
        return out

    def export_pdf(self, output_path: Optional[str | Path] = None) -> Path:
        """Export artifact as PDF. Returns path to written file."""
        out = self._out_path("pdf", output_path)
        with self.artifact_path.open("r", encoding="utf-8") as f:
            import json
            data = json.load(f)
        incidents = data.get("incidents", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
        decisions = data.get("decisions", []) if isinstance(data, dict) else []
        summary = data.get("recommendation_summary", {}) if isinstance(data, dict) else {}
        pdf_bytes = pdfgenerator.generate_pdf_bytes(incidents, decisions, summary)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(pdf_bytes)
        return out

    def export_csv(self, output_path: Optional[str | Path] = None) -> Path:
        """Export artifact as combined CSV (incidents + decisions). Returns path."""
        out = self._out_path("csv", output_path)
        csvexport.export_csv(self.artifact_path, out)
        return out

    def export_all(
        self,
        output_dir: Optional[str | Path] = None,
    ) -> Dict[str, Path]:
        """Generate JSON, PDF, and CSV with the same timestamp. Returns dict of paths."""
        base = Path(output_dir) if output_dir else OUTPUT_DIR
        base.mkdir(parents=True, exist_ok=True)
        ts = get_report_timestamp()
        return {
            "json": self.export_json(base / f"threat_report_{ts}.json"),
            "pdf": self.export_pdf(base / f"threat_report_{ts}.pdf"),
            "csv": self.export_csv(base / f"threat_report_{ts}.csv"),
        }
