"""
Shared report paths and timestamp for JSON/PDF/CSV outputs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

OUTPUT_DIR = Path("reports/output")


def get_report_timestamp() -> str:
    """ISO-style timestamp for filenames: 20250214_213045."""
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def timestamped_path(extension: str) -> Path:
    """Path like reports/output/threat_report_20250214_213045.pdf."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    return OUTPUT_DIR / f"threat_report_{get_report_timestamp()}.{extension.lstrip('.')}"
