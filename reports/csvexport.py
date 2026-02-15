"""
CSV report export – combined incidents + decisions (one row per incident).

Usage:
  python reports/csvexport.py
  python reports/csvexport.py --input reports/incident_recommendations.json --output reports/output/threat_report.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

# Ensure project root on path when run as python reports/csvexport.py
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from reports.report_utils import timestamped_path

DEFAULT_INPUT = "reports/incident_recommendations.json"


def _severity(inc: Dict[str, Any]) -> str:
    s = inc.get("score") or {}
    return s.get("severity_level") or inc.get("_severity") or "UNKNOWN"


def _final_score(inc: Dict[str, Any]) -> float:
    s = inc.get("score") or {}
    return float(s.get("final_score") or inc.get("_final_score") or 0.0)


def export_csv(input_path: str | Path, output_path: str | Path) -> Path:
    inp = Path(input_path)
    out = Path(output_path)
    if not inp.exists():
        raise FileNotFoundError(f"Input not found: {inp}")
    with inp.open("r", encoding="utf-8") as f:
        data = json.load(f)
    incidents = data.get("incidents", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
    decisions = data.get("decisions", []) if isinstance(data, dict) else []
    decisions_by_id = {str(d.get("incident_id") or d.get("incidentid", "")): d for d in decisions}

    out.parent.mkdir(parents=True, exist_ok=True)
    columns = [
        "Incident ID", "Severity", "Risk Score", "Group Size", "Families", "IOC Types",
        "Recommendation", "Confidence", "Reason",
    ]
    with out.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=columns, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        for inc in incidents:
            inc_id = str(inc.get("incident_id", ""))
            dec = decisions_by_id.get(inc_id) or {}
            writer.writerow({
                "Incident ID": inc_id,
                "Severity": _severity(inc),
                "Risk Score": round(_final_score(inc), 2),
                "Group Size": int(inc.get("group_size", 0) or 0),
                "Families": ", ".join(inc.get("malware_families") or []),
                "IOC Types": ", ".join(inc.get("ioc_types") or []),
                "Recommendation": dec.get("recommendation", ""),
                "Confidence": dec.get("confidence", ""),
                "Reason": str(dec.get("reason", ""))[:500],
            })
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Export threat report as combined CSV")
    parser.add_argument("--input", "-i", default=DEFAULT_INPUT, help=f"Input artifact (default: {DEFAULT_INPUT})")
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output CSV path (default: reports/output/threat_report_<timestamp>.csv)",
    )
    args = parser.parse_args()
    output_path = args.output or str(timestamped_path("csv"))
    try:
        out = export_csv(args.input, output_path)
        print(f"Exported: {out}")
        return 0
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
