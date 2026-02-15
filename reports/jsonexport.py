"""
JSON report export – load artifact and write canonical JSON report.

Usage:
  python reports/jsonexport.py
  python reports/jsonexport.py --input reports/incident_recommendations.json --output reports/threat_report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root on path when run as python reports/jsonexport.py
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from reports.report_utils import timestamped_path

DEFAULT_INPUT = "reports/incident_recommendations.json"


def load_artifact(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def export_json(
    input_path: str | Path,
    output_path: str | Path,
    add_metadata: bool = True,
) -> Path:
    inp = Path(input_path)
    out = Path(output_path)
    if not inp.exists():
        raise FileNotFoundError(f"Input not found: {inp}")

    data = load_artifact(inp)
    if add_metadata:
        meta = dict(data.get("metadata") or {})
        meta["exported_at"] = datetime.now(timezone.utc).isoformat()
        meta["source_file"] = str(inp)
        if "incidents" in data:
            meta["total_incidents"] = len(data["incidents"])
        if "decisions" in data:
            meta["total_decisions"] = len(data["decisions"])
        data = {**data, "metadata": meta}

    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Export threat report as JSON")
    parser.add_argument(
        "--input", "-i",
        default=DEFAULT_INPUT,
        help=f"Input artifact path (default: {DEFAULT_INPUT})",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output JSON path (default: reports/output/threat_report_<timestamp>.json)",
    )
    parser.add_argument(
        "--no-metadata",
        action="store_true",
        help="Do not add metadata (exported_at, total_incidents, etc.)",
    )
    args = parser.parse_args()
    output_path = args.output or str(timestamped_path("json"))
    try:
        out = export_json(args.input, output_path, add_metadata=not args.no_metadata)
        print(f"Exported: {out}")
        return 0
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
