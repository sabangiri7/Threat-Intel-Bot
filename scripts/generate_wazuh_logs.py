#!/usr/bin/env python3
"""
Convert Threat Intel Platform snapshot JSON into Wazuh-friendly NDJSON logs.

Reads ``output/platform_snapshot.json`` (or a path you pass with ``--input``),
extracts each incident, and **appends** one compact JSON object per line to the
output file (UTF-8, append mode, each line terminated with a newline).
Wazuh expects one JSON event per line (no pretty-printing).

**Lab-only:** This script is for local / lab SIEM demonstration. It does not
deploy to production networks.

Usage:
    python scripts/generate_wazuh_logs.py
    python scripts/generate_wazuh_logs.py --input output/platform_snapshot.json --output output/intel.log
    python scripts/generate_wazuh_logs.py --output /var/ossec/logs/intel/intel.log   # Linux lab
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Default paths (project root = parent of scripts/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = PROJECT_ROOT / "output" / "platform_snapshot.json"
DEFAULT_OUTPUT = PROJECT_ROOT / "output" / "intel.log"

SOURCE_LABEL = "FYP-ThreatIntelBot"
DEFAULT_MALWARE_FAMILY = "Unknown"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate one-line JSON Wazuh log events from platform_snapshot.json",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help=f"Path to platform snapshot JSON (default: {DEFAULT_INPUT})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"NDJSON log file path (default: {DEFAULT_OUTPUT})",
    )
    return parser.parse_args()


def _load_platform(path: Path) -> Dict[str, Any]:
    """Load and parse the platform JSON file."""
    if not path.exists():
        raise FileNotFoundError(
            f"Platform snapshot not found: {path}. "
            f"Generate it first, e.g. `python -m src.platform --demo 20 --output {path}` "
            f"or copy examples/platform_snapshot.json to this path."
        )
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _build_ioc_lookup(iocs: List[Dict[str, Any]]) -> Dict[str, str]:
    """Map ioc_value -> ioc_type from the platform ``iocs`` array."""
    lookup: Dict[str, str] = {}
    for row in iocs:
        val = row.get("ioc_value")
        if val is None:
            continue
        t = (row.get("ioc_type") or "unknown").lower()
        lookup[str(val).strip()] = t
    return lookup


def _infer_ioc_type(ioc_value: str) -> str:
    """Best-effort IOC type when not found in the platform ``iocs`` list."""
    v = ioc_value.strip()
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", v):
        return "ip"
    if re.match(r"^https?://", v, re.I):
        return "url"
    if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", v):
        return "hash"
    if "." in v and " " not in v:
        return "domain"
    return "unknown"


def _normalize_timestamp(raw: Optional[str]) -> str:
    """Return an ISO8601 UTC string ending with Z (Wazuh-friendly)."""
    if raw:
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, TypeError):
            pass
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _triage_action_from_incident(incident: Dict[str, Any]) -> str:
    """
    Derive a coarse triage label for the Wazuh log line.

    Prefer keywords in ``recommended_action``; otherwise map from ``severity``.
    """
    rec = str(incident.get("recommended_action") or "").upper()
    if "BLOCK" in rec:
        return "BLOCK"
    if "QUARANTINE" in rec:
        return "QUARANTINE"
    if "MONITOR" in rec:
        return "MONITOR"
    if "IGNORE" in rec:
        return "IGNORE"

    sev = str(incident.get("severity") or "LOW").upper()
    if sev == "CRITICAL":
        return "BLOCK"
    if sev == "HIGH":
        return "BLOCK"
    if sev == "MEDIUM":
        return "MONITOR"
    return "IGNORE"


def _pick_ioc_value(ioc_values: List[Any]) -> str:
    """Use the first IOC, or join with commas if you prefer a single string."""
    if not ioc_values:
        return ""
    first = ioc_values[0]
    if first is None:
        return ""
    return str(first).strip()


def incident_to_wazuh_line(
    incident: Dict[str, Any],
    ioc_type_lookup: Dict[str, str],
    timestamp: str,
) -> Dict[str, Any]:
    """
    Build the flat JSON object for one incident (keys must match Wazuh decoder expectations).
    """
    ioc_values = incident.get("ioc_values") or []
    if not isinstance(ioc_values, list):
        ioc_values = []

    ioc_value = _pick_ioc_value(ioc_values)
    ioc_type = ioc_type_lookup.get(ioc_value) or _infer_ioc_type(ioc_value)

    family = incident.get("malware_family")
    if family is None or str(family).strip() == "" or str(family).upper() == "UNKNOWN":
        malware_family = DEFAULT_MALWARE_FAMILY
    else:
        malware_family = str(family)

    risk = incident.get("risk_score", 0)
    try:
        risk_score = int(round(float(risk)))
    except (TypeError, ValueError):
        risk_score = 0

    return {
        "source": SOURCE_LABEL,
        "incident_id": str(incident.get("incident_id") or "INC-0000"),
        "severity": str(incident.get("severity") or "LOW").upper(),
        "malware_family": malware_family,
        "ioc_value": ioc_value,
        "ioc_type": ioc_type,
        "triage_action": _triage_action_from_incident(incident),
        "risk_score": risk_score,
        "timestamp": timestamp,
    }


def generate_wazuh_logs(
    platform: Dict[str, Any],
    output_path: Path,
) -> int:
    """
    Append one JSON object per line for each incident (UTF-8, newline-terminated).

    Opens the log in append mode so the Wazuh agent can tail the file safely.
    Delete or truncate ``intel.log`` manually if you need a full refresh.

    Returns:
        Number of lines written this run.
    """
    incidents = platform.get("incidents")
    if incidents is None:
        raise ValueError("Platform JSON missing required key: 'incidents'")
    if not isinstance(incidents, list):
        raise ValueError("'incidents' must be a JSON array")

    iocs = platform.get("iocs") or []
    if not isinstance(iocs, list):
        iocs = []
    lookup = _build_ioc_lookup(iocs)

    ts = _normalize_timestamp(platform.get("generated_at"))

    output_path.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with open(output_path, "a", encoding="utf-8") as out:
        for inc in incidents:
            if not isinstance(inc, dict):
                continue
            line_obj = incident_to_wazuh_line(inc, lookup, ts)
            line = json.dumps(line_obj, separators=(",", ":"), ensure_ascii=False)
            out.write(line + "\n")
            count += 1

    return count


def main() -> int:
    args = _parse_args()
    try:
        platform = _load_platform(args.input)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON in {args.input}: {exc}", file=sys.stderr)
        return 1

    try:
        n = generate_wazuh_logs(platform, args.output)
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"Appended {n} log line(s) to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
