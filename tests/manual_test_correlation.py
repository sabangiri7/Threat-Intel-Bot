#!/usr/bin/env python3
# =============================================================================
# Manual Interactive Correlation Test
# =============================================================================
# Usage:
#   python tests/manual_test_correlation.py
#   python tests/manual_test_correlation.py --mock
#   python tests/manual_test_correlation.py --save incidents.json
#   python tests/manual_test_correlation.py --verbose
# =============================================================================

import sys
import os
import re
import json
import hashlib
import argparse
import logging
from pathlib import Path
from datetime import datetime, timezone

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

logger = logging.getLogger("manual_test_correlation")

# ── Mock enriched IOC generation (reused from enrichment test) ───────────────

TEST_NETS = ["192.0.2", "198.51.100", "203.0.113"]
MALWARE_FAMILIES = [
    "Trojan.GenericKD", "Ransom.WannaCry", "Backdoor.Cobalt",
    "Trojan.Emotet", "Infostealer.AgentTesla", "RAT.AsyncRAT",
]

IOC_PATTERNS = {
    "IP":     r"^(\d{1,3}\.){3}\d{1,3}$",
    "DOMAIN": r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$",
    "URL":    r"^https?://",
    "HASH":   r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$",
}

def _deterministic_int(ioc_value: str, salt: str = "") -> int:
    return int(hashlib.md5((ioc_value + salt).encode()).hexdigest()[:8], 16)

def classify_ioc(value: str) -> str:
    value = value.strip()
    for ioc_type, pattern in IOC_PATTERNS.items():
        if re.match(pattern, value):
            return ioc_type
    return "UNKNOWN"

def _mock_enriched_for_correlation(ioc_value: str, ioc_type: str,
                                   resolves_to: str = "",
                                   malware_family: str = "",
                                   unified_confidence: float = None) -> dict:
    """Build an enriched IOC dict in *correlation-engine format* (no underscores)."""
    seed = _deterministic_int(ioc_value)

    if unified_confidence is None:
        unified_confidence = round((seed % 10001) / 10000.0, 4)

    if not resolves_to and ioc_type in ("DOMAIN", "URL"):
        net = TEST_NETS[seed % len(TEST_NETS)]
        resolves_to = f"{net}.{(seed >> 8) % 254 + 1}"

    if not malware_family:
        if unified_confidence > 0.85:
            malware_family = MALWARE_FAMILIES[seed % len(MALWARE_FAMILIES)]
        else:
            malware_family = "UNKNOWN"

    if unified_confidence >= 0.70:
        action = "BLOCK"
    elif unified_confidence >= 0.30:
        action = "MONITOR"
    else:
        action = "IGNORE"

    vt_malicious = seed % 71
    abuse_score = seed % 101
    otx_pulses = seed % 12
    tf_conf = seed % 101

    return {
        "iocvalue": ioc_value,
        "ioctype": ioc_type.upper(),
        "unifiedconfidence": unified_confidence,
        "triageaction": action,
        "malwarefamily": malware_family,
        "resolvesto": resolves_to,
        "otxpulses": [f"pulse-{i:03d}" for i in range(min(otx_pulses, 3))],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "apiresults": {
            "virustotal": {"malicious": vt_malicious, "detections": vt_malicious},
            "abuseipdb": {"abuseconfidencescore": abuse_score},
            "otx": {"pulsecount": otx_pulses},
            "threatfox": {"confidencelevel": tf_conf},
        },
    }

# ── Load correlation engine ──────────────────────────────────────────────────

def _load_correlate():
    """Try several import paths; return callable or None."""
    attempts = [
        ("src.correlation.engine.engine", "correlate_iocs"),
        ("src.correlation", "correlate_iocs"),
        ("correlation.engine.engine", "correlate_iocs"),
    ]
    for mod_path, fn_name in attempts:
        try:
            mod = __import__(mod_path, fromlist=[fn_name])
            fn = getattr(mod, fn_name, None)
            if callable(fn):
                logger.debug("Loaded %s.%s", mod_path, fn_name)
                return fn
        except Exception:
            continue

    for mod_path, cls_name in [
        ("src.correlation.engine.engine", "CorrelationEngine"),
        ("src.correlation", "CorrelationEngine"),
    ]:
        try:
            mod = __import__(mod_path, fromlist=[cls_name])
            cls = getattr(mod, cls_name)
            engine = cls()
            if hasattr(engine, "correlate"):
                return engine.correlate
        except Exception:
            continue
    return None

# ── Interactive prompts ──────────────────────────────────────────────────────

def prompt_enriched_iocs_json() -> list:
    """Ask user to paste a JSON list of enriched IOCs."""
    print("\nPaste a JSON array of enriched IOC dicts (end with an empty line):")
    lines = []
    while True:
        line = input()
        if line.strip() == "":
            break
        lines.append(line)
    text = "\n".join(lines).strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            data = [data]
        return data
    except json.JSONDecodeError as exc:
        print(f"  JSON parse error: {exc}")
        return []

def prompt_enriched_iocs_manual() -> list:
    """Walk user through entering enriched IOC fields one by one."""
    iocs = []
    print("\nEnter enriched IOCs interactively (blank IOC value to stop):\n")
    idx = 0
    while True:
        idx += 1
        print(f"--- IOC #{idx} ---")
        value = input("  ioc_value: ").strip()
        if not value:
            break

        ioc_type = input("  ioc_type [auto-detect]: ").strip().upper()
        if not ioc_type:
            ioc_type = classify_ioc(value)
            print(f"    -> auto-detected: {ioc_type}")

        conf_raw = input("  unified_confidence (0-1, blank=0.5): ").strip()
        try:
            conf = float(conf_raw) if conf_raw else 0.5
        except ValueError:
            conf = 0.5

        family = input("  malware_family [UNKNOWN]: ").strip() or "UNKNOWN"
        resolves = input("  resolves_to [blank]: ").strip()

        iocs.append(_mock_enriched_for_correlation(
            value, ioc_type,
            resolves_to=resolves,
            malware_family=family,
            unified_confidence=conf,
        ))
    return iocs

# ── Main ─────────────────────────────────────────────────────────────────────

def main(args=None):
    parser = argparse.ArgumentParser(description="Manual interactive correlation test")
    parser.add_argument("--mock", action="store_true", help="Generate mock enriched IOCs for demo")
    parser.add_argument("--save", type=str, default=None, metavar="FILE", help="Save output JSON")
    parser.add_argument("--verbose", action="store_true", help="Debug logging")
    opts = parser.parse_args(args)

    level = logging.DEBUG if opts.verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(asctime)s %(name)s %(levelname)s %(message)s", force=True)

    print("=" * 70)
    print("  MANUAL CORRELATION TEST")
    print("=" * 70)

    # Collect enriched IOCs
    if opts.mock:
        sample_values = [
            ("malware-c2.com", "DOMAIN"),
            ("evil-payload.ru", "DOMAIN"),
            ("192.168.1.50", "IP"),
            ("dropper.net", "DOMAIN"),
            ("d41d8cd98f00b204e9800998ecf8427e", "HASH"),
        ]
        enriched_iocs = [
            _mock_enriched_for_correlation(v, t) for v, t in sample_values
        ]
        print(f"\n  Generated {len(enriched_iocs)} mock enriched IOCs.\n")
    else:
        print("\nHow do you want to provide enriched IOCs?")
        print("  1) Paste JSON")
        print("  2) Enter fields interactively")
        choice = input("  > ").strip()
        if choice == "1":
            enriched_iocs = prompt_enriched_iocs_json()
        else:
            enriched_iocs = prompt_enriched_iocs_manual()

    if not enriched_iocs:
        print("No IOCs provided. Exiting.")
        return

    # Normalise keys: accept both underscore and no-underscore forms
    normalised = []
    for ioc in enriched_iocs:
        entry = {
            "iocvalue": ioc.get("iocvalue") or ioc.get("ioc_value", ""),
            "ioctype": (ioc.get("ioctype") or ioc.get("ioc_type", "UNKNOWN")).upper(),
            "unifiedconfidence": ioc.get("unifiedconfidence") or ioc.get("unified_confidence", 0.5),
            "triageaction": ioc.get("triageaction") or ioc.get("triage_action", "MONITOR"),
            "malwarefamily": ioc.get("malwarefamily") or ioc.get("malware_family", "UNKNOWN"),
            "resolvesto": ioc.get("resolvesto") or ioc.get("resolves_to", ""),
            "otxpulses": ioc.get("otxpulses", []),
            "timestamp": ioc.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "apiresults": ioc.get("apiresults") or ioc.get("api_results", {}),
        }
        normalised.append(entry)

    print(f"\n  {len(normalised)} IOC(s) ready for correlation.\n")

    # Run correlation
    correlate_fn = _load_correlate()
    if not correlate_fn:
        print("ERROR: Could not import correlation engine.")
        print("Make sure you are running from the project root directory.")
        return

    try:
        incidents = correlate_fn(normalised)
    except Exception as exc:
        print(f"\nCorrelation failed: {exc}")
        if opts.verbose:
            import traceback
            traceback.print_exc()
        return

    print("\n" + "=" * 70)
    print("  CORRELATION RESULTS")
    print("=" * 70)
    print(json.dumps(incidents, indent=2, default=str))

    # Summary with Malware Families included
    print(f"\n  Total incident groups: {len(incidents)}")
    for inc in incidents:
        score = inc.get("score", {})
        
        # Safely extract malware families; default to empty list if key missing
        families = inc.get("malware_families", [])
        if not families:  # if empty list or None
            family_str = "UNKNOWN"
        else:
            family_str = ", ".join(families)

        print(
            f"    {inc.get('incident_id', 'INC-????')}  |  "
            f"size={inc.get('group_size', 0)}  |  "
            f"severity={score.get('severity_level', '?')}  |  "
            f"score={score.get('final_score', 0):.1f}  |  "
            f"family={family_str}"
        )

    if opts.save:
        out_path = Path(opts.save)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(incidents, f, indent=2, default=str)
        print(f"\nResults saved to {out_path}")

    return incidents

if __name__ == "__main__":
    main()