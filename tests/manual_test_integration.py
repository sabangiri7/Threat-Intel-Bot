#!/usr/bin/env python3
# =============================================================================
# Manual Interactive Integration Test (end-to-end)
# =============================================================================
# Usage:
#   python tests/manual_test_integration.py
#   python tests/manual_test_integration.py --mock
#   python tests/manual_test_integration.py --mock --save report.json
#   python tests/manual_test_integration.py --verbose
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

logger = logging.getLogger("manual_test_integration")

# ── Constants ────────────────────────────────────────────────────────────────

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
    try:
        from src.classification import IOCClassifier
        t, _ = IOCClassifier().classify(value)
        if t != "UNKNOWN":
            return t
    except Exception:
        pass
    value = value.strip()
    for ioc_type, pattern in IOC_PATTERNS.items():
        if re.match(pattern, value):
            return ioc_type
    return "UNKNOWN"


# ── Mock enrichment (full pipeline mock) ─────────────────────────────────────

def generate_mock_enrichment(ioc_value: str, ioc_type: str) -> dict:
    """Deterministic mock enrichment in the *output schema* (0-100 confidence)."""
    seed = _deterministic_int(ioc_value)
    confidence = round((seed % 10001) / 100.0, 2)

    if ioc_type in ("DOMAIN", "URL"):
        net = TEST_NETS[seed % len(TEST_NETS)]
        resolves_to = f"{net}.{(seed >> 8) % 254 + 1}"
    else:
        resolves_to = ""

    family = MALWARE_FAMILIES[seed % len(MALWARE_FAMILIES)] if confidence > 85 else "UNKNOWN"

    if confidence >= 85:
        action = "BLOCK"
    elif confidence >= 70:
        action = "QUARANTINE"
    elif confidence >= 50:
        action = "MONITOR"
    else:
        action = "IGNORE"

    vt_mal = seed % 71
    abuse = seed % 101
    otx_p = seed % 12
    tf_c = seed % 101

    return {
        "ioc_value": ioc_value,
        "ioc_type": ioc_type,
        "enrichment_timestamp": datetime.now(timezone.utc).isoformat(),
        "unified_confidence": confidence,
        "malware_family": family,
        "resolves_to": resolves_to,
        "recommended_action": action,
        "api_results": {
            "virustotal": {"malicious": vt_mal, "harmless": 70 - vt_mal},
            "abuseipdb": {"abuseConfidenceScore": abuse, "totalReports": seed % 500},
            "otx": {"found": otx_p > 0, "pulse_count": otx_p},
            "threatfox": {"confidence": tf_c, "threat_type": "c2" if tf_c > 70 else "payload_delivery"},
        },
    }


# ── Format converters ────────────────────────────────────────────────────────

def _enriched_to_correlation_format(enriched: dict) -> dict:
    """Convert output-schema enriched dict to correlation-engine input format."""
    conf_raw = enriched.get("unified_confidence", 0.0)
    conf_0_1 = conf_raw / 100.0 if conf_raw > 1.0 else conf_raw

    ioc_type = (enriched.get("ioc_type") or "UNKNOWN").upper()

    if conf_0_1 >= 0.70:
        action = "BLOCK"
    elif conf_0_1 >= 0.30:
        action = "MONITOR"
    else:
        action = "IGNORE"

    api_raw = enriched.get("api_results", {})
    api_corr = {}
    if "virustotal" in api_raw:
        vt = api_raw["virustotal"]
        api_corr["virustotal"] = {
            "malicious": vt.get("malicious", vt.get("detections", 0)),
            "detections": vt.get("detections", vt.get("malicious", 0)),
        }
    if "abuseipdb" in api_raw:
        ab = api_raw["abuseipdb"]
        api_corr["abuseipdb"] = {
            "abuseconfidencescore": ab.get("abuseconfidencescore",
                                           ab.get("abuseConfidenceScore",
                                                   ab.get("abuse_confidence_score", 0))),
        }
    if "otx" in api_raw:
        ox = api_raw["otx"]
        api_corr["otx"] = {
            "pulsecount": ox.get("pulsecount", ox.get("pulse_count", 0)),
        }
    if "threatfox" in api_raw:
        tf = api_raw["threatfox"]
        api_corr["threatfox"] = {
            "confidencelevel": tf.get("confidencelevel",
                                      tf.get("confidence_level",
                                              tf.get("confidence", 0))),
        }

    return {
        "iocvalue": enriched.get("ioc_value", ""),
        "ioctype": ioc_type,
        "unifiedconfidence": conf_0_1,
        "triageaction": action,
        "malwarefamily": enriched.get("malware_family", "UNKNOWN"),
        "resolvesto": enriched.get("resolves_to", ""),
        "otxpulses": [],
        "timestamp": enriched.get("enrichment_timestamp",
                                  enriched.get("timestamp",
                                               datetime.now(timezone.utc).isoformat())),
        "apiresults": api_corr,
    }


def _normalise_real_enriched(raw: dict) -> dict:
    """Normalise real enrichment engine output into the output schema."""
    conf_raw = raw.get("unified_confidence", 0.0)
    conf_pct = round(conf_raw * 100, 2) if conf_raw <= 1.0 else round(conf_raw, 2)
    if conf_pct >= 85:
        action = "BLOCK"
    elif conf_pct >= 70:
        action = "QUARANTINE"
    elif conf_pct >= 50:
        action = "MONITOR"
    else:
        action = "IGNORE"

    return {
        "ioc_value": raw.get("ioc_value", ""),
        "ioc_type": raw.get("ioc_type", ""),
        "enrichment_timestamp": raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "api_results": raw.get("api_results", {}),
        "unified_confidence": conf_pct,
        "malware_family": raw.get("malware_family", "UNKNOWN"),
        "resolves_to": raw.get("resolves_to", ""),
        "recommended_action": action,
    }


# ── Load engines ─────────────────────────────────────────────────────────────

def _load_enricher():
    try:
        from src.enrichment.enrichment import IOCEnricher
        return IOCEnricher()
    except Exception:
        pass
    try:
        from src.enrichment import IOCEnricher
        return IOCEnricher(use_cache=False)
    except Exception:
        pass
    return None


def _load_correlate():
    for mod_path, fn_name in [
        ("src.correlation.engine.engine", "correlate_iocs"),
        ("src.correlation", "correlate_iocs"),
    ]:
        try:
            mod = __import__(mod_path, fromlist=[fn_name])
            fn = getattr(mod, fn_name, None)
            if callable(fn):
                return fn
        except Exception:
            continue

    for mod_path, cls_name in [
        ("src.correlation.engine.engine", "CorrelationEngine"),
        ("src.correlation", "CorrelationEngine"),
    ]:
        try:
            mod = __import__(mod_path, fromlist=[cls_name])
            engine = getattr(mod, cls_name)()
            if hasattr(engine, "correlate"):
                return engine.correlate
        except Exception:
            continue
    return None


# ── Interactive prompt ───────────────────────────────────────────────────────

def prompt_iocs() -> list:
    print("\nEnter IOC values (comma-separated):")
    raw = input("  > ").strip()
    if not raw:
        return []

    values = [v.strip() for v in raw.split(",") if v.strip()]

    print("\nIOC type for ALL (blank = auto-detect per IOC):")
    print("  Options: IP, DOMAIN, URL, HASH")
    global_type = input("  > ").strip().upper()
    if global_type and global_type not in ("IP", "DOMAIN", "URL", "HASH"):
        print(f"  Unknown type '{global_type}', will auto-detect.")
        global_type = ""

    results = []
    for v in values:
        t = global_type if global_type else classify_ioc(v)
        results.append((v, t))

    print(f"\n  Parsed {len(results)} IOC(s):")
    for v, t in results:
        print(f"    {v}  [{t}]")
    return results


# ── Main ─────────────────────────────────────────────────────────────────────

def main(args=None):
    parser = argparse.ArgumentParser(description="Manual end-to-end integration test")
    parser.add_argument("--mock", action="store_true", help="Use mock enrichment (offline)")
    parser.add_argument("--save", type=str, default=None, metavar="FILE", help="Save full report JSON")
    parser.add_argument("--verbose", action="store_true", help="Debug logging")
    opts = parser.parse_args(args)

    level = logging.DEBUG if opts.verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(asctime)s %(name)s %(levelname)s %(message)s", force=True)

    print("=" * 70)
    print("  MANUAL INTEGRATION TEST  (Enrichment -> Correlation)")
    print("  Mode: " + ("MOCK (offline)" if opts.mock else "LIVE APIs"))
    print("=" * 70)

    iocs = prompt_iocs()
    if not iocs:
        print("No IOCs entered. Exiting.")
        return

    # ── STEP 1: Enrichment ───────────────────────────────────────────────
    print("\n" + "-" * 70)
    print("  STEP 1: ENRICHMENT")
    print("-" * 70)

    enriched_results = []

    if opts.mock:
        print("  Using mock enrichment data...")
        for value, ioc_type in iocs:
            enriched_results.append(generate_mock_enrichment(value, ioc_type))
    else:
        enricher = _load_enricher()
        if enricher:
            print("  Using real enrichment engine...")
            for value, ioc_type in iocs:
                try:
                    ioc_type_for_engine = ioc_type.lower() if hasattr(enricher, '_safe_check') else ioc_type
                    raw = enricher.enrich_ioc(value, ioc_type_for_engine)
                    enriched_results.append(_normalise_real_enriched(raw))
                except Exception as exc:
                    print(f"    ERROR enriching {value}: {exc}")
                    print(f"    Falling back to mock for this IOC.")
                    enriched_results.append(generate_mock_enrichment(value, ioc_type))
        else:
            print("  Enrichment engine unavailable. Using mock data.")
            for value, ioc_type in iocs:
                enriched_results.append(generate_mock_enrichment(value, ioc_type))

    print(f"\n  Enriched {len(enriched_results)} IOC(s).\n")
    print(json.dumps(enriched_results, indent=2, default=str))

    # ── STEP 2: Correlation ──────────────────────────────────────────────
    print("\n" + "-" * 70)
    print("  STEP 2: CORRELATION")
    print("-" * 70)

    correlate_fn = _load_correlate()
    if not correlate_fn:
        print("  ERROR: Could not load correlation engine.")
        print("  Ensure you run from project root: python tests/manual_test_integration.py")
        return

    corr_input = [_enriched_to_correlation_format(e) for e in enriched_results]

    try:
        incidents = correlate_fn(corr_input)
    except Exception as exc:
        print(f"  Correlation failed: {exc}")
        if opts.verbose:
            import traceback
            traceback.print_exc()
        return

    print(f"\n  Generated {len(incidents)} incident group(s).\n")
    print(json.dumps(incidents, indent=2, default=str))

    # ── STEP 3: Final Report ─────────────────────────────────────────────
    print("\n" + "-" * 70)
    print("  STEP 3: INCIDENT REPORT")
    print("-" * 70)

    for inc in incidents:
        score = inc.get("score", {})
        severity = score.get("severity_level", "UNKNOWN")
        final_score = score.get("final_score", 0)
        families = ", ".join(inc.get("malware_families", ["UNKNOWN"]))
        ioc_list = inc.get("ioc_values", [])

        print(f"\n  {inc['incident_id']}  [{severity}]  score={final_score:.1f}")
        print(f"    Malware families : {families}")
        print(f"    IOC types        : {', '.join(inc.get('ioc_types', []))}")
        print(f"    Group size       : {inc['group_size']}")
        print(f"    IOCs             : {', '.join(ioc_list[:5])}", end="")
        if len(ioc_list) > 5:
            print(f" + {len(ioc_list) - 5} more")
        else:
            print()
        print(f"    Reasoning        : {score.get('reasoning', '-')}")

    # ── Save ─────────────────────────────────────────────────────────────
    full_report = {
        "run_timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": "mock" if opts.mock else "live",
        "input_iocs": [{"value": v, "type": t} for v, t in iocs],
        "enrichment_results": enriched_results,
        "correlation_incidents": incidents,
    }

    if opts.save:
        out_path = Path(opts.save)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(full_report, f, indent=2, default=str)
        print(f"\n  Full report saved to {out_path}")

    print("\n" + "=" * 70)
    print("  INTEGRATION TEST COMPLETE")
    print("=" * 70 + "\n")

    return full_report


if __name__ == "__main__":
    main()
