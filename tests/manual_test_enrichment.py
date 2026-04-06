#!/usr/bin/env python3
# =============================================================================
# Manual Interactive Enrichment Test
# =============================================================================
# Usage:
#   python tests/manual_test_enrichment.py
#   python tests/manual_test_enrichment.py --mock
#   python tests/manual_test_enrichment.py --mock --save results.json
#   python tests/manual_test_enrichment.py --verbose
#   python tests/manual_test_enrichment.py --sources vt,otx
# =============================================================================

import sys
import os
import re
import json
import hashlib
import argparse
import logging
import time
from pathlib import Path
from datetime import datetime, timezone

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

logger = logging.getLogger("manual_test_enrichment")

# ── IOC classification (standalone fallback) ─────────────────────────────────

IOC_PATTERNS = {
    "IP":     r"^(\d{1,3}\.){3}\d{1,3}$",
    "DOMAIN": r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$",
    "URL":    r"^https?://",
    "HASH":   r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$",
}


def classify_ioc(value: str) -> str:
    """Classify an IOC value into IP / DOMAIN / URL / HASH / UNKNOWN."""
    try:
        from src.classification import IOCClassifier
        classifier = IOCClassifier()
        ioc_type, _ = classifier.classify(value)
        if ioc_type != "UNKNOWN":
            return ioc_type
    except Exception:
        pass

    value = value.strip()
    for ioc_type, pattern in IOC_PATTERNS.items():
        if re.match(pattern, value):
            return ioc_type
    return "UNKNOWN"


# ── Mock enrichment ──────────────────────────────────────────────────────────

TEST_NETS = ["192.0.2", "198.51.100", "203.0.113"]

MALWARE_FAMILIES = [
    "Trojan.GenericKD", "Ransom.WannaCry", "Backdoor.Cobalt",
    "Trojan.Emotet", "Infostealer.AgentTesla", "RAT.AsyncRAT",
]


def _deterministic_int(ioc_value: str, salt: str = "") -> int:
    digest = hashlib.md5((ioc_value + salt).encode()).hexdigest()
    return int(digest[:8], 16)


def generate_mock_enrichment(ioc_value: str, ioc_type: str) -> dict:
    """Generate deterministic fake enrichment for a single IOC."""
    seed = _deterministic_int(ioc_value)
    confidence = (seed % 10001) / 100.0  # 0.00 – 100.00

    if ioc_type in ("DOMAIN", "URL"):
        net = TEST_NETS[seed % len(TEST_NETS)]
        resolves_to = f"{net}.{(seed >> 8) % 254 + 1}"
    else:
        resolves_to = ""

    if confidence > 85:
        family = MALWARE_FAMILIES[seed % len(MALWARE_FAMILIES)]
    else:
        family = "UNKNOWN"

    vt_malicious = (seed % 71)
    vt_harmless = 70 - vt_malicious
    abuse_score = (seed % 101)
    otx_pulses = (seed % 12)
    tf_conf = (seed % 101)

    if confidence >= 85:
        action = "BLOCK"
    elif confidence >= 70:
        action = "QUARANTINE"
    elif confidence >= 50:
        action = "MONITOR"
    else:
        action = "IGNORE"

    return {
        "ioc_value": ioc_value,
        "ioc_type": ioc_type,
        "enrichment_timestamp": datetime.now(timezone.utc).isoformat(),
        "unified_confidence": round(confidence, 2),
        "malware_family": family,
        "resolves_to": resolves_to,
        "recommended_action": action,
        "api_results": {
            "virustotal": {"malicious": vt_malicious, "harmless": vt_harmless},
            "abuseipdb": {"abuseConfidenceScore": abuse_score, "totalReports": (seed % 500)},
            "otx": {"found": otx_pulses > 0, "pulse_count": otx_pulses},
            "threatfox": {"confidence": tf_conf, "threat_type": "c2" if tf_conf > 70 else "payload_delivery"},
        },
    }


# ── Real enrichment helpers ──────────────────────────────────────────────────

def _action_from_confidence(conf_0_1: float) -> str:
    """Map 0-100 confidence to recommended action (slide thresholds)."""
    pct = conf_0_1 * 100 if conf_0_1 <= 1.0 else conf_0_1
    if pct >= 85:
        return "BLOCK"
    if pct >= 70:
        return "QUARANTINE"
    if pct >= 50:
        return "MONITOR"
    return "IGNORE"


def _normalise_enriched(raw: dict) -> dict:
    """Normalise enrichment engine output into the standard output schema."""
    conf_raw = raw.get("unified_confidence", 0.0)
    conf_pct = round(conf_raw * 100, 2) if conf_raw <= 1.0 else round(conf_raw, 2)

    return {
        "ioc_value": raw.get("ioc_value", ""),
        "ioc_type": raw.get("ioc_type", ""),
        "enrichment_timestamp": raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "api_results": raw.get("api_results", {}),
        "unified_confidence": conf_pct,
        "malware_family": raw.get("malware_family", "UNKNOWN"),
        "resolves_to": raw.get("resolves_to", ""),
        "recommended_action": _action_from_confidence(conf_raw),
    }


def _load_enricher():
    """Try to import and instantiate the real enrichment engine."""
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


def _load_handlers(sources: list):
    """Load individual API handlers if full engine unavailable."""
    mapping = {
        "vt":        ("src.api_handlers.virustotal_handler", "VirusTotalHandler"),
        "abuseipdb": ("src.api_handlers.abuseipdb_handler",  "AbuseIPDBHandler"),
        "otx":       ("src.api_handlers.otx_handler",        "OTXHandler"),
        "threatfox": ("src.api_handlers.threatfox_handler",   "ThreatFoxHandler"),
    }
    handlers = {}
    for key in sources:
        if key not in mapping:
            continue
        mod_path, cls_name = mapping[key]
        try:
            mod = __import__(mod_path, fromlist=[cls_name])
            handlers[key] = getattr(mod, cls_name)()
        except Exception as exc:
            logger.warning("Could not load handler %s: %s", key, exc)
    return handlers


# ── Interactive prompts ──────────────────────────────────────────────────────

def prompt_iocs() -> list:
    """Ask user for IOCs (comma-separated). Returns list of (value, type)."""
    print("\nEnter IOC values (comma-separated):")
    raw = input("  > ").strip()
    if not raw:
        print("No IOCs entered.")
        return []

    values = [v.strip() for v in raw.split(",") if v.strip()]

    print("\nIOC type for ALL (leave blank to auto-detect per IOC):")
    print("  Options: IP, DOMAIN, URL, HASH")
    global_type = input("  > ").strip().upper()
    if global_type and global_type not in ("IP", "DOMAIN", "URL", "HASH"):
        print(f"  Unknown type '{global_type}', will auto-detect.")
        global_type = ""

    results = []
    for v in values:
        t = global_type if global_type else classify_ioc(v)
        results.append((v, t))
        logger.debug("Classified %s -> %s", v, t)

    print(f"\n  Parsed {len(results)} IOC(s):")
    for v, t in results:
        print(f"    {v}  [{t}]")
    return results


def prompt_sources() -> list:
    """Ask which API sources to query."""
    print("\nWhich sources? (comma-separated, or 'all')")
    print("  Options: vt, abuseipdb, otx, threatfox, all")
    raw = input("  > ").strip().lower()
    if not raw or raw == "all":
        return ["vt", "abuseipdb", "otx", "threatfox"]
    return [s.strip() for s in raw.split(",") if s.strip()]


# ── Main ─────────────────────────────────────────────────────────────────────

def main(args=None):
    parser = argparse.ArgumentParser(description="Manual interactive enrichment test")
    parser.add_argument("--mock", action="store_true", help="Use mock data instead of real APIs")
    parser.add_argument("--save", type=str, default=None, metavar="FILE", help="Save output JSON to file")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--sources", type=str, default=None, help="Comma-separated sources (vt,abuseipdb,otx,threatfox)")
    opts = parser.parse_args(args)

    level = logging.DEBUG if opts.verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    print("=" * 70)
    print("  MANUAL ENRICHMENT TEST")
    print("  Mode: " + ("MOCK (offline)" if opts.mock else "LIVE APIs"))
    print("=" * 70)

    iocs = prompt_iocs()
    if not iocs:
        return

    sources = (
        [s.strip() for s in opts.sources.split(",")]
        if opts.sources
        else prompt_sources()
    )

    enriched_results = []
    t0 = time.perf_counter()

    if opts.mock:
        for value, ioc_type in iocs:
            enriched_results.append(generate_mock_enrichment(value, ioc_type))
    else:
        enricher = _load_enricher()
        if enricher:
            print("\nUsing enrichment engine...")
            for value, ioc_type in iocs:
                try:
                    ioc_type_for_engine = ioc_type.lower() if hasattr(enricher, '_safe_check') else ioc_type
                    raw = enricher.enrich_ioc(value, ioc_type_for_engine)
                    enriched_results.append(_normalise_enriched(raw))
                except Exception as exc:
                    print(f"  ERROR enriching {value}: {exc}")
                    enriched_results.append(generate_mock_enrichment(value, ioc_type))
        else:
            print("\nEnrichment engine unavailable, trying individual handlers...")
            handlers = _load_handlers(sources)
            if not handlers:
                print("  No handlers loaded. Falling back to mock data.")
                for value, ioc_type in iocs:
                    enriched_results.append(generate_mock_enrichment(value, ioc_type))
            else:
                for value, ioc_type in iocs:
                    api_results = {}
                    for name, handler in handlers.items():
                        try:
                            if hasattr(handler, "enrich_ioc"):
                                api_results[name] = handler.enrich_ioc(value, ioc_type)
                            elif hasattr(handler, "check"):
                                api_results[name] = handler.check(value, ioc_type)
                        except Exception as exc:
                            api_results[name] = {"status": "error", "error": str(exc)}
                    enriched_results.append({
                        "ioc_value": value,
                        "ioc_type": ioc_type,
                        "enrichment_timestamp": datetime.now(timezone.utc).isoformat(),
                        "api_results": api_results,
                        "unified_confidence": 0.0,
                        "malware_family": "UNKNOWN",
                        "resolves_to": "",
                        "recommended_action": "IGNORE",
                    })

    elapsed = time.perf_counter() - t0
    print("\n" + "=" * 70)
    print("  ENRICHMENT RESULTS")
    if enriched_results and elapsed >= 0:
        avg_time = elapsed / len(enriched_results)
        print(f"  Time: {elapsed:.2f}s total, {avg_time:.2f}s avg/IOC")
    print("=" * 70)
    print(json.dumps(enriched_results, indent=2, default=str))

    if opts.save:
        out_path = Path(opts.save)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(enriched_results, f, indent=2, default=str)
        print(f"\nResults saved to {out_path}")

    # Print cache stats after live enrichment (cache hit rate for metrics)
    if not opts.mock:
        try:
            from src.cache import get_cache_stats
            stats = get_cache_stats()
            total = stats.get("hits", 0) + stats.get("misses", 0)
            if total > 0:
                print(f"\n--- Cache stats (for metrics verification) ---")
                print(f"  Hits: {stats.get('hits')}  Misses: {stats.get('misses')}  Hit rate: {stats.get('hit_rate', 0):.1f}%")
        except Exception:
            pass

    return enriched_results


if __name__ == "__main__":
    main()
