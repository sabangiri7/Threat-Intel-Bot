#!/usr/bin/env python3
"""
Verify key metrics for Threat-Intel-Bot (Slide 7):

  1. Cache Hit Rate     - from get_cache_stats() after enrichment
  2. API Success Rate   - success / (success + error) across api_results
  3. Average Enrichment Time - total_time / num_iocs in seconds

Usage:
  python scripts/verify_metrics.py                    # Live APIs, sample IOCs
  python scripts/verify_metrics.py --clear-cache     # Clear cache first, then run live (forces API calls)
  python scripts/verify_metrics.py --mock             # Mock data (offline)
  python scripts/verify_metrics.py --load results.json # From saved enrichment JSON
  python scripts/verify_metrics.py --save out.json    # Save results and print metrics
"""

import argparse
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

# Sample IOCs for quick verification (IP, DOMAIN, etc.)
SAMPLE_IOCS = [
    ("8.8.8.8", "IP"),
    ("1.1.1.1", "IP"),
    ("google.com", "DOMAIN"),
    ("cloudflare.com", "DOMAIN"),
    ("example.com", "DOMAIN"),
    ("192.0.2.1", "IP"),
    ("198.51.100.1", "IP"),
    ("203.0.113.1", "IP"),
]


def compute_api_success_rate(enriched_results: list) -> dict:
    """Compute API success rate from enrichment results."""
    total = 0
    success = 0
    for item in enriched_results:
        api_results = item.get("api_results", {})
        for source, data in api_results.items():
            if not isinstance(data, dict):
                continue
            status = data.get("status")
            if status is None:
                # Mock data may omit status; treat as success for counting
                status = "success"
            total += 1
            if str(status).lower() == "success":
                success += 1
    rate = (success / total * 100) if total > 0 else 0.0
    return {
        "api_success_rate_pct": round(rate, 1),
        "api_calls_total": total,
        "api_calls_success": success,
    }


def run_live_enrichment(iocs: list) -> tuple[list, float, dict]:
    """Run live enrichment and return (results, elapsed_seconds, cache_stats)."""
    from src.enrichment.enrichment import IOCEnricher
    enricher = IOCEnricher()
    batch = [{"ioc_value": v, "ioc_type": t} for v, t in iocs]
    start = time.perf_counter()
    results = enricher.enrich_batch(batch)
    elapsed = time.perf_counter() - start
    cache_stats = enricher.get_batch_cache_stats()
    return results, elapsed, cache_stats


def run_mock_enrichment(iocs: list) -> tuple[list, float]:
    """Run mock enrichment with status in api_results for metrics."""
    from datetime import datetime, timezone
    import hashlib

    def _hash(s: str) -> int:
        return int(hashlib.md5(s.encode()).hexdigest()[:8], 16)

    results = []
    start = time.perf_counter()
    for value, ioc_type in iocs:
        seed = _hash(value)
        conf = (seed % 10001) / 100.0
        # Simulate mixed success/error for realistic API success rate
        vt_status = "success" if (seed % 10) < 9 else "error"
        otx_status = "success" if (seed % 10) < 8 else "error"
        tf_status = "success" if (seed % 10) < 9 else "not_found"
        ab_status = "success" if ioc_type.lower() == "ip" and (seed % 10) < 9 else "error"
        results.append({
            "ioc_value": value,
            "ioc_type": ioc_type,
            "api_results": {
                "virustotal": {"status": vt_status, "malicious": seed % 50},
                "otx": {"status": otx_status, "pulse_count": seed % 5},
                "threatfox": {"status": tf_status, "confidence": seed % 100},
                "abuseipdb": {"status": ab_status, "abuseConfidenceScore": seed % 100},
            },
        })
    elapsed = time.perf_counter() - start
    return results, elapsed


def main():
    parser = argparse.ArgumentParser(
        description="Verify Cache Hit Rate, API Success Rate, and Average Enrichment Time"
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Use mock enrichment (offline, no API keys)",
    )
    parser.add_argument(
        "--load",
        type=str,
        metavar="FILE",
        help="Load enrichment results from JSON file (API success only)",
    )
    parser.add_argument(
        "--save",
        type=str,
        metavar="FILE",
        help="Save enrichment results to JSON",
    )
    parser.add_argument(
        "--iocs",
        type=int,
        default=None,
        help="Number of sample IOCs to use (default: all %d)" % len(SAMPLE_IOCS),
    )
    parser.add_argument(
        "--clear-cache",
        action="store_true",
        help="Clear enrichment cache before running (live mode only; forces API calls)",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  METRICS VERIFICATION (Slide 7)")
    print("=" * 60)

    enriched_results = []
    elapsed_sec = 0.0
    from_cache = False

    if args.load:
        p = Path(args.load)
        if not p.exists():
            print(f"ERROR: File not found: {args.load}")
            sys.exit(1)
        with open(p, "r") as f:
            data = json.load(f)
        enriched_results = data if isinstance(data, list) else data.get("results", data.get("enriched", []))
        print(f"\nLoaded {len(enriched_results)} IOCs from {args.load}")
        from_cache = True
    else:
        iocs = SAMPLE_IOCS[: (args.iocs or len(SAMPLE_IOCS))]
        print(f"\nMode: {'MOCK' if args.mock else 'LIVE'}")
        print(f"IOCs: {len(iocs)}")
        cache_stats = {}
        if args.mock:
            enriched_results, elapsed_sec = run_mock_enrichment(iocs)
        else:
            if args.clear_cache:
                from src.cache import clear_cache
                clear_cache()
                print("Cache cleared.")
            enriched_results, elapsed_sec, cache_stats = run_live_enrichment(iocs)
        print(f"Elapsed: {elapsed_sec:.2f} s")

    if args.save:
        out = Path(args.save)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w") as f:
            json.dump(enriched_results, f, indent=2, default=str)
        print(f"Saved to {args.save}")

    # 1. API Success Rate
    api_stats = compute_api_success_rate(enriched_results)
    print("\n--- 1. API Success Rate ---")
    print(f"  Total API calls:  {api_stats['api_calls_total']}")
    print(f"  Successful:       {api_stats['api_calls_success']}")
    print(f"  API Success Rate: {api_stats['api_success_rate_pct']}%")

    # 2. Cache Hit Rate (from enricher's batch tracking - reliable)
    if not from_cache and not args.mock:
        print("\n--- 2. Cache Hit Rate ---")
        print(f"  Hits:      {cache_stats.get('hits', 0)}")
        print(f"  Misses:    {cache_stats.get('misses', 0)}")
        print(f"  Hit Rate:  {cache_stats.get('hit_rate', 0):.1f}%")
    else:
        print("\n--- 2. Cache Hit Rate ---")
        if args.mock:
            print("  N/A (mock mode does not use cache)")
        else:
            print("  N/A (loaded from file; run live to see cache stats)")

    # 3. Average Enrichment Time
    print("\n--- 3. Average Enrichment Time ---")
    if elapsed_sec > 0 and enriched_results:
        avg = elapsed_sec / len(enriched_results)
        print(f"  Total time:     {elapsed_sec:.2f} s")
        print(f"  IOCs enriched:  {len(enriched_results)}")
        print(f"  Average/IOC:    {avg:.2f} s")
    else:
        if from_cache:
            print("  N/A (loaded from file; run live to measure)")
        else:
            print("  N/A")

    print("\n" + "=" * 60)
    print("  DONE")
    print("=" * 60)


if __name__ == "__main__":
    main()
