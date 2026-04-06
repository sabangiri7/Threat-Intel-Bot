"""
CLI entrypoint for the Threat Intelligence Platform generator.

Usage:
    python -m src.platform --input data/sample_enriched_iocs.json --output examples/platform_snapshot.json
    python -m src.platform --demo 20 --output examples/platform_snapshot.json
"""

import argparse
import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.platform.threat_intel_platform import (
    generate_platform_json,
    load_iocs_from_file,
    generate_demo_iocs,
    save_platform_json,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m src.platform",
        description="Generate a Threat Intelligence Platform JSON snapshot",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input", type=str, metavar="FILE", help="Path to enriched IOC JSON file")
    group.add_argument("--demo", type=int, metavar="N", help="Generate N demo IOCs instead of loading a file")

    parser.add_argument("--output", type=str, default="examples/platform_snapshot.json", help="Output path (default: examples/platform_snapshot.json)")
    parser.add_argument("--no-correlation", action="store_true", help="Skip correlation and decision engines")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load or generate IOCs
    if args.input:
        path = Path(args.input)
        if not path.exists():
            print(f"ERROR: File not found: {args.input}")
            sys.exit(1)
        iocs = load_iocs_from_file(args.input)
        print(f"Loaded {len(iocs)} IOCs from {args.input}")
    else:
        iocs = generate_demo_iocs(args.demo)
        print(f"Generated {len(iocs)} demo IOCs")

    # Generate platform JSON
    platform = generate_platform_json(iocs, run_correlation=not args.no_correlation)

    # Save
    save_platform_json(platform, args.output)

    # Print summary
    s = platform["summary"]
    print()
    print("=" * 55)
    print("  PLATFORM JSON GENERATED")
    print("=" * 55)
    print(f"  Output:     {args.output}")
    print(f"  IOCs:       {s['total_iocs']}")
    print(f"  Incidents:  {s['total_incidents']}")
    print(f"  Critical:   {s['critical_incidents']}")
    print(f"  High:       {s['high_incidents']}")
    print(f"  Campaigns:  {s['campaigns_detected']}")
    if s.get("unique_malware_families"):
        print(f"  Families:   {', '.join(s['unique_malware_families'])}")
    print("=" * 55)


if __name__ == "__main__":
    main()
