#!/usr/bin/env python3
# =============================================================================
# Manual Test Runner – Menu-driven launcher
# =============================================================================
# Usage:
#   python tests/manual_test_all.py
#   python tests/manual_test_all.py --mock
#   python tests/manual_test_all.py --verbose
# =============================================================================

import sys
import argparse
import logging
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from tests.manual_test_enrichment import main as enrichment_main
from tests.manual_test_correlation import main as correlation_main
from tests.manual_test_integration import main as integration_main


def print_menu():
    print()
    print("=" * 50)
    print("  THREAT-INTEL-BOT  –  Manual Test Runner")
    print("=" * 50)
    print()
    print("  1)  Enrichment test")
    print("  2)  Correlation test")
    print("  3)  Integration test (end-to-end)")
    print("  4)  Exit")
    print()


def main():
    parser = argparse.ArgumentParser(description="Menu-driven manual test runner")
    parser.add_argument("--mock", action="store_true", help="Pass --mock to sub-tests")
    parser.add_argument("--save", type=str, default=None, metavar="FILE", help="Pass --save to sub-tests")
    parser.add_argument("--verbose", action="store_true", help="Pass --verbose to sub-tests")
    opts = parser.parse_args()

    level = logging.DEBUG if opts.verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(asctime)s %(name)s %(levelname)s %(message)s", force=True)

    sub_args = []
    if opts.mock:
        sub_args.append("--mock")
    if opts.verbose:
        sub_args.append("--verbose")
    if opts.save:
        sub_args.extend(["--save", opts.save])

    while True:
        print_menu()
        choice = input("  Select [1-4]: ").strip()

        if choice == "1":
            print("\n>>> Running Enrichment Test ...\n")
            try:
                enrichment_main(sub_args if sub_args else None)
            except (SystemExit, KeyboardInterrupt):
                pass
            except Exception as exc:
                print(f"\n  Test error: {exc}")

        elif choice == "2":
            print("\n>>> Running Correlation Test ...\n")
            try:
                correlation_main(sub_args if sub_args else None)
            except (SystemExit, KeyboardInterrupt):
                pass
            except Exception as exc:
                print(f"\n  Test error: {exc}")

        elif choice == "3":
            print("\n>>> Running Integration Test ...\n")
            try:
                integration_main(sub_args if sub_args else None)
            except (SystemExit, KeyboardInterrupt):
                pass
            except Exception as exc:
                print(f"\n  Test error: {exc}")

        elif choice == "4":
            print("\nGoodbye.\n")
            break

        else:
            print("  Invalid choice. Enter 1-4.")


if __name__ == "__main__":
    main()
