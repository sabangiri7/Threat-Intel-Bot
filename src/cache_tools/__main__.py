"""
CLI for cache inspection and management.

Usage:
    python -m src.cache_tools --stats          Show cache statistics
    python -m src.cache_tools --purge          Remove entries older than 30 days
    python -m src.cache_tools --clear          Wipe entire cache
    python -m src.cache_tools --export FILE    Dump cache to a JSON file
"""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.cache.cache import PermanentCache, _DEFAULT_CACHE_FILE


def _print_stats(cache: PermanentCache) -> None:
    s = cache.stats()
    print("=" * 55)
    print("  PERMANENT CACHE — STATISTICS")
    print("=" * 55)
    print(f"  Cache file:          {s['cache_file']}")
    print(f"  File size:           {s['cache_file_size_kb']:.1f} KB")
    print(f"  Total entries:       {s['total_entries']} / {s['max_size']}")
    print()
    print(f"  Fresh  (<{s['stale_threshold_days']}d):      {s['fresh_entries']}")
    print(f"  Stale  ({s['stale_threshold_days']}–{s['purge_threshold_days']}d):    {s['stale_entries']}")
    print(f"  Expired (>{s['purge_threshold_days']}d):     {s['expired_entries']}")
    print()
    print(f"  Session hits:        {s['hits']}")
    print(f"  Session misses:      {s['misses']}")
    print(f"  Session hit rate:    {s['hit_rate']}%")
    print(f"  Stale hits:          {s.get('stale_hits', 0)}")
    print("=" * 55)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m src.cache_tools",
        description="Inspect and manage the IOC enrichment cache",
    )
    parser.add_argument("--stats", action="store_true", help="Show cache statistics")
    parser.add_argument("--purge", action="store_true", help="Remove entries older than purge threshold")
    parser.add_argument("--clear", action="store_true", help="Wipe entire cache")
    parser.add_argument("--export", type=str, metavar="FILE", help="Export cache to JSON file")
    parser.add_argument("--cache-file", type=str, default=_DEFAULT_CACHE_FILE, help="Path to cache file")
    args = parser.parse_args()

    if not any([args.stats, args.purge, args.clear, args.export]):
        args.stats = True

    cache = PermanentCache(cache_file=args.cache_file)

    if args.clear:
        count = len(cache)
        cache.clear()
        cache.save()
        print(f"Cache cleared ({count} entries removed).")

    if args.purge:
        removed = cache.purge_expired()
        cache.save()
        print(f"Purged {removed} expired entries.")

    if args.export:
        out = Path(args.export)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            json.dump({"entries": cache._entries}, fh, indent=2, default=str)
        print(f"Exported {len(cache)} entries to {args.export}")

    if args.stats:
        _print_stats(cache)


if __name__ == "__main__":
    main()
