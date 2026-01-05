"""
Public API wrapper for Phase 2 IOC Enrichment Engine.

This module exposes a simple, stable interface around `IOCEnricher` so that
other components (CLI tools, dashboards, Phase 3 correlation engine) can
consume enrichment services without depending directly on the implementation
details in `enrichment.py`.
"""

import sys
import os
from pathlib import Path
from typing import Dict, List, Optional

# ============================================================================
# SMART PATH HANDLING - Works from any directory
# ============================================================================

current_file = Path(__file__).resolve()
current_dir = current_file.parent  # src/enrichment/
enrichment_dir = current_dir
src_dir = enrichment_dir.parent  # src/
project_root = src_dir.parent  # project root

for path_to_add in [str(enrichment_dir), str(src_dir), str(project_root)]:
    if path_to_add not in sys.path:
        sys.path.insert(0, path_to_add)

# ============================================================================
# FLEXIBLE IMPORTS
# ============================================================================

IOCEnricher = None
get_cache = None
get_cache_stats_func = None

try:
    from enrichment import IOCEnricher
except ImportError:
    try:
        from src.enrichment.enrichment import IOCEnricher
    except ImportError:
        import importlib.util
        spec = importlib.util.spec_from_file_location("enrichment", str(src_dir / "enrichment" / "enrichment.py"))
        if spec and spec.loader:
            enrichment_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(enrichment_module)
            IOCEnricher = enrichment_module.IOCEnricher

try:
    from cache import get_cache, get_cache_stats as get_cache_stats_func
except ImportError:
    try:
        from src.cache import get_cache, get_cache_stats as get_cache_stats_func
    except ImportError:
        import importlib.util
        spec = importlib.util.spec_from_file_location("cache", str(src_dir / "cache" / "cache.py"))
        if spec and spec.loader:
            cache_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cache_module)
            get_cache = cache_module.get_cache
            get_cache_stats_func = cache_module.get_cache_stats

# ============================================================================
# SINGLETON ENRICHER INSTANCE & HELPERS
# ============================================================================

_ENRICHER: Optional[IOCEnricher] = None

def _get_enricher() -> IOCEnricher:
    global _ENRICHER
    if _ENRICHER is None:
        _ENRICHER = IOCEnricher()
    return _ENRICHER

def _normalize_ioc_type(ioc_type: str) -> str:
    """Normalize IOC type to match engine's strict validation."""
    if not ioc_type: return "unknown"
    t = ioc_type.lower().strip()
    if t == 'ip': return 'IP'
    if t == 'url': return 'URL'
    return t  # domain and hash remain lowercase

# ============================================================================
# PUBLIC API FUNCTIONS
# ============================================================================

def enrich_single(ioc_value: str, ioc_type: str) -> Dict:
    """Enrich a single IOC using the Phase 2 engine."""
    enricher = _get_enricher()
    normalized_type = _normalize_ioc_type(ioc_type)
    return enricher.enrich_ioc(ioc_value, normalized_type)

def enrich_batch(iocs: List[Dict[str, str]]) -> List[Dict]:
    """Enrich a batch of IOCs."""
    enricher = _get_enricher()
    normalized_iocs = []
    for item in iocs:
        normalized_item = item.copy()
        if "ioc_type" in normalized_item:
            normalized_item["ioc_type"] = _normalize_ioc_type(normalized_item["ioc_type"])
        normalized_iocs.append(normalized_item)
    return enricher.enrich_batch(normalized_iocs)

def get_enriched_from_cache(ioc_value: str, ioc_type: str) -> Optional[Dict]:
    """Retrieve an enriched IOC directly from the cache."""
    cache = get_cache()
    normalized_type = _normalize_ioc_type(ioc_type)
    key = f"{normalized_type}::{ioc_value.strip()}"
    return cache.get(key)

def get_cache_stats() -> Dict:
    """Return cache performance statistics using the cache module utility."""
    return get_cache_stats_func()

# ============================================================================
# DEMO / TEST
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("Phase 2 Enrichment API Demo")
    print("=" * 70 + "\n")

    demo_iocs = [
        {"ioc_value": "8.8.8.8", "ioc_type": "ip"},
        {"ioc_value": "google.com", "ioc_type": "domain"},
    ]

    print("Enrich single IOC:")
    single = enrich_single("8.8.8.8", "ip")
    print(f"- IOC: {single.get('ioc_value')} ({single.get('ioc_type')})")
    print(f"  Confidence: {single.get('unified_confidence', 0.0):.2f}")
    print(f"  Action: {single.get('triage_action', 'UNKNOWN')}\n")

    print("Enrich batch of IOCs:")
    batch_results = enrich_batch(demo_iocs)
    for r in batch_results:
        print(f"- IOC: {r.get('ioc_value')} ({r.get('ioc_type')}) "
              f"=> {r.get('triage_action', 'UNKNOWN')} "
              f"(conf={r.get('unified_confidence', 0.0):.2f})")

    print("\n" + "=" * 70)
    print("Cache Statistics:")
    print("=" * 70)
    try:
        stats = get_cache_stats()
        for k, v in stats.items():
            print(f"  {k}: {v}")
    except Exception as e:
        print(f"  ❌ Could not retrieve stats: {e}")
    print("=" * 70)