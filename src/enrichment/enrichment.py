import os
import sys
import logging
import random
from typing import Dict, List
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

# ============================================================================
# PATH HANDLING
# ============================================================================

current_file = Path(__file__).resolve()
enrichment_dir = current_file.parent
src_dir = enrichment_dir.parent
project_root = src_dir.parent

if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

env_file = project_root / ".env"
load_dotenv(dotenv_path=env_file if env_file.exists() else None)

# ============================================================================
# IMPORTS
# ============================================================================

try:
    from src.cache import get_cache
except ImportError:
    from cache import get_cache

try:
    from src.api_handlers.virustotal_handler import VirusTotalHandler
    from src.api_handlers.otx_handler import OTXHandler
    from src.api_handlers.threatfox_handler import ThreatFoxHandler
    from src.api_handlers.abuseipdb_handler import AbuseIPDBHandler
except ImportError as e:
    print(f"❌ Fatal import error: {e}")
    sys.exit(1)

# ============================================================================
# LOGGING
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ============================================================================
# IOC ENRICHER
# ============================================================================

class IOCEnricher:
    """
    Orchestrates multi-source IOC enrichment with caching and triage.
    """

    def __init__(self):
        logger.info("Initializing IOC Enricher with 4 API handlers")

        self.handlers = {
            "virustotal": VirusTotalHandler(),
            "otx": OTXHandler(),
            "threatfox": ThreatFoxHandler(),
            "abuseipdb": AbuseIPDBHandler()
        }

        logger.info("✅ IOC Enricher ready")

    # ----------------------------------------------------------------------

    def _safe_check(self, handler, source: str, ioc_value: str, ioc_type: str) -> Dict:
        """
        Safely call handler.check() and normalize failures.
        """
        if not hasattr(handler, "check"):
            logger.error(f"{source} handler has no check() method")
            return {
                "status": "error",
                "source": source,
                "confidence": 0.0,
                "error": "check() not implemented"
            }

        try:
            result = handler.check(ioc_value, ioc_type)
            if not isinstance(result, dict):
                raise ValueError("Invalid response format")

            result.setdefault("confidence", 0.0)
            result.setdefault("status", "success")
            result.setdefault("source", source)

            return result

        except Exception as e:
            logger.error(f"{source} failed for {ioc_value}: {e}")
            return {
                "status": "error",
                "source": source,
                "confidence": 0.0,
                "error": str(e)
            }

    # ----------------------------------------------------------------------

    def enrich_ioc(self, ioc_value: str, ioc_type: str) -> Dict:
        """
        Enrich a single IOC.
        """

        ioc_type = ioc_type.strip().lower()
        cache = get_cache()
        cache_key = f"{ioc_type}::{ioc_value.strip()}"

        cached = cache.get(cache_key)
        if cached:
            logger.info(f"💾 Cache hit: {cache_key}")
            return cached

        logger.info(f"🔍 Enriching IOC: {ioc_value} ({ioc_type})")

        api_results = {}

        for source, handler in self.handlers.items():
            if source == "abuseipdb" and ioc_type != "ip":
                continue

            api_results[source] = self._safe_check(
                handler, source, ioc_value, ioc_type
            )

        # ------------------------------------------------------------------
        # Aggregate confidence
        # ------------------------------------------------------------------

        valid_scores = [
            r["confidence"]
            for r in api_results.values()
            if r.get("status") == "success"
        ]

        unified_confidence = (
            sum(valid_scores) / len(valid_scores)
            if valid_scores else 0.0
        )

        if unified_confidence >= 0.70:
            triage_action = "BLOCK"
        elif unified_confidence >= 0.30:
            triage_action = "MONITOR"
        else:
            triage_action = "IGNORE"

        enriched = {
            "ioc_value": ioc_value,
            "ioc_type": ioc_type,
            "unified_confidence": round(unified_confidence, 3),
            "triage_action": triage_action,
            "api_results": api_results,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        cache.set(cache_key, enriched)

        if random.random() < 0.1:
            cache.save_to_disk()

        logger.info(
            f"✅ Enrichment complete: {ioc_value} "
            f"(confidence={unified_confidence:.2f}, action={triage_action})"
        )

        return enriched

    # ----------------------------------------------------------------------

    def enrich_batch(self, iocs: List[Dict]) -> List[Dict]:
        """
        Enrich multiple IOCs.
        """

        logger.info(f"📦 Starting batch enrichment: {len(iocs)} IOCs")
        results = []

        for idx, ioc in enumerate(iocs, 1):
            ioc_value = ioc.get("ioc_value")
            ioc_type = ioc.get("ioc_type", "")

            if not ioc_value:
                logger.warning(f"⚠️ Skipping IOC #{idx}: missing value")
                continue

            try:
                logger.info(f"  [{idx}/{len(iocs)}] {ioc_value}")
                results.append(self.enrich_ioc(ioc_value, ioc_type))
            except Exception as e:
                logger.error(f"❌ Fatal error enriching {ioc_value}: {e}")
                results.append({
                    "ioc_value": ioc_value,
                    "ioc_type": ioc_type,
                    "triage_action": "ERROR",
                    "error": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })

        get_cache().save_to_disk()
        logger.info("✅ Batch enrichment complete")

        return results

    # ----------------------------------------------------------------------

    def get_cache_stats(self) -> Dict:
        return get_cache().get_stats()

# ============================================================================
# DEMO
# ============================================================================

if __name__ == "__main__":

    print("\n" + "=" * 70)
    print("IOC ENRICHMENT ENGINE - Demo")
    print("=" * 70 + "\n")

    enricher = IOCEnricher()

    sample_iocs = [
        {"ioc_value": "8.8.8.8", "ioc_type": "IP"},
        {"ioc_value": "192.168.1.1", "ioc_type": "IP"},
        {"ioc_value": "google.com", "ioc_type": "domain"},
    ]

    results = enricher.enrich_batch(sample_iocs)

    print("\n" + "=" * 70)
    print("ENRICHMENT RESULTS")
    print("=" * 70 + "\n")

    for r in results:
        print(f"IOC: {r['ioc_value']} ({r['ioc_type']})")
        print(f"  Action: {r['triage_action']}")

        if "error" in r:
            print(f"  Error: {r['error']}")
        else:
            print(f"  Confidence: {r['unified_confidence']:.2f}")
            print(f"  APIs queried: {len(r.get('api_results', {}))}")

        print()

    stats = enricher.get_cache_stats()
    print("=" * 70)
    print("CACHE STATISTICS")
    print("=" * 70)
    print(f"Size: {stats['current_size']}/{stats['max_size']}")
    print(f"Hits: {stats['hits']} | Misses: {stats['misses']}")
    print(f"Hit rate: {stats['hit_rate']:.1f}%")
    print("=" * 70)