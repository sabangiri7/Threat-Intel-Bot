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
    from cache import get_cache, save_cache, get_cache_stats
except ImportError:
    try:
        from src.cache import get_cache, save_cache, get_cache_stats
    except ImportError as e:
        logger.error(f"Fatal import error for cache: {e}")
        sys.exit(1)

try:
    from api_handlers.virustotal_handler import VirusTotalHandler
    from api_handlers.otx_handler import OTXHandler
    from api_handlers.threatfox_handler import ThreatFoxHandler
    from api_handlers.abuseipdb_handler import AbuseIPDBHandler
except ImportError:
    try:
        from src.api_handlers.virustotal_handler import VirusTotalHandler
        from src.api_handlers.otx_handler import OTXHandler
        from src.api_handlers.threatfox_handler import ThreatFoxHandler
        from src.api_handlers.abuseipdb_handler import AbuseIPDBHandler
    except ImportError as e:
        logger.error(f"Fatal import error for handlers: {e}")
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
                "error": "check() not implemented"
            }

        try:
            result = handler.check(ioc_value, ioc_type)
            if not isinstance(result, dict):
                raise ValueError("Invalid response format")

            result.setdefault("status", "success")
            result.setdefault("source", source)
            return result

        except Exception as e:
            logger.error(f"{source} failed for {ioc_value}: {e}")
            return {
                "status": "error",
                "source": source,
                "error": str(e)
            }

    # ----------------------------------------------------------------------

    def _compute_unified_confidence(self, api_results: Dict, ioc_type: str) -> float:
        """
        Compute confidence from actual API signals (NOT from per-handler 'confidence').
        This fixes the 0.0 confidence issue in cache.
        
        Scoring rules:
        - VirusTotal: 0 detections=0%, 1-3=0.25, 4-9=0.45, 10+=0.60
        - OTX: 0=0%, 1=0.20, 5+=0.35
        - ThreatFox: If found in ThreatFox=+0.50
        - AbuseIPDB (IP only): abuse_confidence_score (0-100) with whitelisting check
        """
        vt = api_results.get("virustotal", {}) or {}
        otx = api_results.get("otx", {}) or {}
        tf = api_results.get("threatfox", {}) or {}
        ab = api_results.get("abuseipdb", {}) or {}

        score = 0.0

        # ---------------------------
        # VirusTotal signals
        # ---------------------------
        if vt.get("status") == "success":
            detections = int(vt.get("detections", 0) or 0)
            if detections >= 10:
                score += 0.60
            elif detections >= 4:
                score += 0.45
            elif detections >= 1:
                score += 0.25

        # ---------------------------
        # OTX signals
        # ---------------------------
        if otx.get("status") == "success":
            pulse_count = int(otx.get("pulse_count", 0) or 0)
            if pulse_count >= 5:
                score += 0.35
            elif pulse_count >= 1:
                score += 0.20

        # ---------------------------
        # ThreatFox signals
        # ---------------------------
        if tf.get("status") == "success":
            # finding IOC in ThreatFox is a strong signal
            score += 0.50

        # ---------------------------
        # AbuseIPDB signals (IP only)
        # ---------------------------
        if ioc_type == "ip" and ab.get("status") == "success":
            # If whitelisted, do not treat reports as malicious
            if ab.get("is_whitelisted") is True:
                score += 0.0
            else:
                # Use abuse_confidence_score directly (0-100 scale, convert to 0.0-1.0)
                abuse_score = int(ab.get("abuse_confidence_score", 0) or 0)
                if abuse_score > 0:
                    score += min(abuse_score / 100.0, 1.0)

        # Clamp final score to [0.0, 1.0]
        return max(0.0, min(1.0, score))

    # ----------------------------------------------------------------------

    def enrich_ioc(self, ioc_value: str, ioc_type: str) -> Dict:
        """
        Enrich a single IOC.
        """
        ioc_type = ioc_type.strip().lower()
        cache = get_cache()
        cache_key = f"{ioc_type}::{ioc_value.strip()}"

        # Check cache first
        if cache_key in cache:
            logger.info(f"💾 Cache hit: {cache_key}")
            return cache[cache_key]

        logger.info(f"🔍 Enriching IOC: {ioc_value} ({ioc_type})")

        api_results = {}

        for source, handler in self.handlers.items():
            if source == "abuseipdb" and ioc_type != "ip":
                continue

            api_results[source] = self._safe_check(handler, source, ioc_value, ioc_type)

        # ------------------------------------------------------------------
        # Aggregate confidence (FIXED)
        # ------------------------------------------------------------------
        unified_confidence = self._compute_unified_confidence(api_results, ioc_type)

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

        cache[cache_key] = enriched

        if random.random() < 0.1:
            save_cache()

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

        save_cache()
        logger.info("✅ Batch enrichment complete")
        return results

    # ----------------------------------------------------------------------

    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        return get_cache_stats()
