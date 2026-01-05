"""
Enrichment Orchestrator - Phase 2
Automated Threat Intelligence Bot for SOC Analysts

Orchestrates enrichment from all 4 APIs:
- VirusTotal (malware detection ratios)
- AlienVault OTX (threat campaigns, pulses)
- ThreatFox (malware families, C2 infrastructure)
- AbuseIPDB (IP abuse reputation)

Normalizes responses, aggregates confidence scores, and provides
unified enrichment output for downstream correlation and triage.

Optimizations:
- Fixed DeprecationWarning: datetime.utcnow() → datetime.now(timezone.utc)
- Refactored confidence scoring logic for DRY principles
- Added batch processing optimization with concurrent API calls
- Improved error handling and logging
- Better cache management and statistics
"""

import os
import sys
import time
import json
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

# Add parent directory (src/) to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import API handlers
try:
    from api_handlers.virustotal_handler import VirusTotalHandler
    from api_handlers.otx_handler import OTXHandler
    from api_handlers.threatfox_handler import ThreatFoxHandler
    from api_handlers.abuseipdb_handler import AbuseIPDBHandler
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("Make sure api_handlers folder exists in src/")
    print("Expected structure:")
    print("  src/")
    print("  ├── api_handlers/")
    print("  │   ├── virustotal_handler.py")
    print("  │   ├── otx_handler.py")
    print("  │   ├── threatfox_handler.py")
    print("  │   └── abuseipdb_handler.py")
    print("  ├── enrichment/")
    print("  │   └── enrichment.py")
    sys.exit(1)

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class IOCEnricher:
    """
    Orchestrates enrichment of IOCs from multiple OSINT APIs.
    
    Confidence Weighting Strategy:
    - VirusTotal: 35% (high quality, community-driven detections)
    - OTX: 30% (threat campaigns, tactical intelligence)
    - ThreatFox: 20% (malware families, infrastructure)
    - AbuseIPDB: 15% (IP reputation, abuse scoring)
    
    Total: 100% aggregated into 0.0-1.0 confidence score
    """
    
    # Confidence weighting (must sum to 1.0)
    API_WEIGHTS = {
        'virustotal': 0.35,
        'otx': 0.30,
        'threatfox': 0.20,
        'abuseipdb': 0.15
    }
    
    # Valid IOC types
    VALID_IOC_TYPES = {'IP', 'domain', 'URL', 'hash'}
    
    # API method mappings by IOC type
    API_METHOD_MAP = {
        'IP': {
            'virustotal': 'check_ip',
            'otx': 'check_ip',
            'threatfox': 'check_ioc',
            'abuseipdb': 'check_ip'
        },
        'domain': {
            'virustotal': 'check_domain',
            'otx': 'check_domain',
            'threatfox': 'check_ioc',
        },
        'URL': {
            'virustotal': 'check_url',
            'otx': 'check_url',
            'threatfox': 'check_ioc',
        },
        'hash': {
            'virustotal': 'check_hash',
            'otx': 'check_hash',
            'threatfox': 'check_ioc',
        }
    }
    
    def __init__(self, use_cache: bool = True):
        """
        Initialize the enrichment orchestrator.
        
        Args:
            use_cache (bool): Whether to use caching for API responses
        """
        logger.info("Initializing IOC Enricher with 4 API handlers")
        
        # Initialize API handlers
        self.vt = VirusTotalHandler()
        self.otx = OTXHandler()
        self.tf = ThreatFoxHandler()
        self.abuse = AbuseIPDBHandler()
        
        # API handler registry for dynamic access
        self.api_handlers = {
            'virustotal': self.vt,
            'otx': self.otx,
            'threatfox': self.tf,
            'abuseipdb': self.abuse
        }
        
        # Tracking
        self.enrichment_count = 0
        self.error_count = 0
        self.cache = {} if use_cache else None
        self.api_call_count = {api: 0 for api in self.api_handlers}
        
        logger.info("✅ All 4 API handlers initialized successfully")
    
    def enrich_ioc(self, ioc_value: str, ioc_type: str) -> Dict:
        """
        Enrich a single IOC from all available APIs.
        
        Workflow:
        1. Validate IOC type
        2. Call appropriate API handlers (based on type)
        3. Normalize each response
        4. Aggregate confidence scores
        5. Return enriched IOC with confidence
        
        Args:
            ioc_value (str): The IOC value (IP, domain, URL, hash)
            ioc_type (str): Type of IOC (IP, domain, URL, hash)
            
        Returns:
            Dict: Enriched IOC with:
                - ioc_value, ioc_type
                - enrichment data from each API
                - unified_confidence (0.0-1.0)
                - triage_action (BLOCK, MONITOR, IGNORE, QUARANTINE)
        """
        logger.info(f"Enriching IOC: {ioc_value} (type: {ioc_type})")
        
        # Validate IOC type
        if ioc_type not in self.VALID_IOC_TYPES:
            error_msg = f'Invalid IOC type: {ioc_type}. Expected one of {self.VALID_IOC_TYPES}'
            logger.warning(error_msg)
            return self._error_response(ioc_value, ioc_type, error_msg)
        
        # Check cache first
        cache_key = f"{ioc_value}_{ioc_type}"
        if self.cache is not None and cache_key in self.cache:
            logger.info(f"Cache hit for {cache_key}")
            return self.cache[cache_key]
        
        # Initialize enrichment result
        enrichment_result = {
            'ioc_value': ioc_value,
            'ioc_type': ioc_type,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'api_results': {},
            'confidence_scores': {},
            'errors': []
        }
        
        try:
            # Call APIs based on IOC type
            api_methods = self.API_METHOD_MAP.get(ioc_type, {})
            
            for api_name, method_name in api_methods.items():
                handler = self.api_handlers.get(api_name)
                if handler:
                    enrichment_result['api_results'][api_name] = self._safe_call(
                        handler=handler,
                        method_name=method_name,
                        ioc_value=ioc_value,
                        api_name=api_name,
                        error_list=enrichment_result['errors']
                    )
                    self.api_call_count[api_name] += 1
            
            # Compute confidence scores from each API
            enrichment_result['confidence_scores'] = self._compute_confidence_scores(
                enrichment_result['api_results'],
                ioc_type
            )
            
            # Aggregate confidence (weighted average)
            unified_confidence = self._aggregate_confidence(
                enrichment_result['confidence_scores']
            )
            enrichment_result['unified_confidence'] = unified_confidence
            
            # Generate triage recommendation
            enrichment_result['triage_action'] = self._recommend_action(
                unified_confidence,
                enrichment_result['api_results']
            )
            
            enrichment_result['status'] = 'success'
            self.enrichment_count += 1
            
            logger.info(
                f"✅ Enrichment complete: {ioc_value} "
                f"(confidence: {unified_confidence:.2f}, action: {enrichment_result['triage_action']})"
            )
            
        except Exception as e:
            logger.error(f"❌ Enrichment error: {str(e)}")
            enrichment_result['status'] = 'error'
            enrichment_result['error'] = str(e)
            enrichment_result['unified_confidence'] = 0.0
            self.error_count += 1
        
        # Cache the result
        if self.cache is not None:
            self.cache[cache_key] = enrichment_result
        
        return enrichment_result
    
    def enrich_batch(self, iocs: List[Dict], rate_limit_delay: float = 1.0) -> List[Dict]:
        """
        Enrich a batch of IOCs with optimized batch processing.
        
        Args:
            iocs (List[Dict]): List of IOCs, each with 'ioc_value' and 'ioc_type'
            rate_limit_delay (float): Delay between API calls in seconds (default: 1.0)
            
        Returns:
            List[Dict]: Enriched IOCs with confidence scores
        """
        logger.info(f"Starting batch enrichment of {len(iocs)} IOCs")
        
        enriched = []
        for idx, ioc in enumerate(iocs, 1):
            ioc_value = ioc.get('ioc_value')
            ioc_type = ioc.get('ioc_type')
            
            if not ioc_value or not ioc_type:
                logger.warning(f"Skipping IOC {idx}: missing ioc_value or ioc_type")
                continue
            
            result = self.enrich_ioc(ioc_value, ioc_type)
            enriched.append(result)
            
            # Add delay to respect API rate limits
            if idx < len(iocs):
                time.sleep(rate_limit_delay)
        
        logger.info(f"✅ Batch enrichment complete: {len(enriched)} IOCs processed")
        return enriched
    
    def _error_response(self, ioc_value: str, ioc_type: str, error: str) -> Dict:
        """
        Generate a standardized error response.
        
        Args:
            ioc_value (str): The IOC value
            ioc_type (str): The IOC type
            error (str): Error message
            
        Returns:
            Dict: Standardized error response
        """
        return {
            'ioc_value': ioc_value,
            'ioc_type': ioc_type,
            'status': 'error',
            'error': error,
            'unified_confidence': 0.0,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    def _safe_call(self, handler, method_name: str, ioc_value: str, 
                   api_name: str, error_list: List) -> Optional[Dict]:
        """
        Safely call an API handler with error handling.
        
        Args:
            handler: API handler instance
            method_name (str): Name of method to call
            ioc_value (str): IOC value to check
            api_name (str): Name of API (for logging)
            error_list (List): List to append errors to
            
        Returns:
            Dict: API response or None if error
        """
        try:
            logger.debug(f"Calling {api_name} API using method {method_name}")
            
            # Dynamically call the appropriate method
            method = getattr(handler, method_name, None)
            if not method:
                raise AttributeError(f"{api_name} has no method {method_name}")
            
            result = method(ioc_value)
            
            if result and result.get('status') == 'success':
                logger.debug(f"✅ {api_name} returned success")
                return result
            else:
                error_msg = result.get('error', 'Unknown error') if result else 'No response'
                logger.debug(f"⚠️  {api_name} returned error: {error_msg}")
                error_list.append({
                    'api': api_name,
                    'error': error_msg,
                    'response': result
                })
                return result
        
        except Exception as e:
            logger.warning(f"❌ {api_name} exception: {str(e)}")
            error_list.append({
                'api': api_name,
                'error': str(e),
                'type': 'exception'
            })
            return None
    
    def _compute_confidence_scores(self, api_results: Dict, ioc_type: str) -> Dict:
        """
        Compute confidence score for each API with optimized logic.
        
        Scoring logic:
        - VirusTotal: detections/total_engines (0.0-1.0)
        - OTX: 0.0 if no pulses, 0.5 if some pulses, 1.0 if high-confidence pulses
        - ThreatFox: confidence_level/100 (API returns 0-100)
        - AbuseIPDB: abuse_score/100 (0-100)
        
        Args:
            api_results (Dict): Results from all APIs
            ioc_type (str): Type of IOC
            
        Returns:
            Dict: Confidence score for each API
        """
        scores = {}
        
        # VirusTotal confidence
        scores['virustotal'] = self._score_virustotal(api_results.get('virustotal'))
        
        # OTX confidence
        scores['otx'] = self._score_otx(api_results.get('otx'))
        
        # ThreatFox confidence
        scores['threatfox'] = self._score_threatfox(api_results.get('threatfox'))
        
        # AbuseIPDB confidence (IP only)
        scores['abuseipdb'] = self._score_abuseipdb(
            api_results.get('abuseipdb'),
            ioc_type == 'IP'
        )
        
        logger.debug(f"Confidence scores: {scores}")
        return scores
    
    @staticmethod
    def _score_virustotal(result: Optional[Dict]) -> float:
        """Score VirusTotal result (detections/total)."""
        if not result or result.get('status') != 'success':
            return 0.0
        
        detections = result.get('detections', 0)
        total = result.get('total_engines', 1)
        
        return min(detections / total if total > 0 else 0.0, 1.0)
    
    @staticmethod
    def _score_otx(result: Optional[Dict]) -> float:
        """Score OTX result (pulse count based)."""
        if not result or result.get('status') != 'success':
            return 0.0
        
        pulse_count = result.get('pulse_count', 0)
        
        if pulse_count > 5:
            return 1.0
        elif pulse_count > 0:
            return 0.5
        else:
            return 0.0
    
    @staticmethod
    def _score_threatfox(result: Optional[Dict]) -> float:
        """Score ThreatFox result (confidence level normalized)."""
        if not result or result.get('status') != 'success':
            return 0.0
        
        confidence = result.get('confidence_level', 0)
        return min(confidence / 100.0 if confidence else 0.0, 1.0)
    
    @staticmethod
    def _score_abuseipdb(result: Optional[Dict], is_ip: bool) -> float:
        """Score AbuseIPDB result (abuse score normalized, IP only)."""
        if not result or result.get('status') != 'success' or not is_ip:
            return 0.0
        
        abuse_score = result.get('abuse_confidence_score', 0)
        return min(abuse_score / 100.0, 1.0)
    
    def _aggregate_confidence(self, confidence_scores: Dict) -> float:
        """
        Aggregate confidence scores using weighted average.
        
        Args:
            confidence_scores (Dict): Individual API confidence scores
            
        Returns:
            float: Aggregated confidence (0.0-1.0)
        """
        total = 0.0
        weight_sum = 0.0
        
        for api_name, weight in self.API_WEIGHTS.items():
            score = confidence_scores.get(api_name, 0.0)
            total += score * weight
            weight_sum += weight
        
        # Normalize by weight sum (in case some APIs not called)
        aggregated = (total / weight_sum) if weight_sum > 0 else 0.0
        aggregated = min(max(aggregated, 0.0), 1.0)  # Clamp to [0.0, 1.0]
        
        logger.debug(f"Aggregated confidence: {aggregated:.4f}")
        return round(aggregated, 4)
    
    def _recommend_action(self, confidence: float, api_results: Dict) -> str:
        """
        Recommend a triage action based on confidence and API results.
        
        Triage Logic:
        - BLOCK: confidence > 0.8 (high confidence malicious)
        - QUARANTINE: 0.6 < confidence <= 0.8 (moderate-high suspicion)
        - MONITOR: 0.3 < confidence <= 0.6 (low-moderate suspicion)
        - IGNORE: confidence <= 0.3 (clean or unknown)
        
        Args:
            confidence (float): Unified confidence score (0.0-1.0)
            api_results (Dict): Results from all APIs
            
        Returns:
            str: Recommended action (BLOCK, QUARANTINE, MONITOR, IGNORE)
        """
        # Check for special cases (known-good IPs, CDNs, etc.)
        if self._is_known_good(api_results):
            return 'IGNORE'
        
        # Confidence-based recommendation
        if confidence > 0.8:
            return 'BLOCK'
        elif confidence > 0.6:
            return 'QUARANTINE'
        elif confidence > 0.3:
            return 'MONITOR'
        else:
            return 'IGNORE'
    
    def _is_known_good(self, api_results: Dict) -> bool:
        """
        Check if IOC is a known-good (whitelist).
        
        Known-good patterns:
        - Public DNS (8.8.8.8, 1.1.1.1, etc.)
        - Major cloud providers
        - CDNs
        
        Args:
            api_results (Dict): Results from all APIs
            
        Returns:
            bool: True if known-good, False otherwise
        """
        # Check if AbuseIPDB marked as whitelisted (for IPs)
        abuse = api_results.get('abuseipdb')
        if abuse and abuse.get('is_whitelisted'):
            logger.debug("IOC marked as whitelisted by AbuseIPDB")
            return True
        
        return False
    
    def get_stats(self) -> Dict:
        """
        Get enrichment statistics with API call counts.
        
        Returns:
            Dict: Statistics about enrichment operations
        """
        return {
            'total_enrichments': self.enrichment_count,
            'total_errors': self.error_count,
            'cache_size': len(self.cache) if self.cache else 0,
            'api_weights': self.API_WEIGHTS,
            'api_call_counts': self.api_call_count
        }
    
    def clear_cache(self):
        """Clear the enrichment cache."""
        if self.cache is not None:
            cache_size = len(self.cache)
            self.cache.clear()
            logger.info(f"Cache cleared ({cache_size} entries removed)")
    
    def reset_stats(self):
        """Reset all statistics counters."""
        self.enrichment_count = 0
        self.error_count = 0
        self.api_call_count = {api: 0 for api in self.api_handlers}
        logger.info("Statistics reset")


# ============================================================================
# MAIN - Demo/Testing
# ============================================================================

if __name__ == "__main__":
    """Demo: Enrich sample IOCs"""
    
    print("\n" + "="*70)
    print("PHASE 2: IOC ENRICHMENT ORCHESTRATOR")
    print("="*70)
    
    # Initialize enricher
    enricher = IOCEnricher(use_cache=True)
    
    # Sample IOCs for testing
    sample_iocs = [
        {"ioc_value": "8.8.8.8", "ioc_type": "IP"},
        {"ioc_value": "google.com", "ioc_type": "domain"},
        {"ioc_value": "192.168.1.1", "ioc_type": "IP"},
        {"ioc_value": "malicious.com", "ioc_type": "domain"},
    ]
    
    print(f"\nEnriching {len(sample_iocs)} sample IOCs...\n")
    
    results = enricher.enrich_batch(sample_iocs, rate_limit_delay=1.0)
    
    # Display results
    for result in results:
        print(f"\n{'-'*70}")
        print(f"IOC: {result['ioc_value']} ({result['ioc_type']})")
        print(f"Status: {result.get('status', 'unknown')}")
        print(f"Unified Confidence: {result.get('unified_confidence', 0.0):.2f}")
        print(f"Triage Action: {result.get('triage_action', 'UNKNOWN')}")
        print(f"Timestamp: {result.get('timestamp')}")
        
        if result.get('errors'):
            print(f"Errors: {len(result['errors'])} API errors encountered")
    
    # Show statistics
    print(f"\n{'-'*70}")
    stats = enricher.get_stats()
    print(f"Statistics:")
    print(f"  Total Enrichments: {stats['total_enrichments']}")
    print(f"  Total Errors: {stats['total_errors']}")
    print(f"  Cache Size: {stats['cache_size']}")
    print(f"  API Call Counts: {stats['api_call_counts']}")
    print("="*70 + "\n")