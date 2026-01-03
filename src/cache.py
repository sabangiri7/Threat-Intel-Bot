"""
Cache Management Module
Handles caching of IOC enrichment results with TTL and persistence
"""

import json
import logging
from pathlib import Path
from threading import Lock
from typing import Dict, Any, Optional
from datetime import datetime, timezone


logger = logging.getLogger(__name__)


class CacheManager:
    """
    Manages caching of IOC enrichment results with TTL and persistence.
    Only stores results when explicitly requested via enrichment pipeline.
    
    Configuration:
    - max_size: Maximum number of entries (default: 1000)
    - ttl_seconds: Time-to-live for cache entries (default: 3600 = 1 hour)
    - persist_enabled: Enable persistent storage to disk (default: True)
    """
    
    DEFAULT_MAX_SIZE = 1000
    DEFAULT_TTL_SECONDS = 3600  # 1 hour
    DEFAULT_CACHE_DIR = Path(__file__).parent / 'cache'
    
    def __init__(
        self,
        max_size: int = DEFAULT_MAX_SIZE,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        persist_enabled: bool = True,
        persist_path: Optional[Path] = None
    ):
        """
        Initialize cache manager.
        
        Args:
            max_size: Maximum cache entries before LRU eviction
            ttl_seconds: Entry lifetime in seconds
            persist_enabled: Enable disk persistence
            persist_path: Custom path for cache file
        """
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.persist_enabled = persist_enabled
        
        if persist_path is None:
            self.persist_path = self.DEFAULT_CACHE_DIR / 'enrichment_cache.json'
        else:
            self.persist_path = Path(persist_path)
        
        if self.persist_enabled:
            self.persist_path.parent.mkdir(parents=True, exist_ok=True)
        
        # In-memory cache: {key: (value, timestamp, access_count)}
        self.cache: Dict[str, tuple] = {}
        self.lock = Lock()
        
        # Statistics
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'expirations': 0,
            'additions': 0
        }
        
        logger.info(f"CacheManager initialized: max_size={max_size}, ttl={ttl_seconds}s")
        
        if self.persist_enabled:
            self._load_from_disk()
    
    def get(self, key: str) -> Optional[Dict]:
        """
        Retrieve cached enrichment result.
        
        Args:
            key: Cache key format "ioc_value_ioc_type" e.g., "8.8.8.8_IP"
            
        Returns:
            Cached enrichment result or None if expired/missing
        """
        with self.lock:
            if key not in self.cache:
                self.stats['misses'] += 1
                return None
            
            value, timestamp, access_count = self.cache[key]
            
            if self._is_expired(timestamp):
                del self.cache[key]
                self.stats['expirations'] += 1
                self.stats['misses'] += 1
                logger.debug(f"Cache entry expired: {key}")
                return None
            
            # Update access count (for LRU tracking)
            self.cache[key] = (value, timestamp, access_count + 1)
            self.stats['hits'] += 1
            logger.debug(f"Cache hit: {key}")
            
            return value
    
    def set(self, key: str, value: Dict) -> None:
        """
        Store enrichment result in cache.
        
        Args:
            key: Cache key format "ioc_value_ioc_type"
            value: Enrichment result dict
        """
        with self.lock:
            if len(self.cache) >= self.max_size and key not in self.cache:
                self._evict_lru()
            
            current_time = datetime.now(timezone.utc).timestamp()
            self.cache[key] = (value, current_time, 0)
            self.stats['additions'] += 1
            logger.debug(f"Cache set: {key} (size: {len(self.cache)}/{self.max_size})")
    
    def cleanup_expired(self) -> int:
        """
        Remove all expired entries from cache.
        
        Returns:
            Number of entries removed
        """
        with self.lock:
            expired_keys = [
                key for key, (_, timestamp, _) in self.cache.items()
                if self._is_expired(timestamp)
            ]
            
            for key in expired_keys:
                del self.cache[key]
                self.stats['expirations'] += 1
            
            if expired_keys:
                logger.info(f"Cleaned {len(expired_keys)} expired entries")
            
            return len(expired_keys)
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dict with hits, misses, hit_rate, size, evictions, etc.
        """
        with self.lock:
            total = self.stats['hits'] + self.stats['misses']
            hit_rate = (self.stats['hits'] / total * 100) if total > 0 else 0.0
            
            return {
                'current_size': len(self.cache),
                'max_size': self.max_size,
                'hits': self.stats['hits'],
                'misses': self.stats['misses'],
                'hit_rate': round(hit_rate, 2),
                'evictions': self.stats['evictions'],
                'expirations': self.stats['expirations'],
                'additions': self.stats['additions'],
                'total_requests': total,
                'ttl_seconds': self.ttl_seconds
            }
    
    def save_to_disk(self) -> bool:
        """
        Persist cache to disk as JSON.
        
        Returns:
            True if successful, False otherwise
        """
        if not self.persist_enabled:
            return False
        
        try:
            with self.lock:
                cache_data = {}
                for key, (value, timestamp, access_count) in self.cache.items():
                    cache_data[key] = {
                        'value': value,
                        'timestamp': timestamp,
                        'access_count': access_count
                    }
                
                with open(self.persist_path, 'w') as f:
                    json.dump(cache_data, f, indent=2)
                
                logger.info(f"Cache saved: {len(cache_data)} entries")
                return True
        
        except Exception as e:
            logger.error(f"Error saving cache: {str(e)}")
            return False
    
    def _load_from_disk(self) -> None:
        """Load cache from disk if file exists."""
        if not self.persist_path.exists():
            return
        
        try:
            with open(self.persist_path, 'r') as f:
                cache_data = json.load(f)
            
            with self.lock:
                for key, data in cache_data.items():
                    value = data['value']
                    timestamp = data['timestamp']
                    access_count = data.get('access_count', 0)
                    
                    if not self._is_expired(timestamp):
                        self.cache[key] = (value, timestamp, access_count)
            
            logger.info(f"Cache loaded: {len(self.cache)} valid entries")
        
        except Exception as e:
            logger.error(f"Error loading cache: {str(e)}")
    
    def _is_expired(self, timestamp: float) -> bool:
        """Check if cache entry is expired."""
        current_time = datetime.now(timezone.utc).timestamp()
        return (current_time - timestamp) > self.ttl_seconds
    
    def _evict_lru(self) -> None:
        """Evict least recently used entry."""
        if not self.cache:
            return
        
        lru_key = min(self.cache.items(), key=lambda x: x[1][2])[0]
        del self.cache[lru_key]
        self.stats['evictions'] += 1
        logger.debug(f"LRU eviction: {lru_key}")


# Singleton instance
_cache_instance: Optional[CacheManager] = None
_cache_lock = Lock()


def get_cache(
    max_size: int = CacheManager.DEFAULT_MAX_SIZE,
    ttl_seconds: int = CacheManager.DEFAULT_TTL_SECONDS,
    persist_enabled: bool = True
) -> CacheManager:
    """Get or create the global cache manager instance (singleton)."""
    global _cache_instance
    
    if _cache_instance is None:
        with _cache_lock:
            if _cache_instance is None:
                _cache_instance = CacheManager(
                    max_size=max_size,
                    ttl_seconds=ttl_seconds,
                    persist_enabled=persist_enabled
                )
    
    return _cache_instance