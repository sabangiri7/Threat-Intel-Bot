"""Cache management for enriched IOCs"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path

# Cache file location
CACHE_FILE = "data/enrichment_cache.json"

# In-memory cache dictionary
_memory_cache = {}

# Cache statistics
_cache_stats = {
    "hits": 0,
    "misses": 0,
    "current_size": 0,
    "max_size": 10000
}

# Cache TTL (Time To Live) in days
CACHE_TTL_DAYS = 7


def init_cache():
    """Initialize cache from disk if it exists"""
    global _memory_cache
    
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                data = json.load(f)
                _memory_cache = data.get("cache", {})
                _cache_stats["current_size"] = len(_memory_cache)
        except (json.JSONDecodeError, IOError):
            _memory_cache = {}
            _cache_stats["current_size"] = 0
    else:
        _memory_cache = {}
        _cache_stats["current_size"] = 0


def get_cache():
    """Get the in-memory cache dictionary"""
    return _memory_cache


def get_cache_stats():
    """Get cache statistics"""
    return {
        "hits": _cache_stats["hits"],
        "misses": _cache_stats["misses"],
        "hit_rate": (_cache_stats["hits"] / max(1, _cache_stats["hits"] + _cache_stats["misses"])) * 100,
        "current_size": _cache_stats["current_size"],
        "max_size": _cache_stats["max_size"]
    }


def cache_get(key):
    """Get value from cache (with hit/miss tracking)"""
    if key in _memory_cache:
        entry = _memory_cache[key]
        
        # Check if entry has expired
        if "timestamp" in entry:
            try:
                created = datetime.fromisoformat(entry["timestamp"])
                if datetime.now() - created > timedelta(days=CACHE_TTL_DAYS):
                    del _memory_cache[key]
                    _cache_stats["misses"] += 1
                    _cache_stats["current_size"] = len(_memory_cache)
                    return None
            except (ValueError, TypeError):
                pass
        
        _cache_stats["hits"] += 1
        return entry
    
    _cache_stats["misses"] += 1
    return None


def cache_set(key, value):
    """Set value in cache"""
    if _cache_stats["current_size"] < _cache_stats["max_size"]:
        _memory_cache[key] = value
        _cache_stats["current_size"] = len(_memory_cache)
        
        # Periodically save to disk
        total_ops = _cache_stats["hits"] + _cache_stats["misses"]
        if total_ops > 0 and total_ops % max(1, _cache_stats["max_size"] // 10) == 0:
            save_cache()


def save_cache():
    """Save cache to disk"""
    try:
        Path("data").mkdir(exist_ok=True)
        with open(CACHE_FILE, 'w') as f:
            json.dump({"cache": _memory_cache}, f, indent=2)
    except IOError as e:
        print(f"Warning: Could not save cache to {CACHE_FILE}: {e}")


def clear_cache():
    """Clear all cache"""
    global _memory_cache
    _memory_cache = {}
    _cache_stats["hits"] = 0
    _cache_stats["misses"] = 0
    _cache_stats["current_size"] = 0


# Initialize cache on import
init_cache()
