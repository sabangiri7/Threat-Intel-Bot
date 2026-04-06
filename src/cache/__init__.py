"""Cache module for enrichment engine — persistent, age-aware IOC cache."""

from .cache import (
    PermanentCache,
    get_cache,
    get_cache_stats,
    cache_get,
    cache_set,
    save_cache,
    clear_cache,
    init_cache,
)

__all__ = [
    'PermanentCache',
    'get_cache',
    'get_cache_stats',
    'cache_get',
    'cache_set',
    'save_cache',
    'clear_cache',
    'init_cache',
]
