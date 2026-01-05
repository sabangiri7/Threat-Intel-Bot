"""Cache module for enrichment engine"""

from .cache import (
    get_cache,
    get_cache_stats,
    cache_get,
    cache_set,
    save_cache,
    clear_cache,
    init_cache
)

__all__ = [
    'get_cache',
    'get_cache_stats',
    'cache_get',
    'cache_set',
    'save_cache',
    'clear_cache',
    'init_cache'
]
