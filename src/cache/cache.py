"""
Permanent Cache for enriched IOCs.

Replaces the old in-memory-only cache with a persistent, age-aware
JSON-backed store.  Entries survive process restarts and carry metadata
(cached_at, stale flag) so downstream consumers know how fresh the data is.

Staleness policy (configurable):
  - < STALE_THRESHOLD_DAYS   -> fresh  (stale=False)
  - STALE_THRESHOLD_DAYS..PURGE_THRESHOLD_DAYS -> stale (stale=True, still returned)
  - > PURGE_THRESHOLD_DAYS   -> eligible for manual purge (still kept until purge())
"""

import json
import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Defaults (overridable via constructor)
_DEFAULT_CACHE_FILE = "data/enrichment_cache.json"
_DEFAULT_MAX_SIZE = 10_000
_DEFAULT_STALE_DAYS = 7
_DEFAULT_PURGE_DAYS = 30


class PermanentCache:
    """
    Persistent JSON-backed IOC cache with age metadata and staleness tracking.
    """

    def __init__(
        self,
        cache_file: str = _DEFAULT_CACHE_FILE,
        max_size: int = _DEFAULT_MAX_SIZE,
        stale_threshold_days: int = _DEFAULT_STALE_DAYS,
        purge_threshold_days: int = _DEFAULT_PURGE_DAYS,
    ):
        self._cache_file = cache_file
        self._max_size = max_size
        self._stale_days = stale_threshold_days
        self._purge_days = purge_threshold_days

        self._entries: Dict[str, Dict[str, Any]] = {}

        self._hits = 0
        self._misses = 0
        self._stale_hits = 0

        self.load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def load(self) -> int:
        """Load cache from disk. Returns number of entries loaded."""
        if not os.path.exists(self._cache_file):
            self._entries = {}
            return 0

        try:
            with open(self._cache_file, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except (json.JSONDecodeError, IOError) as exc:
            logger.warning("Cache file corrupt or unreadable (%s); starting fresh.", exc)
            self._entries = {}
            return 0

        if isinstance(raw, dict) and "cache" in raw:
            old_flat = raw["cache"]
            self._entries = self._migrate_legacy(old_flat)
        elif isinstance(raw, dict) and "entries" in raw:
            self._entries = raw["entries"]
        else:
            self._entries = {}

        logger.info("Loaded %d cache entries from %s", len(self._entries), self._cache_file)
        return len(self._entries)

    @staticmethod
    def _migrate_legacy(old_cache: dict) -> dict:
        """Convert old flat cache (key -> enrichment_data) to new entry format."""
        migrated: Dict[str, dict] = {}
        for key, value in old_cache.items():
            cached_at = value.get("timestamp", datetime.now(timezone.utc).isoformat())
            migrated[key] = {
                "enrichment_data": value,
                "cached_at": cached_at,
                "stale": False,
            }
        return migrated

    def save(self) -> None:
        """Persist cache to disk."""
        try:
            Path(self._cache_file).parent.mkdir(parents=True, exist_ok=True)
            with open(self._cache_file, "w", encoding="utf-8") as fh:
                json.dump({"entries": self._entries}, fh, indent=2, default=str)
        except IOError as exc:
            logger.error("Could not save cache to %s: %s", self._cache_file, exc)

    # ------------------------------------------------------------------
    # Core get / set
    # ------------------------------------------------------------------

    def get(self, key: str) -> Optional[Dict]:
        """
        Retrieve an entry.  Returns the enrichment_data dict or None.
        Tracks hits/misses and updates the stale flag in-place.
        """
        entry = self._entries.get(key)
        if entry is None:
            self._misses += 1
            return None

        age = self._entry_age_days(entry)
        entry["stale"] = age >= self._stale_days

        if entry["stale"]:
            self._stale_hits += 1
            logger.debug("Stale cache entry for %s (%.1f days old)", key, age)

        self._hits += 1
        return entry["enrichment_data"]

    def set(self, key: str, enrichment_data: Dict) -> None:
        """Store or update an entry with current timestamp."""
        if len(self._entries) >= self._max_size and key not in self._entries:
            self._evict_oldest()

        self._entries[key] = {
            "enrichment_data": enrichment_data,
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "stale": False,
        }

    def invalidate(self, key: str) -> bool:
        """Remove a single entry. Returns True if it existed."""
        return self._entries.pop(key, None) is not None

    # ------------------------------------------------------------------
    # Bulk operations
    # ------------------------------------------------------------------

    def purge_expired(self) -> int:
        """Remove entries older than purge_threshold_days. Returns count removed."""
        now = datetime.now(timezone.utc)
        to_remove = [
            k for k, v in self._entries.items()
            if self._entry_age_days(v, now) > self._purge_days
        ]
        for k in to_remove:
            del self._entries[k]
        if to_remove:
            logger.info("Purged %d expired entries (>%d days)", len(to_remove), self._purge_days)
        return len(to_remove)

    def clear(self) -> None:
        """Remove all entries and reset stats."""
        self._entries.clear()
        self._hits = 0
        self._misses = 0
        self._stale_hits = 0

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        """Return cache performance and health statistics."""
        total_ops = self._hits + self._misses
        now = datetime.now(timezone.utc)

        fresh = stale = expired = 0
        for entry in self._entries.values():
            age = self._entry_age_days(entry, now)
            if age > self._purge_days:
                expired += 1
            elif age >= self._stale_days:
                stale += 1
            else:
                fresh += 1

        file_size = 0
        if os.path.exists(self._cache_file):
            file_size = os.path.getsize(self._cache_file)

        return {
            "total_entries": len(self._entries),
            "max_size": self._max_size,
            "hits": self._hits,
            "misses": self._misses,
            "stale_hits": self._stale_hits,
            "hit_rate": round((self._hits / max(1, total_ops)) * 100, 1),
            "fresh_entries": fresh,
            "stale_entries": stale,
            "expired_entries": expired,
            "cache_file": self._cache_file,
            "cache_file_size_kb": round(file_size / 1024, 1),
            "stale_threshold_days": self._stale_days,
            "purge_threshold_days": self._purge_days,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _entry_age_days(self, entry: dict, now: Optional[datetime] = None) -> float:
        """Return age of an entry in fractional days."""
        now = now or datetime.now(timezone.utc)
        try:
            cached_at = datetime.fromisoformat(entry["cached_at"])
            if cached_at.tzinfo is None:
                cached_at = cached_at.replace(tzinfo=timezone.utc)
            return (now - cached_at).total_seconds() / 86400
        except (KeyError, ValueError, TypeError):
            return 0.0

    def _evict_oldest(self) -> None:
        """Remove the oldest entry to make room."""
        if not self._entries:
            return
        oldest_key = min(self._entries, key=lambda k: self._entries[k].get("cached_at", ""))
        del self._entries[oldest_key]
        logger.debug("Evicted oldest entry: %s", oldest_key)

    def keys(self) -> List[str]:
        return list(self._entries.keys())

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, key: str) -> bool:
        return key in self._entries


# ======================================================================
# Module-level singleton + backward-compatible functions
# ======================================================================

_instance: Optional[PermanentCache] = None


def _get_instance() -> PermanentCache:
    global _instance
    if _instance is None:
        _instance = PermanentCache()
    return _instance


def init_cache(cache_file: str = _DEFAULT_CACHE_FILE) -> None:
    """(Re-)initialize the module-level cache singleton."""
    global _instance
    _instance = PermanentCache(cache_file=cache_file)


def get_cache() -> dict:
    """Backward-compat: return a dict-like view of enrichment data."""
    inst = _get_instance()
    return {k: v["enrichment_data"] for k, v in inst._entries.items()}


def get_cache_stats() -> Dict:
    """Backward-compat: return stats in the old format expected by enrichment."""
    s = _get_instance().stats()
    return {
        "hits": s["hits"],
        "misses": s["misses"],
        "hit_rate": s["hit_rate"],
        "current_size": s["total_entries"],
        "max_size": s["max_size"],
    }


def cache_get(key: str) -> Optional[Dict]:
    """Retrieve enrichment data for *key* (tracks hits/misses)."""
    return _get_instance().get(key)


def cache_set(key: str, value: Dict) -> None:
    """Store enrichment data under *key*."""
    _get_instance().set(key, value)


def save_cache() -> None:
    """Flush current cache to disk."""
    _get_instance().save()


def clear_cache() -> None:
    """Wipe all entries and reset stats."""
    _get_instance().clear()


# Auto-initialize on import (loads existing cache file)
init_cache()
