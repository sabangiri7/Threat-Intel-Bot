"""
Unit tests for PermanentCache (Phase 1).

Covers:
  - Persistence across restarts (save + reload)
  - Staleness detection with mocked timestamps
  - Purge of expired entries
  - Cache statistics accuracy
  - Eviction when max_size reached
  - Graceful recovery from corrupted cache file
  - Legacy cache migration
  - Backward-compatible module-level functions
"""

import json
import os
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from src.cache.cache import PermanentCache


# ── Helpers ──────────────────────────────────────────────────────────────────

def _tmp_cache(**kwargs) -> PermanentCache:
    """Create a PermanentCache backed by a temp file."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    os.unlink(path)
    return PermanentCache(cache_file=path, **kwargs)


def _make_entry(ioc: str, ioc_type: str = "ip", days_ago: float = 0.0) -> dict:
    """Build a minimal enrichment-data dict."""
    ts = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
    return {
        "ioc_value": ioc,
        "ioc_type": ioc_type,
        "unified_confidence": 0.5,
        "triage_action": "MONITOR",
        "api_results": {},
        "timestamp": ts,
    }


# ── Tests ────────────────────────────────────────────────────────────────────

class TestPermanentCachePersistence:
    """Cache survives save → new instance load cycle."""

    def test_save_and_reload(self):
        cache = _tmp_cache()
        cache.set("ip::1.1.1.1", _make_entry("1.1.1.1"))
        cache.set("domain::evil.com", _make_entry("evil.com", "domain"))
        cache.save()

        reloaded = PermanentCache(cache_file=cache._cache_file)
        assert len(reloaded) == 2
        assert reloaded.get("ip::1.1.1.1") is not None
        assert reloaded.get("domain::evil.com") is not None
        os.unlink(cache._cache_file)

    def test_reload_preserves_enrichment_data(self):
        cache = _tmp_cache()
        data = _make_entry("8.8.8.8")
        data["unified_confidence"] = 0.92
        cache.set("ip::8.8.8.8", data)
        cache.save()

        reloaded = PermanentCache(cache_file=cache._cache_file)
        result = reloaded.get("ip::8.8.8.8")
        assert result["unified_confidence"] == 0.92
        os.unlink(cache._cache_file)

    def test_empty_cache_file_does_not_exist(self):
        cache = _tmp_cache()
        assert len(cache) == 0
        assert cache.get("nonexistent") is None


class TestStalenessDetection:
    """Entries older than stale_threshold_days are flagged but still returned."""

    def test_fresh_entry_not_stale(self):
        cache = _tmp_cache(stale_threshold_days=7)
        cache.set("ip::1.1.1.1", _make_entry("1.1.1.1", days_ago=0))
        result = cache.get("ip::1.1.1.1")
        assert result is not None
        entry = cache._entries["ip::1.1.1.1"]
        assert entry["stale"] is False

    def test_old_entry_marked_stale(self):
        cache = _tmp_cache(stale_threshold_days=7)
        cache.set("ip::2.2.2.2", _make_entry("2.2.2.2"))
        # Backdate the cached_at timestamp
        cache._entries["ip::2.2.2.2"]["cached_at"] = (
            datetime.now(timezone.utc) - timedelta(days=10)
        ).isoformat()

        result = cache.get("ip::2.2.2.2")
        assert result is not None
        assert cache._entries["ip::2.2.2.2"]["stale"] is True

    def test_stale_entry_still_returned(self):
        cache = _tmp_cache(stale_threshold_days=3)
        data = _make_entry("3.3.3.3")
        cache.set("ip::3.3.3.3", data)
        cache._entries["ip::3.3.3.3"]["cached_at"] = (
            datetime.now(timezone.utc) - timedelta(days=5)
        ).isoformat()

        result = cache.get("ip::3.3.3.3")
        assert result is not None
        assert result["ioc_value"] == "3.3.3.3"


class TestPurgeExpired:
    """Entries older than purge_threshold_days are removed on purge()."""

    def test_purge_removes_old_entries(self):
        cache = _tmp_cache(purge_threshold_days=30)
        cache.set("ip::old", _make_entry("old"))
        cache._entries["ip::old"]["cached_at"] = (
            datetime.now(timezone.utc) - timedelta(days=35)
        ).isoformat()
        cache.set("ip::fresh", _make_entry("fresh"))

        removed = cache.purge_expired()
        assert removed == 1
        assert "ip::old" not in cache
        assert "ip::fresh" in cache

    def test_purge_keeps_entries_within_threshold(self):
        cache = _tmp_cache(purge_threshold_days=30)
        cache.set("ip::recent", _make_entry("recent", days_ago=5))
        removed = cache.purge_expired()
        assert removed == 0
        assert len(cache) == 1


class TestCacheStatistics:
    """stats() returns accurate counts."""

    def test_stats_after_hits_and_misses(self):
        cache = _tmp_cache()
        cache.set("ip::a", _make_entry("a"))

        cache.get("ip::a")       # hit
        cache.get("ip::a")       # hit
        cache.get("ip::missing") # miss

        s = cache.stats()
        assert s["hits"] == 2
        assert s["misses"] == 1
        assert s["hit_rate"] == pytest.approx(66.7, abs=0.1)
        assert s["total_entries"] == 1

    def test_stats_age_distribution(self):
        cache = _tmp_cache(stale_threshold_days=7, purge_threshold_days=30)
        cache.set("ip::fresh", _make_entry("fresh", days_ago=1))
        cache.set("ip::stale", _make_entry("stale"))
        cache._entries["ip::stale"]["cached_at"] = (
            datetime.now(timezone.utc) - timedelta(days=15)
        ).isoformat()
        cache.set("ip::expired", _make_entry("expired"))
        cache._entries["ip::expired"]["cached_at"] = (
            datetime.now(timezone.utc) - timedelta(days=40)
        ).isoformat()

        s = cache.stats()
        assert s["fresh_entries"] == 1
        assert s["stale_entries"] == 1
        assert s["expired_entries"] == 1


class TestEviction:
    """When max_size is reached, the oldest entry is evicted."""

    def test_evicts_oldest_when_full(self):
        cache = _tmp_cache(max_size=2)
        cache.set("ip::first", _make_entry("first"))
        cache._entries["ip::first"]["cached_at"] = (
            datetime.now(timezone.utc) - timedelta(days=10)
        ).isoformat()
        cache.set("ip::second", _make_entry("second"))

        # This should evict "first" (oldest)
        cache.set("ip::third", _make_entry("third"))
        assert len(cache) == 2
        assert "ip::first" not in cache
        assert "ip::third" in cache


class TestCorruptedCacheRecovery:
    """Gracefully handle a corrupted cache file."""

    def test_corrupted_json_starts_fresh(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(path, "w") as f:
            f.write("{invalid json!!")

        cache = PermanentCache(cache_file=path)
        assert len(cache) == 0
        cache.set("ip::ok", _make_entry("ok"))
        assert len(cache) == 1
        os.unlink(path)


class TestLegacyMigration:
    """Old flat cache format is migrated to new entry format on load."""

    def test_migrates_old_format(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        old_data = {
            "cache": {
                "ip::8.8.8.8": {
                    "ioc_value": "8.8.8.8",
                    "ioc_type": "ip",
                    "unified_confidence": 0.1,
                    "triage_action": "IGNORE",
                    "api_results": {},
                    "timestamp": "2026-02-01T12:00:00+00:00",
                }
            }
        }
        with open(path, "w") as f:
            json.dump(old_data, f)

        cache = PermanentCache(cache_file=path)
        assert len(cache) == 1
        result = cache.get("ip::8.8.8.8")
        assert result is not None
        assert result["ioc_value"] == "8.8.8.8"
        os.unlink(path)


class TestModuleLevelFunctions:
    """Backward-compatible module-level functions delegate to PermanentCache."""

    def test_cache_get_set_roundtrip(self):
        from src.cache.cache import init_cache, cache_get, cache_set, save_cache, clear_cache

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(path)
        init_cache(cache_file=path)

        cache_set("ip::test", _make_entry("test"))
        result = cache_get("ip::test")
        assert result is not None
        assert result["ioc_value"] == "test"

        save_cache()
        assert os.path.exists(path)

        clear_cache()
        assert cache_get("ip::test") is None
        os.unlink(path)

    def test_get_cache_stats_format(self):
        from src.cache.cache import init_cache, get_cache_stats

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(path)
        init_cache(cache_file=path)

        s = get_cache_stats()
        for field in ("hits", "misses", "hit_rate", "current_size", "max_size"):
            assert field in s, f"Missing field: {field}"
