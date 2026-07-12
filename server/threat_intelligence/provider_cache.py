import time
from typing import Dict, Any, Optional
from collections import OrderedDict
from models.threat_intelligence_model import ThreatObservable, ProviderResult
from utils.metrics import metrics_collector
from utils.structured_logger import structured_logger

class ProviderCache:
    def __init__(self, max_size: int = 1000):
        # Using OrderedDict to implement LRU
        self._cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self._max_size = max_size
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._expired_entries = 0
        
    def _make_key(self, provider_name: str, observable: ThreatObservable) -> str:
        return f"{provider_name}:{observable.type}:{observable.value}"
        
    async def lookup(self, provider_name: str, observable: ThreatObservable) -> Optional[ProviderResult]:
        """Checks the cache for a non-expired entry for the given provider and observable."""
        key = self._make_key(provider_name, observable)
        entry = self._cache.get(key)
        
        if not entry:
            self._misses += 1
            metrics_collector.record_cache_miss(provider_name)
            structured_logger.debug("Cache miss", provider_name, {"key": key})
            return None
            
        # Check expiration
        now = time.time()
        if now > entry["expires_at"]:
            # Evict expired entry
            del self._cache[key]
            self._expired_entries += 1
            self._misses += 1
            metrics_collector.record_cache_miss(provider_name)
            metrics_collector.record_cache_expiry(provider_name)
            structured_logger.debug("Cache entry expired", provider_name, {"key": key})
            return None
            
        # Update LRU order: move to end
        self._cache.move_to_end(key)
        
        self._hits += 1
        metrics_collector.record_cache_hit(provider_name)
        structured_logger.debug("Cache hit", provider_name, {"key": key})
        
        # Settle cached result with cache_hit = True
        cached_res = entry["result"]
        # Update cache_hit field (we re-create because it is frozen)
        result_copy = ProviderResult(
            provider_name=cached_res.provider_name,
            provider_status=cached_res.provider_status,
            evidence=cached_res.evidence,
            lookup_time_ms=0.0,  # Cached served instantly
            cache_hit=True,
            timestamp=cached_res.timestamp,
            error_message=cached_res.error_message
        )
        return result_copy
        
    async def insert(self, provider_name: str, observable: ThreatObservable, result: ProviderResult, ttl_sec: float) -> None:
        """Inserts a ProviderResult into the cache with a specified TTL and enforces LRU limit."""
        key = self._make_key(provider_name, observable)
        expires_at = time.time() + ttl_sec
        
        # Insert or update entry
        if key in self._cache:
            del self._cache[key]
        self._cache[key] = {
            "result": result,
            "expires_at": expires_at
        }
        
        # Enforce maximum cache size (LRU eviction)
        if len(self._cache) > self._max_size:
            # Pop first item (oldest/least recently used)
            oldest_key, oldest_val = self._cache.popitem(last=False)
            self._evictions += 1
            # Extract provider name from key prefix
            prov = oldest_key.split(":")[0]
            metrics_collector.record_cache_eviction(prov)
            structured_logger.debug("Cache LRU eviction executed", prov, {"key": oldest_key})
            
    def _estimate_memory(self) -> int:
        # Simple string-length based heuristic of keys + string representation of values in bytes
        mem_bytes = 0
        for k, v in self._cache.items():
            mem_bytes += len(k)
            # Estimate size of result Pydantic structure
            res = v["result"]
            mem_bytes += len(res.provider_name) + len(res.provider_status)
            for ev in res.evidence:
                mem_bytes += len(ev.observable) + len(ev.observable_type) + len(ev.classification) + len(ev.severity)
            mem_bytes += 32 # Overhead estimation
        return mem_bytes

    def get_statistics(self) -> Dict[str, Any]:
        """Returns cache stats (hits, misses, size, evictions, expired, memory)."""
        now = time.time()
        # Non-blocking cleanup of expired entries during stats calculation
        expired_keys = [
            k for k, v in self._cache.items()
            if now > v["expires_at"]
        ]
        for k in expired_keys:
            del self._cache[k]
            self._expired_entries += 1
            # Extract provider name
            prov = k.split(":")[0]
            metrics_collector.record_cache_expiry(prov)
            
        return {
            "hits": self._hits,
            "misses": self._misses,
            "size": len(self._cache),
            "evictions": self._evictions,
            "expired_entries": self._expired_entries,
            "memory_usage_estimate_bytes": self._estimate_memory()
        }
        
    def clear(self) -> None:
        """Clears all cached entries."""
        self._cache.clear()
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._expired_entries = 0
