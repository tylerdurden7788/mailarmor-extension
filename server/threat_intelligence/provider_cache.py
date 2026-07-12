import time
from typing import Dict, Any, Optional
from models.threat_intelligence_model import ThreatObservable, ProviderResult

class ProviderCache:
    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        
    def _make_key(self, provider_name: str, observable: ThreatObservable) -> str:
        return f"{provider_name}:{observable.type}:{observable.value}"
        
    async def lookup(self, provider_name: str, observable: ThreatObservable) -> Optional[ProviderResult]:
        """Checks the cache for a non-expired entry for the given provider and observable."""
        key = self._make_key(provider_name, observable)
        entry = self._cache.get(key)
        
        if not entry:
            self._misses += 1
            return None
            
        # Check expiration
        now = time.time()
        if now > entry["expires_at"]:
            # Evict expired entry
            del self._cache[key]
            self._evictions += 1
            self._misses += 1
            return None
            
        self._hits += 1
        
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
        """Inserts a ProviderResult into the cache with a specified TTL."""
        key = self._make_key(provider_name, observable)
        expires_at = time.time() + ttl_sec
        self._cache[key] = {
            "result": result,
            "expires_at": expires_at
        }
        
    def get_statistics(self) -> Dict[str, int]:
        """Returns cache stats (hits, misses, size, evictions)."""
        now = time.time()
        expired_keys = [
            k for k, v in self._cache.items()
            if now > v["expires_at"]
        ]
        for k in expired_keys:
            del self._cache[k]
            self._evictions += 1
            
        return {
            "hits": self._hits,
            "misses": self._misses,
            "size": len(self._cache),
            "evictions": self._evictions
        }
        
    def clear(self) -> None:
        """Clears all cached entries."""
        self._cache.clear()
        self._hits = 0
        self._misses = 0
        self._evictions = 0
