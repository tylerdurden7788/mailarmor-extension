import asyncio
import time
import logging
from typing import List, Dict, Any
from models.threat_intelligence_model import ThreatObservable, ThreatEvidence, ProviderResult
from threat_intelligence.provider_registry import ProviderRegistry
from threat_intelligence.provider_cache import ProviderCache
from threat_intelligence.provider_health import ProviderHealthMonitor
from threat_intelligence.ioc_normalizer import IOCNormalizer

logger = logging.getLogger("ProviderManager")

class ProviderManager:
    def __init__(self, registry: ProviderRegistry, cache: ProviderCache, health_monitor: ProviderHealthMonitor):
        self.registry = registry
        self.cache = cache
        self.health_monitor = health_monitor

    async def lookup_observables(self, observables: List[ThreatObservable]) -> List[ProviderResult]:
        """
        Deduplicates, normalizes, and queries all enabled providers for a list of observables.
        Returns a list of ProviderResult objects.
        """
        # 1. Normalize and deduplicate observables
        unique_observables: Dict[tuple, ThreatObservable] = {}
        for obs in observables:
            norm_val = IOCNormalizer.normalize(obs.value, obs.type)
            key = (obs.type, norm_val)
            if key not in unique_observables:
                unique_observables[key] = ThreatObservable(value=norm_val, type=obs.type)
                
        results: List[ProviderResult] = []
        tasks = []
        
        # 2. Query enabled providers for each observable
        for obs in unique_observables.values():
            enabled_names = self.registry.get_enabled_providers()
            for name in enabled_names:
                provider = self.registry.get_provider(name)
                meta = self.registry.get_metadata(name)
                
                if not provider or not meta:
                    continue
                    
                # Skip if provider does not support this observable type
                if not provider.is_supported(obs.type):
                    continue
                    
                # Check health status (circuit-breaker)
                if self.health_monitor.get_health_status(name) == "Unhealthy":
                    logger.warning(f"Skipping unhealthy threat provider: {name}")
                    results.append(ProviderResult(
                        provider_name=name,
                        provider_status="UNAVAILABLE",
                        evidence=[],
                        lookup_time_ms=0.0,
                        cache_hit=False,
                        error_message="Skipped due to unhealthy circuit-breaker status"
                    ))
                    continue
                    
                # Dispatch query task
                tasks.append(self._process_single_lookup(name, provider, meta, obs))
                
        if tasks:
            lookup_results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in lookup_results:
                if isinstance(res, ProviderResult):
                    results.append(res)
                elif isinstance(res, Exception):
                    logger.error(f"Unexpected exception during lookup task: {res}")
                    
        return results

    async def _process_single_lookup(self, name: str, provider: Any, meta: Dict[str, Any], obs: ThreatObservable) -> ProviderResult:
        start_time = time.perf_counter()
        
        # 1. Cache lookup
        cached = await self.cache.lookup(name, obs)
        if cached is not None:
            return cached
            
        timeout = meta.get("timeout", 2.0)
        retries = meta.get("retry_count", 2)
        ttl = meta.get("cache_ttl", 300)
        
        # 2. Execution with retries and timeout (already handled inside provider, but manager acts as a guard)
        result: ProviderResult
        try:
            # Call provider's lookup, protecting with wait_for in case provider has no internal timeout
            result = await asyncio.wait_for(provider.lookup(obs), timeout=timeout)
        except asyncio.TimeoutError:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            self.health_monitor.record_failure(name)
            result = ProviderResult(
                provider_name=name,
                provider_status="UNAVAILABLE",
                evidence=[],
                lookup_time_ms=latency_ms,
                cache_hit=False,
                error_message="Request timed out at Manager guard"
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            self.health_monitor.record_failure(name)
            result = ProviderResult(
                provider_name=name,
                provider_status="ERROR",
                evidence=[],
                lookup_time_ms=latency_ms,
                cache_hit=False,
                error_message=str(e)
            )

        latency_ms = (time.perf_counter() - start_time) * 1000.0
        
        # 3. Track in health monitor based on status
        if result.provider_status in ["SUCCESS", "NO_DATA"]:
            self.health_monitor.record_success(name, latency_ms)
            # Insert in cache
            await self.cache.insert(name, obs, result, ttl)
        else:
            self.health_monitor.record_failure(name)
            
        return result
