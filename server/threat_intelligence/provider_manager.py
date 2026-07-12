import asyncio
import time
from typing import List, Dict, Any
from models.threat_intelligence_model import ThreatObservable, ThreatEvidence, ProviderResult
from threat_intelligence.provider_registry import ProviderRegistry
from threat_intelligence.provider_cache import ProviderCache
from threat_intelligence.provider_health import ProviderHealthMonitor
from threat_intelligence.ioc_normalizer import IOCNormalizer
from utils.structured_logger import structured_logger
from utils.metrics import metrics_collector

class ProviderManager:
    def __init__(self, registry: ProviderRegistry, cache: ProviderCache, health_monitor: ProviderHealthMonitor):
        self.registry = registry
        self.cache = cache
        self.health_monitor = health_monitor
        # Bounded worker pool: limit concurrent provider lookups globally to protect system resources
        self._semaphore = asyncio.Semaphore(20)

    async def lookup_observables(self, observables: List[ThreatObservable]) -> List[ProviderResult]:
        """
        Deduplicates, normalizes, and queries all enabled providers for a list of observables.
        Returns a list of ProviderResult objects.
        """
        # Resource Protection: Maximum 50 unique IOC lookups per email to prevent resource exhaustion
        if len(observables) > 50:
            structured_logger.warning("Email exceeded maximum IOC lookup limit. Truncating list.", None, {"original_count": len(observables)})
            observables = observables[:50]

        # 1. Normalize and deduplicate observables
        unique_observables: Dict[tuple, ThreatObservable] = {}
        for obs in observables:
            if not obs.value or not obs.type:
                continue
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
                health_state = self.health_monitor.get_health_status(name)
                if health_state == "UNAVAILABLE":
                    structured_logger.warning("Skipping unavailable threat provider", name, {"observable": obs.value})
                    results.append(ProviderResult(
                        provider_name=name,
                        provider_status="UNAVAILABLE",
                        evidence=[],
                        lookup_time_ms=0.0,
                        cache_hit=False,
                        error_message="Skipped due to tripped circuit-breaker status"
                    ))
                    metrics_collector.record_request(name)
                    metrics_collector.record_failure(name)
                    continue
                    
                # Dispatch query task
                tasks.append(self._process_single_lookup(name, provider, meta, obs))
                
        if tasks:
            lookup_results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in lookup_results:
                if isinstance(res, ProviderResult):
                    results.append(res)
                elif isinstance(res, Exception):
                    structured_logger.error(f"Unexpected exception during lookup task: {res}")
                    
        return results

    async def _process_single_lookup(self, name: str, provider: Any, meta: Dict[str, Any], obs: ThreatObservable) -> ProviderResult:
        start_time = time.perf_counter()
        
        # Update metrics: increment request count
        metrics_collector.record_request(name)
        
        # 1. Cache lookup
        cached = await self.cache.lookup(name, obs)
        if cached is not None:
            return cached
            
        timeout = meta.get("timeout", 2.0)
        ttl = meta.get("cache_ttl", 300)
        
        # 2. Execution under worker pool semaphore limits
        async with self._semaphore:
            structured_logger.info("Provider execution started", name, {"observable": obs.value})
            
            result: ProviderResult
            try:
                # Call provider's lookup, protecting with wait_for
                result = await asyncio.wait_for(provider.lookup(obs), timeout=timeout)
            except asyncio.TimeoutError:
                latency_ms = (time.perf_counter() - start_time) * 1000.0
                structured_logger.warning("Provider lookup timed out", name, {"observable": obs.value, "timeout": timeout})
                metrics_collector.record_timeout(name)
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
                structured_logger.error(f"Provider lookup exception: {e}", name, {"observable": obs.value})
                metrics_collector.record_failure(name)
                result = ProviderResult(
                    provider_name=name,
                    provider_status="ERROR",
                    evidence=[],
                    lookup_time_ms=latency_ms,
                    cache_hit=False,
                    error_message=str(e)
                )

        latency_ms = (time.perf_counter() - start_time) * 1000.0
        
        # 3. Track in health monitor based on status and write to cache if successful
        if result.provider_status in ["SUCCESS", "NO_DATA"]:
            self.health_monitor.record_success(name, latency_ms)
            metrics_collector.record_success(name, latency_ms)
            # Insert in cache
            await self.cache.insert(name, obs, result, ttl)
            structured_logger.info("Provider execution finished", name, {"status": result.provider_status, "latency_ms": latency_ms})
        else:
            self.health_monitor.record_failure(name)
            metrics_collector.record_failure(name)
            structured_logger.warning("Provider execution failed", name, {"status": result.provider_status, "error": result.error_message})
            
        return result
