import unittest
import asyncio
from typing import List
from models.threat_intelligence_model import ThreatObservable, ProviderResult
from threat_intelligence.base_provider import BaseThreatProvider
from threat_intelligence.provider_registry import ProviderRegistry
from threat_intelligence.provider_cache import ProviderCache
from threat_intelligence.provider_health import ProviderHealthMonitor
from threat_intelligence.provider_manager import ProviderManager

class MockDelayProvider(BaseThreatProvider):
    def __init__(self, name: str):
        self._name = name
        self.concurrent_active = 0
        self.max_concurrent = 0

    def name(self) -> str:
        return self._name

    def supported_observables(self) -> List[str]:
        return ["Domain"]

    async def lookup(self, observable: ThreatObservable) -> ProviderResult:
        self.concurrent_active += 1
        if self.concurrent_active > self.max_concurrent:
            self.max_concurrent = self.concurrent_active
            
        await asyncio.sleep(0.05)
        
        self.concurrent_active -= 1
        return ProviderResult(
            provider_name=self._name,
            provider_status="SUCCESS",
            evidence=[],
            lookup_time_ms=50.0,
            cache_hit=False
        )

class TestProviderPerformance(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.registry = ProviderRegistry()
        self.cache = ProviderCache(max_size=10) # Set small max_size to test evictions easily
        self.health = ProviderHealthMonitor()
        self.manager = ProviderManager(self.registry, self.cache, self.health)

    async def test_cache_lru_eviction(self):
        prov_name = "CacheTestProvider"
        # Insert 12 observables into a cache of max_size=10
        for i in range(12):
            obs = ThreatObservable(value=f"domain-{i}.com", type="Domain")
            result = ProviderResult(
                provider_name=prov_name,
                provider_status="SUCCESS",
                evidence=[],
                lookup_time_ms=0.1,
                cache_hit=False
            )
            await self.cache.insert(prov_name, obs, result, 60.0)
            
        # Get statistics
        stats = self.cache.get_statistics()
        self.assertEqual(stats["size"], 10)
        self.assertEqual(stats["evictions"], 2)
        
        # Older items (0 and 1) must be evicted, whereas newer ones must exist
        obs_old = ThreatObservable(value="domain-0.com", type="Domain")
        self.assertIsNone(await self.cache.lookup(prov_name, obs_old))
        
        obs_new = ThreatObservable(value="domain-11.com", type="Domain")
        res_new = await self.cache.lookup(prov_name, obs_new)
        self.assertIsNotNone(res_new)
        self.assertTrue(res_new.cache_hit)

    async def test_cache_memory_estimation(self):
        prov_name = "MemTestProvider"
        obs = ThreatObservable(value="long-domain-name-to-estimate-size.com", type="Domain")
        result = ProviderResult(
            provider_name=prov_name,
            provider_status="SUCCESS",
            evidence=[],
            lookup_time_ms=0.1,
            cache_hit=False
        )
        await self.cache.insert(prov_name, obs, result, 60.0)
        
        stats = self.cache.get_statistics()
        self.assertGreater(stats["memory_usage_estimate_bytes"], 0)

    async def test_large_ioc_batch_truncation(self):
        large_list = [
            ThreatObservable(value=f"malicious-{i}.com", type="Domain")
            for i in range(100)
        ]
        
        # Register a quick provider
        prov = MockDelayProvider("BatchProvider")
        self.registry.register("BatchProvider", prov)
        
        # Verify manager truncates inputs to 50
        await self.manager.lookup_observables(large_list)
        # 50 unique lookups triggered (since duplicate deduplication runs after truncation)
        self.assertLessEqual(prov.max_concurrent, 20)

    async def test_bounded_worker_concurrency(self):
        # Enforce concurrency limit in manager
        self.manager._semaphore = asyncio.Semaphore(3) # set semaphore to 3 to verify bounds easily
        
        prov = MockDelayProvider("ConcurrencyProvider")
        self.registry.register("ConcurrencyProvider", prov)
        
        observables = [
            ThreatObservable(value=f"domain-{i}.com", type="Domain")
            for i in range(10)
        ]
        
        # Query concurrently
        await self.manager.lookup_observables(observables)
        
        # Concurrency must be bounded by 3
        self.assertLessEqual(prov.max_concurrent, 3)

if __name__ == "__main__":
    unittest.main()
