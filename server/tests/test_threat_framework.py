import unittest
import asyncio
import time
from typing import List
from models.threat_intelligence_model import ThreatObservable, ThreatEvidence, ProviderResult
from threat_intelligence.base_provider import BaseThreatProvider
from threat_intelligence.provider_registry import ProviderRegistry
from threat_intelligence.provider_cache import ProviderCache
from threat_intelligence.provider_health import ProviderHealthMonitor
from threat_intelligence.provider_manager import ProviderManager
from threat_intelligence.ioc_normalizer import IOCNormalizer

class DummyThreatProvider(BaseThreatProvider):
    def __init__(self, name_str: str, delay: float = 0.0, should_fail: bool = False):
        self._name = name_str
        self.delay = delay
        self.should_fail = should_fail
        
    def name(self) -> str:
        return self._name
        
    def supported_observables(self) -> List[str]:
        return ["Domain", "URL"]
        
    async def lookup(self, observable: ThreatObservable) -> ProviderResult:
        if self.delay > 0:
            await asyncio.sleep(self.delay)
        if self.should_fail:
            raise Exception("Lookup failed")
            
        evidence = [
            ThreatEvidence(
                provider=self._name,
                observable=observable.value,
                observable_type=observable.type,
                classification="malicious",
                severity="HIGH",
                provider_confidence=0.90,
                technical_details={"detected": True},
                metadata={"test": True}
            )
        ]
        return ProviderResult(
            provider_name=self._name,
            provider_status="SUCCESS",
            evidence=evidence,
            lookup_time_ms=0.0,
            cache_hit=False
        )

class TestThreatFramework(unittest.TestCase):
    def run_async(self, coro):
        return asyncio.run(coro)

    def test_provider_registration_and_metadata(self):
        registry = ProviderRegistry()
        provider = DummyThreatProvider("TestProv")
        registry.register("TestProv", provider, {"custom_key": "val"})
        
        self.assertIn("TestProv", registry.get_enabled_providers())
        self.assertEqual(registry.get_provider("TestProv"), provider)
        
        meta = registry.get_metadata("TestProv")
        self.assertEqual(meta["custom_key"], "val")
        self.assertEqual(meta["health_status"], "Healthy")

    def test_ioc_normalization(self):
        # 1. Domain
        self.assertEqual(IOCNormalizer.normalize("http://LOOKALIKE.com/login", "Domain"), "lookalike.com")
        self.assertEqual(IOCNormalizer.normalize("lookalike.com.", "Domain"), "lookalike.com")
        
        # 2. URL
        self.assertEqual(IOCNormalizer.normalize("HTTP://lookalike.com/path#fragment", "URL"), "http://lookalike.com/path")
        
        # 3. Email
        self.assertEqual(IOCNormalizer.normalize("Admin <ADMIN@domain.com>", "Email Address"), "admin@domain.com")
        
        # 4. Hash
        self.assertEqual(IOCNormalizer.normalize(" A1B2c3D4 ", "File Hash"), "a1b2c3d4")

    def test_cache_insertion_expiration_and_stats(self):
        cache = ProviderCache()
        obs = ThreatObservable(value="malicious.com", type="Domain")
        evidence = [ThreatEvidence(
            provider="CacheTest", observable="malicious.com", observable_type="Domain",
            classification="malicious", severity="MEDIUM", provider_confidence=0.8
        )]
        result = ProviderResult(
            provider_name="CacheTest",
            provider_status="SUCCESS",
            evidence=evidence,
            lookup_time_ms=1.0,
            cache_hit=False
        )
        
        # Insert
        self.run_async(cache.insert("CacheTest", obs, result, ttl_sec=0.2))
        
        # Lookup hit
        hit = self.run_async(cache.lookup("CacheTest", obs))
        self.assertIsNotNone(hit)
        self.assertEqual(len(hit.evidence), 1)
        self.assertTrue(hit.cache_hit)
        
        # Wait for expiration
        time.sleep(0.3)
        miss = self.run_async(cache.lookup("CacheTest", obs))
        self.assertIsNone(miss)
        
        stats = cache.get_statistics()
        self.assertEqual(stats["hits"], 1)
        self.assertEqual(stats["size"], 0)

    def test_health_circuit_breaker(self):
        health = ProviderHealthMonitor(failure_threshold=2, min_calls=2)
        
        # Record success
        health.record_success("Prov", latency_ms=10.0)
        self.assertEqual(health.get_health_status("Prov"), "Healthy")
        
        # Consecutive failures
        health.record_failure("Prov")
        self.assertEqual(health.get_health_status("Prov"), "Healthy") # Failures = 1
        
        health.record_failure("Prov")
        self.assertEqual(health.get_health_status("Prov"), "Unhealthy") # Failures = 2 (Threshold reached)
        
        metrics = health.get_metrics("Prov")
        self.assertEqual(metrics["total_calls"], 3)
        self.assertEqual(metrics["consecutive_failures"], 2)

    def test_provider_manager_lookups(self):
        registry = ProviderRegistry()
        cache = ProviderCache()
        health = ProviderHealthMonitor()
        manager = ProviderManager(registry, cache, health)
        
        provider = DummyThreatProvider("ManagerTest")
        registry.register("ManagerTest", provider)
        
        obs = ThreatObservable(value="test.com", type="Domain")
        results = self.run_async(manager.lookup_observables([obs]))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].provider_name, "ManagerTest")
        self.assertEqual(len(results[0].evidence), 1)
        
        # Verify cached hit
        stats = cache.get_statistics()
        self.assertEqual(stats["size"], 1)
        
        # Repeat lookup should hit cache
        results2 = self.run_async(manager.lookup_observables([obs]))
        self.assertEqual(len(results2), 1)
        self.assertTrue(results2[0].cache_hit)
        stats2 = cache.get_statistics()
        self.assertEqual(stats2["hits"], 1)

if __name__ == '__main__':
    unittest.main()
