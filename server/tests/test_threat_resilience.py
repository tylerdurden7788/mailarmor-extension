import unittest
import asyncio
import time
from typing import List
from models.threat_intelligence_model import ThreatObservable, ProviderResult, ThreatEvidence
from threat_intelligence.base_provider import BaseThreatProvider
from threat_intelligence.provider_registry import ProviderRegistry
from threat_intelligence.provider_cache import ProviderCache
from threat_intelligence.provider_health import ProviderHealthMonitor
from threat_intelligence.provider_manager import ProviderManager
from threat_intelligence.http_client import http_client

# Define mock providers
class MockResilientProvider(BaseThreatProvider):
    def __init__(self, name: str, behavior: str = "success", delay: float = 0.0):
        self._name = name
        self.behavior = behavior
        self.delay = delay
        self.calls = 0

    def name(self) -> str:
        return self._name

    def supported_observables(self) -> List[str]:
        return ["Domain", "URL"]

    async def lookup(self, observable: ThreatObservable) -> ProviderResult:
        self.calls += 1
        if self.delay > 0.0:
            await asyncio.sleep(self.delay)
            
        if self.behavior == "success":
            return ProviderResult(
                provider_name=self._name,
                provider_status="SUCCESS",
                evidence=[ThreatEvidence(
                    provider=self._name,
                    observable=observable.value,
                    observable_type=observable.type,
                    classification="malicious",
                    severity="HIGH",
                    provider_confidence=0.9
                )],
                lookup_time_ms=self.delay * 1000.0,
                cache_hit=False
            )
        elif self.behavior == "timeout":
            raise asyncio.TimeoutError()
        elif self.behavior == "crash":
            raise RuntimeError("Mock provider crash")
        else:
            return ProviderResult(
                provider_name=self._name,
                provider_status="UNAVAILABLE",
                evidence=[],
                lookup_time_ms=0.0,
                cache_hit=False
            )

class TestThreatResilience(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.registry = ProviderRegistry()
        self.cache = ProviderCache()
        self.health = ProviderHealthMonitor(failure_threshold=2, min_calls=2, score_threshold=0.5)
        self.manager = ProviderManager(self.registry, self.cache, self.health)

    async def asyncTearDown(self):
        await http_client.close()

    async def test_provider_timeout_graceful_degradation(self):
        # 1. Register a provider with a long delay
        slow_prov = MockResilientProvider("SlowProvider", behavior="success", delay=1.0)
        self.registry.register("SlowProvider", slow_prov, {
            "enabled": True,
            "timeout": 0.1,  # Short timeout to force manager timeout guard
            "cache_ttl": 60
        })
        
        obs = ThreatObservable(value="malicious.com", type="Domain")
        results = await self.manager.lookup_observables([obs])
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].provider_name, "SlowProvider")
        self.assertEqual(results[0].provider_status, "UNAVAILABLE")
        self.assertIn("timed out", results[0].error_message)
        
        # Verify circuit breaker recorded a failure
        self.assertEqual(self.health.get_health_status("SlowProvider"), "HEALTHY") # requires 2 failures

    async def test_provider_crash_graceful_degradation(self):
        crash_prov = MockResilientProvider("CrashProvider", behavior="crash")
        self.registry.register("CrashProvider", crash_prov, {
            "enabled": True,
            "timeout": 1.0,
            "cache_ttl": 60
        })
        
        obs = ThreatObservable(value="malicious.com", type="Domain")
        results = await self.manager.lookup_observables([obs])
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].provider_name, "CrashProvider")
        self.assertEqual(results[0].provider_status, "ERROR")
        self.assertIn("Mock provider crash", results[0].error_message)

    async def test_circuit_breaker_transitions(self):
        crash_prov = MockResilientProvider("UnstableProvider", behavior="crash")
        self.registry.register("UnstableProvider", crash_prov, {
            "enabled": True,
            "timeout": 1.0,
            "cache_ttl": 60
        })
        
        obs = ThreatObservable(value="malicious.com", type="Domain")
        
        # Failure 1
        await self.manager.lookup_observables([obs])
        self.assertEqual(self.health.get_health_status("UnstableProvider"), "HEALTHY")
        
        # Failure 2 (trips circuit breaker)
        await self.manager.lookup_observables([obs])
        self.assertEqual(self.health.get_health_status("UnstableProvider"), "UNAVAILABLE")
        
        # Subsequent lookups should skip execution immediately and return UNAVAILABLE
        res = await self.manager.lookup_observables([obs])
        self.assertEqual(res[0].provider_status, "UNAVAILABLE")
        self.assertIn("tripped circuit-breaker", res[0].error_message)
        
        # Test recovery: manually overwrite next probe time to the past
        metrics = self.health._metrics["UnstableProvider"]
        metrics["next_probe_time"] = time.time() - 10.0
        
        # Next lookup checks health status -> transitions to RECOVERING and allows single probe
        crash_prov.behavior = "success"  # provider is healthy again!
        res_probe = await self.manager.lookup_observables([obs])
        self.assertEqual(res_probe[0].provider_status, "SUCCESS")
        
        # Now circuit breaker transitions back to HEALTHY
        self.assertEqual(self.health.get_health_status("UnstableProvider"), "HEALTHY")

    async def test_duplicate_registration_fails_fast(self):
        prov1 = MockResilientProvider("DupProvider")
        prov2 = MockResilientProvider("DupProvider")
        self.registry.register("DupProvider", prov1)
        with self.assertRaises(ValueError):
            self.registry.register("DupProvider", prov2)

    async def test_retry_after_suspended_backoff(self):
        # Clean up any existing http_client session
        await http_client.close()
        
        # Set a Retry-After suspend timestamp for a mock provider
        http_client._retry_after_until["RateLimitedProvider"] = time.time() + 10.0
        
        # Request should return RATE_LIMITED immediately without dispatching
        res = await http_client.request(
            method="GET",
            url="http://localhost:1234/test",
            provider_name="RateLimitedProvider",
            rate_limit_delay=0.0
        )
        self.assertEqual(res["status"], "RATE_LIMITED")
        self.assertIn("Retry-After", res["error_message"])
        
        # Cleanup
        http_client._retry_after_until.clear()

if __name__ == "__main__":
    unittest.main()
