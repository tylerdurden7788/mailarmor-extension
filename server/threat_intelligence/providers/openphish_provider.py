import time
from typing import List
from models.threat_intelligence_model import ThreatObservable, ThreatEvidence, ProviderResult
from threat_intelligence.base_provider import BaseThreatProvider
from threat_intelligence.http_client import http_client
from config.provider_config import PROVIDER_CONFIGS

class OpenPhishProvider(BaseThreatProvider):
    def name(self) -> str:
        return "OpenPhish"

    def supported_observables(self) -> List[str]:
        return ["URL", "Domain"]

    async def lookup(self, observable: ThreatObservable) -> ProviderResult:
        start_time = time.perf_counter()
        meta = PROVIDER_CONFIGS.get("OpenPhish", {})
        api_key = meta.get("api_key", "")
        
        latency = (time.perf_counter() - start_time) * 1000.0
        
        if not api_key:
            return ProviderResult(
                provider_name="OpenPhish",
                provider_status="UNAVAILABLE",
                evidence=[],
                lookup_time_ms=latency,
                error_message="OpenPhish API key missing"
            )
            
        url = meta.get("url", "https://api.openphish.com/v2/lookup")
        headers = {"Authorization": f"Bearer {api_key}"}
        payload = {"url": observable.value}
        
        res = await http_client.request(
            method="POST",
            url=url,
            provider_name="OpenPhish",
            headers=headers,
            json_data=payload,
            rate_limit_delay=meta.get("rate_limit_delay", 0.5),
            timeout_sec=meta.get("timeout", 2.0),
            retries=meta.get("retry_count", 1)
        )
        
        latency = (time.perf_counter() - start_time) * 1000.0
        
        if res["status"] != "SUCCESS":
            return ProviderResult(
                provider_name="OpenPhish",
                provider_status=res["status"],
                evidence=[],
                lookup_time_ms=latency,
                error_message=res["error_message"]
            )
            
        data = res["data"] or {}
        evidence_list = []
        
        # OpenPhish v2 returns: {"url": "...", "phish": true, "brand": "..."}
        if data.get("phish", False):
            evidence_list.append(ThreatEvidence(
                provider="OpenPhish",
                observable=observable.value,
                observable_type=observable.type,
                classification="malicious",
                severity="HIGH",
                provider_confidence=0.95,
                technical_details=data,
                metadata={"version": "2.0.0", "lookup_latency_ms": latency}
            ))
            status = "SUCCESS"
        else:
            status = "NO_DATA"
            
        return ProviderResult(
            provider_name="OpenPhish",
            provider_status=status,
            evidence=evidence_list,
            lookup_time_ms=latency,
            cache_hit=False
        )
