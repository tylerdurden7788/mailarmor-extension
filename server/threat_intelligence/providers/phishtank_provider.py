import time
from typing import List
from models.threat_intelligence_model import ThreatObservable, ThreatEvidence, ProviderResult
from threat_intelligence.base_provider import BaseThreatProvider
from threat_intelligence.http_client import http_client
from config.provider_config import PROVIDER_CONFIGS

class PhishTankProvider(BaseThreatProvider):
    def name(self) -> str:
        return "PhishTank"

    def supported_observables(self) -> List[str]:
        return ["URL", "Domain"]

    async def lookup(self, observable: ThreatObservable) -> ProviderResult:
        start_time = time.perf_counter()
        meta = PROVIDER_CONFIGS.get("PhishTank", {})
        api_key = meta.get("api_key", "")
        
        url = meta.get("url", "https://checkurl.phishtank.com/checkurl/")
        
        # Prepare POST params
        data_payload = {
            "url": observable.value,
            "format": "json"
        }
        if api_key:
            data_payload["app_key"] = api_key
            
        res = await http_client.request(
            method="POST",
            url=url,
            provider_name="PhishTank",
            data=data_payload,
            rate_limit_delay=meta.get("rate_limit_delay", 1.0),
            timeout_sec=meta.get("timeout", 2.5),
            retries=meta.get("retry_count", 1)
        )
        
        latency = (time.perf_counter() - start_time) * 1000.0
        
        if res["status"] != "SUCCESS":
            return ProviderResult(
                provider_name="PhishTank",
                provider_status=res["status"],
                evidence=[],
                lookup_time_ms=latency,
                error_message=res["error_message"]
            )
            
        # PhishTank returns list/dict
        results = res["data"]
        evidence_list = []
        
        # Check if matched phish
        is_phish = False
        phish_details = {}
        
        if isinstance(results, dict) and "results" in results:
            phish_details = results["results"]
            is_phish = phish_details.get("in_database", False) and phish_details.get("valid", False)
        elif isinstance(results, list) and len(results) > 0:
            # Sometimes a direct JSON list is returned
            phish_details = results[0].get("results", {})
            is_phish = phish_details.get("in_database", False) and phish_details.get("valid", False)
            
        if is_phish:
            evidence_list.append(ThreatEvidence(
                provider="PhishTank",
                observable=observable.value,
                observable_type=observable.type,
                classification="malicious",
                severity="HIGH",
                provider_confidence=0.90 if phish_details.get("verified", False) else 0.70,
                technical_details=phish_details,
                metadata={"version": "2.0.0", "lookup_latency_ms": latency}
            ))
            status = "SUCCESS"
        else:
            status = "NO_DATA"
            
        return ProviderResult(
            provider_name="PhishTank",
            provider_status=status,
            evidence=evidence_list,
            lookup_time_ms=latency,
            cache_hit=False
        )
