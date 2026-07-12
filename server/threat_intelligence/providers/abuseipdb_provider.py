import time
from typing import List
from models.threat_intelligence_model import ThreatObservable, ThreatEvidence, ProviderResult
from threat_intelligence.base_provider import BaseThreatProvider
from threat_intelligence.http_client import http_client
from config.provider_config import PROVIDER_CONFIGS

class AbuseIPDBProvider(BaseThreatProvider):
    def name(self) -> str:
        return "AbuseIPDB"

    def supported_observables(self) -> List[str]:
        return ["IP Address"]

    async def lookup(self, observable: ThreatObservable) -> ProviderResult:
        start_time = time.perf_counter()
        meta = PROVIDER_CONFIGS.get("AbuseIPDB", {})
        api_key = meta.get("api_key", "")
        
        latency = (time.perf_counter() - start_time) * 1000.0
        
        if not api_key:
            return ProviderResult(
                provider_name="AbuseIPDB",
                provider_status="UNAVAILABLE",
                evidence=[],
                lookup_time_ms=latency,
                error_message="AbuseIPDB API key missing"
            )
            
        url = meta.get("url", "https://api.abuseipdb.com/api/v2/check")
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": observable.value,
            "maxAgeInDays": 90
        }
        
        res = await http_client.request(
            method="GET",
            url=url,
            provider_name="AbuseIPDB",
            headers=headers,
            params=params,
            rate_limit_delay=meta.get("rate_limit_delay", 0.2),
            timeout_sec=meta.get("timeout", 2.0),
            retries=meta.get("retry_count", 1)
        )
        
        latency = (time.perf_counter() - start_time) * 1000.0
        
        if res["status"] != "SUCCESS":
            return ProviderResult(
                provider_name="AbuseIPDB",
                provider_status=res["status"],
                evidence=[],
                lookup_time_ms=latency,
                error_message=res["error_message"]
            )
            
        data = (res["data"] or {}).get("data", {})
        evidence_list = []
        
        abuse_score = data.get("abuseConfidenceScore", 0)
        
        if abuse_score > 0:
            evidence_list.append(ThreatEvidence(
                provider="AbuseIPDB",
                observable=observable.value,
                observable_type="IP Address",
                classification="malicious" if abuse_score > 50 else "suspicious",
                severity="HIGH" if abuse_score > 75 else "MEDIUM",
                provider_confidence=0.90,
                technical_details=data,
                metadata={"version": "2.0.0", "lookup_latency_ms": latency}
            ))
            status = "SUCCESS"
        else:
            status = "NO_DATA"
            
        return ProviderResult(
            provider_name="AbuseIPDB",
            provider_status=status,
            evidence=evidence_list,
            lookup_time_ms=latency,
            cache_hit=False
        )
