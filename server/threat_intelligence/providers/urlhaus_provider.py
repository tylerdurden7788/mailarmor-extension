import time
from typing import List
from models.threat_intelligence_model import ThreatObservable, ThreatEvidence, ProviderResult
from threat_intelligence.base_provider import BaseThreatProvider
from threat_intelligence.http_client import http_client
from config.provider_config import PROVIDER_CONFIGS

class URLHausProvider(BaseThreatProvider):
    def name(self) -> str:
        return "URLHaus"

    def supported_observables(self) -> List[str]:
        return ["URL", "Domain"]

    async def lookup(self, observable: ThreatObservable) -> ProviderResult:
        start_time = time.perf_counter()
        meta = PROVIDER_CONFIGS.get("URLHaus", {})
        
        # Endpoint: https://urlhaus-api.abuse.ch/v1/url/ (or /host/ for domains)
        # To simplify, if observable is Domain, we use /host/ endpoint.
        base_url = meta.get("url", "https://urlhaus-api.abuse.ch/v1/url/")
        if observable.type == "Domain":
            url = base_url.replace("/url/", "/host/")
            payload = {"host": observable.value}
        else:
            url = base_url
            payload = {"url": observable.value}
            
        res = await http_client.request(
            method="POST",
            url=url,
            provider_name="URLHaus",
            data=payload,
            rate_limit_delay=meta.get("rate_limit_delay", 0.1),
            timeout_sec=meta.get("timeout", 2.0),
            retries=meta.get("retry_count", 1)
        )
        
        latency = (time.perf_counter() - start_time) * 1000.0
        
        if res["status"] != "SUCCESS":
            return ProviderResult(
                provider_name="URLHaus",
                provider_status=res["status"],
                evidence=[],
                lookup_time_ms=latency,
                error_message=res["error_message"]
            )
            
        data = res["data"] or {}
        evidence_list = []
        
        # Check query status
        query_status = data.get("query_status", "no_match")
        
        if query_status == "ok":
            evidence_list.append(ThreatEvidence(
                provider="URLHaus",
                observable=observable.value,
                observable_type=observable.type,
                classification="malicious",
                severity="HIGH" if data.get("url_status") == "online" else "MEDIUM",
                provider_confidence=0.90,
                technical_details=data,
                metadata={"version": "1.0.0", "lookup_latency_ms": latency}
            ))
            status = "SUCCESS"
        else:
            status = "NO_DATA"
            
        return ProviderResult(
            provider_name="URLHaus",
            provider_status=status,
            evidence=evidence_list,
            lookup_time_ms=latency,
            cache_hit=False
        )
