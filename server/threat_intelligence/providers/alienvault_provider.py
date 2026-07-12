import time
from typing import List
from models.threat_intelligence_model import ThreatObservable, ThreatEvidence, ProviderResult
from threat_intelligence.base_provider import BaseThreatProvider
from threat_intelligence.http_client import http_client
from config.provider_config import PROVIDER_CONFIGS

class AlienvaultOTXProvider(BaseThreatProvider):
    def name(self) -> str:
        return "AlienvaultOTX"

    def supported_observables(self) -> List[str]:
        return ["URL", "Domain", "IP Address", "File Hash"]

    async def lookup(self, observable: ThreatObservable) -> ProviderResult:
        start_time = time.perf_counter()
        meta = PROVIDER_CONFIGS.get("AlienvaultOTX", {})
        api_key = meta.get("api_key", "")
        
        # Route query endpoints depending on type
        obs_type = observable.type
        if obs_type == "Domain":
            type_endpoint = "domain"
        elif obs_type == "IP Address":
            type_endpoint = "IPv4"
        elif obs_type == "File Hash":
            type_endpoint = "file"
        elif obs_type == "URL":
            type_endpoint = "url"
        else:
            latency = (time.perf_counter() - start_time) * 1000.0
            return ProviderResult(
                provider_name="AlienvaultOTX",
                provider_status="ERROR",
                evidence=[],
                lookup_time_ms=latency,
                error_message=f"Unsupported type: {obs_type}"
            )
            
        base_url = meta.get("url", "https://otx.alienvault.com/api/v1/indicators")
        url = f"{base_url}/{type_endpoint}/{observable.value}/general"
        
        headers = {"Accept": "application/json"}
        if api_key:
            headers["X-OTX-API-KEY"] = api_key
            
        res = await http_client.request(
            method="GET",
            url=url,
            provider_name="AlienvaultOTX",
            headers=headers,
            rate_limit_delay=meta.get("rate_limit_delay", 0.1),
            timeout_sec=meta.get("timeout", 2.5),
            retries=meta.get("retry_count", 1)
        )
        
        latency = (time.perf_counter() - start_time) * 1000.0
        
        if res["status"] != "SUCCESS":
            return ProviderResult(
                provider_name="AlienvaultOTX",
                provider_status=res["status"],
                evidence=[],
                lookup_time_ms=latency,
                error_message=res["error_message"]
            )
            
        data = res["data"] or {}
        evidence_list = []
        
        # AlienVault returns a collection of threat pulses
        pulses = data.get("pulse_info", {}).get("pulses", [])
        
        if pulses:
            # Map active threat pulses details
            details = {
                "pulse_count": len(pulses),
                "tags": list(set(tag for p in pulses for tag in p.get("tags", []))),
                "industries": list(set(ind for p in pulses for ind in p.get("targeted_countries", [])))
            }
            evidence_list.append(ThreatEvidence(
                provider="AlienvaultOTX",
                observable=observable.value,
                observable_type=observable.type,
                classification="malicious" if len(pulses) >= 3 else "suspicious",
                severity="HIGH" if len(pulses) >= 5 else "MEDIUM",
                provider_confidence=0.80,
                technical_details=details,
                metadata={"version": "1.0.0", "lookup_latency_ms": latency}
            ))
            status = "SUCCESS"
        else:
            status = "NO_DATA"
            
        return ProviderResult(
            provider_name="AlienvaultOTX",
            provider_status=status,
            evidence=evidence_list,
            lookup_time_ms=latency,
            cache_hit=False
        )
