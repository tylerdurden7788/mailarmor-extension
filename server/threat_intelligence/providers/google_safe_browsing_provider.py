import time
from typing import List
from models.threat_intelligence_model import ThreatObservable, ThreatEvidence, ProviderResult
from threat_intelligence.base_provider import BaseThreatProvider
from threat_intelligence.http_client import http_client
from config.provider_config import PROVIDER_CONFIGS

class GoogleSafeBrowsingProvider(BaseThreatProvider):
    def name(self) -> str:
        return "GoogleSafeBrowsing"

    def supported_observables(self) -> List[str]:
        return ["URL", "Domain"]

    async def lookup(self, observable: ThreatObservable) -> ProviderResult:
        start_time = time.perf_counter()
        meta = PROVIDER_CONFIGS.get("GoogleSafeBrowsing", {})
        api_key = meta.get("api_key", "")
        
        latency = (time.perf_counter() - start_time) * 1000.0
        
        if not api_key:
            return ProviderResult(
                provider_name="GoogleSafeBrowsing",
                provider_status="UNAVAILABLE",
                evidence=[],
                lookup_time_ms=latency,
                error_message="Google Safe Browsing API key missing"
            )
            
        url = f"{meta.get('url')}?key={api_key}"
        
        # Prepare request payload
        payload = {
            "client": {
                "clientId": "mailarmour",
                "clientVersion": "3.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": observable.value}
                ]
            }
        }
        
        res = await http_client.request(
            method="POST",
            url=url,
            provider_name="GoogleSafeBrowsing",
            json_data=payload,
            timeout_sec=meta.get("timeout", 2.0),
            retries=meta.get("retry_count", 1)
        )
        
        latency = (time.perf_counter() - start_time) * 1000.0
        
        if res["status"] != "SUCCESS":
            return ProviderResult(
                provider_name="GoogleSafeBrowsing",
                provider_status=res["status"],
                evidence=[],
                lookup_time_ms=latency,
                error_message=res["error_message"]
            )
            
        matches = (res["data"] or {}).get("matches", [])
        evidence_list = []
        
        if matches:
            for match in matches:
                threat_type = match.get("threatType", "UNKNOWN")
                evidence_list.append(ThreatEvidence(
                    provider="GoogleSafeBrowsing",
                    observable=observable.value,
                    observable_type=observable.type,
                    classification="malicious",
                    severity="HIGH" if threat_type == "SOCIAL_ENGINEERING" else "MEDIUM",
                    provider_confidence=0.95,
                    technical_details=match,
                    metadata={"version": "4.0.0", "lookup_latency_ms": latency}
                ))
            status = "SUCCESS"
        else:
            status = "NO_DATA"
            
        return ProviderResult(
            provider_name="GoogleSafeBrowsing",
            provider_status=status,
            evidence=evidence_list,
            lookup_time_ms=latency,
            cache_hit=False
        )
