import time
from typing import List
from models.threat_intelligence_model import ThreatObservable, ThreatEvidence, ProviderResult
from threat_intelligence.base_provider import BaseThreatProvider
from threat_intelligence.http_client import http_client
from config.provider_config import PROVIDER_CONFIGS

class CiscoTalosProvider(BaseThreatProvider):
    def name(self) -> str:
        return "CiscoTalos"

    def supported_observables(self) -> List[str]:
        return ["Domain", "IP Address"]

    async def lookup(self, observable: ThreatObservable) -> ProviderResult:
        start_time = time.perf_counter()
        meta = PROVIDER_CONFIGS.get("CiscoTalos", {})
        
        # Senders query via query_lookup API endpoint
        base_url = meta.get("url", "https://talosintelligence.com/sb_api/query_lookup")
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": "https://talosintelligence.com/reputation_center"
        }
        
        # Route query parameter depending on observable type
        if observable.type == "Domain":
            params = {"query": f"/api/v1/content_category/domain/{observable.value}"}
        else:
            params = {"query": f"/api/v1/reputation/ip/{observable.value}"}
            
        res = await http_client.request(
            method="GET",
            url=base_url,
            provider_name="CiscoTalos",
            headers=headers,
            params=params,
            rate_limit_delay=meta.get("rate_limit_delay", 0.5),
            timeout_sec=meta.get("timeout", 2.0),
            retries=meta.get("retry_count", 1)
        )
        
        latency = (time.perf_counter() - start_time) * 1000.0
        
        if res["status"] != "SUCCESS":
            return ProviderResult(
                provider_name="CiscoTalos",
                provider_status=res["status"],
                evidence=[],
                lookup_time_ms=latency,
                error_message=res["error_message"]
            )
            
        data = res["data"] or {}
        evidence_list = []
        
        # Cisco Talos responds with reputation stats (e.g. "Trusted", "Neutral", "Poor")
        reputation = data.get("reputation", "Neutral")
        
        # For domain queries, content categories can have dangerous tags
        category = data.get("category", {}).get("description", "Uncategorized")
        
        is_suspicious = reputation in ["Poor", "Suspicious"] or "malicious" in category.lower() or "phishing" in category.lower()
        
        if is_suspicious:
            evidence_list.append(ThreatEvidence(
                provider="CiscoTalos",
                observable=observable.value,
                observable_type=observable.type,
                classification="malicious" if reputation == "Poor" else "suspicious",
                severity="HIGH" if reputation == "Poor" else "MEDIUM",
                provider_confidence=0.85,
                technical_details={"reputation": reputation, "category": category},
                metadata={"version": "1.0.0", "lookup_latency_ms": latency}
            ))
            status = "SUCCESS"
        else:
            status = "NO_DATA"
            
        return ProviderResult(
            provider_name="CiscoTalos",
            provider_status=status,
            evidence=evidence_list,
            lookup_time_ms=latency,
            cache_hit=False
        )
