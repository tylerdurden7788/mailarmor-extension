import time
import base64
from typing import List
from models.threat_intelligence_model import ThreatObservable, ThreatEvidence, ProviderResult
from threat_intelligence.base_provider import BaseThreatProvider
from threat_intelligence.http_client import http_client
from config.provider_config import PROVIDER_CONFIGS

class VirusTotalProvider(BaseThreatProvider):
    def name(self) -> str:
        return "VirusTotal"

    def supported_observables(self) -> List[str]:
        return ["URL", "Domain", "IP Address", "File Hash"]

    async def lookup(self, observable: ThreatObservable) -> ProviderResult:
        start_time = time.perf_counter()
        meta = PROVIDER_CONFIGS.get("VirusTotal", {})
        api_key = meta.get("api_key", "")
        
        latency = (time.perf_counter() - start_time) * 1000.0
        
        if not api_key:
            return ProviderResult(
                provider_name="VirusTotal",
                provider_status="UNAVAILABLE",
                evidence=[],
                lookup_time_ms=latency,
                error_message="VirusTotal API key missing"
            )
            
        base_url = meta.get("url", "https://www.virustotal.com/api/v3")
        headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }
        
        # Route based on observable type
        if observable.type == "Domain":
            endpoint = f"/domains/{observable.value}"
        elif observable.type == "IP Address":
            endpoint = f"/ip_addresses/{observable.value}"
        elif observable.type == "File Hash":
            endpoint = f"/files/{observable.value}"
        elif observable.type == "URL":
            # VT URL identifier must be urlsafe base64 without padding
            url_id = base64.urlsafe_b64encode(observable.value.encode()).decode().rstrip("=")
            endpoint = f"/urls/{url_id}"
        else:
            return ProviderResult(
                provider_name="VirusTotal",
                provider_status="ERROR",
                evidence=[],
                lookup_time_ms=latency,
                error_message=f"Unsupported observable type: {observable.type}"
            )
            
        res = await http_client.request(
            method="GET",
            url=f"{base_url}{endpoint}",
            provider_name="VirusTotal",
            headers=headers,
            rate_limit_delay=meta.get("rate_limit_delay", 15.0),  # Slow public API limit
            timeout_sec=meta.get("timeout", 3.0),
            retries=meta.get("retry_count", 1)
        )
        
        latency = (time.perf_counter() - start_time) * 1000.0
        
        if res["status"] != "SUCCESS":
            return ProviderResult(
                provider_name="VirusTotal",
                provider_status=res["status"],
                evidence=[],
                lookup_time_ms=latency,
                error_message=res["error_message"]
            )
            
        attr = ((res["data"] or {}).get("data", {})).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        total_engines = sum(stats.values())
        
        evidence_list = []
        
        if malicious_count > 0 or suspicious_count > 0:
            details = {
                "malicious_engines": malicious_count,
                "suspicious_engines": suspicious_count,
                "total_engines": total_engines,
                "reputation": attr.get("reputation", 0),
                "categories": attr.get("categories", {})
            }
            
            # Map severity based on detection density
            severity = "MEDIUM"
            if malicious_count >= 5:
                severity = "HIGH"
            if malicious_count >= 15:
                severity = "CRITICAL"
                
            evidence_list.append(ThreatEvidence(
                provider="VirusTotal",
                observable=observable.value,
                observable_type=observable.type,
                classification="malicious" if malicious_count >= 3 else "suspicious",
                severity=severity,
                provider_confidence=min(1.0, 0.5 + (malicious_count / 10.0)),
                technical_details=details,
                metadata={"version": "3.0.0", "lookup_latency_ms": latency}
            ))
            status = "SUCCESS"
        else:
            status = "NO_DATA"
            
        return ProviderResult(
            provider_name="VirusTotal",
            provider_status=status,
            evidence=evidence_list,
            lookup_time_ms=latency,
            cache_hit=False
        )
