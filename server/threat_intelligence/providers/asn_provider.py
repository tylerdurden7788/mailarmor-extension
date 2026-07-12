import asyncio
import time
import socket
import logging
from typing import List
from models.threat_intelligence_model import ThreatObservable, ThreatEvidence, ProviderResult
from threat_intelligence.base_provider import BaseThreatProvider
from threat_intelligence.http_client import http_client
from config.provider_config import PROVIDER_CONFIGS

logger = logging.getLogger("ASNProvider")

class ASNProvider(BaseThreatProvider):
    def name(self) -> str:
        return "ASN"

    def supported_observables(self) -> List[str]:
        return ["IP Address", "Domain"]

    async def lookup(self, observable: ThreatObservable) -> ProviderResult:
        start_time = time.perf_counter()
        value = observable.value
        meta = PROVIDER_CONFIGS.get("ASN", {})
        
        target_ip = ""
        loop = asyncio.get_event_loop()
        
        if observable.type == "Domain":
            try:
                # Settle IP address for the domain first
                addr_info = await loop.getaddrinfo(
                    value, None, family=socket.AF_INET, type=socket.SOCK_STREAM
                )
                if addr_info:
                    target_ip = addr_info[0][4][0]
            except Exception as e:
                logger.debug(f"Failed to resolve domain {value} to IP for ASN lookup: {e}")
        else:
            target_ip = value
            
        if not target_ip:
            latency = (time.perf_counter() - start_time) * 1000.0
            return ProviderResult(
                provider_name="ASN",
                provider_status="NO_DATA",
                evidence=[],
                lookup_time_ms=latency,
                error_message="Could not resolve domain or IP"
            )
            
        # Call ipinfo.io to get ASN details (free tier lookup)
        url = f"https://ipinfo.io/{target_ip}/json"
        
        res = await http_client.request(
            method="GET",
            url=url,
            provider_name="ASN",
            timeout_sec=meta.get("timeout", 2.0),
            retries=meta.get("retry_count", 1)
        )
        
        latency = (time.perf_counter() - start_time) * 1000.0
        
        if res["status"] != "SUCCESS":
            return ProviderResult(
                provider_name="ASN",
                provider_status=res["status"],
                evidence=[],
                lookup_time_ms=latency,
                error_message=res["error_message"]
            )
            
        data = res["data"] or {}
        evidence_list = []
        
        # Settle ASN details
        org = data.get("org", "Unknown")
        asn = "Unknown"
        org_name = org
        
        if org.startswith("AS"):
            parts = org.split(" ", 1)
            asn = parts[0]
            if len(parts) > 1:
                org_name = parts[1]
                
        details = {
            "asn": asn,
            "organization": org_name,
            "country": data.get("country", "Unknown"),
            "hosting_provider": "amazon" in org_name.lower() or "google" in org_name.lower() or "microsoft" in org_name.lower() or "cloudflare" in org_name.lower(),
            "cloud_provider": "hosting" in org_name.lower() or "cloud" in org_name.lower()
        }
        
        # Yields informational evidence
        evidence_list.append(ThreatEvidence(
            provider="ASN",
            observable=observable.value,
            observable_type=observable.type,
            classification="clean",
            severity="INFO",
            provider_confidence=1.0,
            technical_details=details,
            metadata={"version": "1.0.0", "lookup_latency_ms": latency}
        ))
        
        return ProviderResult(
            provider_name="ASN",
            provider_status="SUCCESS",
            evidence=evidence_list,
            lookup_time_ms=latency,
            cache_hit=False
        )
