import time
from datetime import datetime, timezone
from typing import List
from models.threat_intelligence_model import ThreatObservable, ThreatEvidence, ProviderResult
from threat_intelligence.base_provider import BaseThreatProvider
from threat_intelligence.http_client import http_client
from config.provider_config import PROVIDER_CONFIGS

class WHOISProvider(BaseThreatProvider):
    def name(self) -> str:
        return "WHOIS"

    def supported_observables(self) -> List[str]:
        return ["Domain"]

    async def lookup(self, observable: ThreatObservable) -> ProviderResult:
        start_time = time.perf_counter()
        domain = observable.value
        
        # Use public RDAP JSON bootstrap endpoint
        url = f"https://rdap.org/domain/{domain}"
        meta = PROVIDER_CONFIGS.get("WHOIS", {})
        
        res = await http_client.request(
            method="GET",
            url=url,
            provider_name="WHOIS",
            rate_limit_delay=meta.get("rate_limit_delay", 1.0),
            timeout_sec=meta.get("timeout", 3.0),
            retries=meta.get("retry_count", 1)
        )
        
        latency = (time.perf_counter() - start_time) * 1000.0
        
        if res["status"] != "SUCCESS":
            return ProviderResult(
                provider_name="WHOIS",
                provider_status=res["status"],
                evidence=[],
                lookup_time_ms=latency,
                error_message=res["error_message"]
            )
            
        data = res["data"] or {}
        evidence_list = []
        
        # Extract registrar
        registrar = "Unknown"
        entities = data.get("entities", [])
        for ent in entities:
            roles = ent.get("roles", [])
            if "registrar" in roles:
                vcard = ent.get("vcardArray", [])
                if len(vcard) > 1:
                    properties = vcard[1]
                    for prop in properties:
                        if prop[0] == "fn":
                            registrar = prop[3]
                            break
                            
        # Extract dates
        created_date = None
        expires_date = None
        events = data.get("events", [])
        for ev in events:
            action = ev.get("eventAction")
            date_str = ev.get("eventDate")
            if action in ["registration", "creation"] and date_str:
                created_date = date_str[:10]  # YYYY-MM-DD
            elif action == "expiration" and date_str:
                expires_date = date_str[:10]
                
        # Calculate domain age in days
        domain_age_days = -1
        if created_date:
            try:
                created_dt = datetime.strptime(created_date, "%Y-%m-%d")
                domain_age_days = (datetime.now(timezone.utc).replace(tzinfo=None) - created_dt).days
            except Exception:
                pass

        details = {
            "registrar": registrar,
            "creation_date": created_date,
            "expiration_date": expires_date,
            "domain_age_days": domain_age_days,
            "privacy_protected": "privacy" in str(data).lower()
        }
        
        # Generate informational telemetry evidence
        evidence_list.append(ThreatEvidence(
            provider="WHOIS",
            observable=domain,
            observable_type="Domain",
            classification="clean",
            severity="INFO",
            provider_confidence=1.0,
            technical_details=details,
            metadata={"version": "1.0.0", "lookup_latency_ms": latency}
        ))
        
        return ProviderResult(
            provider_name="WHOIS",
            provider_status="SUCCESS",
            evidence=evidence_list,
            lookup_time_ms=latency,
            cache_hit=False
        )
