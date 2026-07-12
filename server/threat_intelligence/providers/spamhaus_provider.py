import asyncio
import time
import socket
import logging
from typing import List
from models.threat_intelligence_model import ThreatObservable, ThreatEvidence, ProviderResult
from threat_intelligence.base_provider import BaseThreatProvider
from config.provider_config import PROVIDER_CONFIGS

logger = logging.getLogger("SpamhausProvider")

class SpamhausProvider(BaseThreatProvider):
    def name(self) -> str:
        return "Spamhaus"

    def supported_observables(self) -> List[str]:
        return ["Domain", "IP Address"]

    async def lookup(self, observable: ThreatObservable) -> ProviderResult:
        start_time = time.perf_counter()
        value = observable.value
        meta = PROVIDER_CONFIGS.get("Spamhaus", {})
        timeout = meta.get("timeout", 2.0)
        
        evidence_list = []
        loop = asyncio.get_event_loop()
        
        # Determine DNSBL query hostname
        query_host = ""
        if observable.type == "IP Address":
            try:
                # Reverse IP octets for zen lookup
                octets = value.split(".")
                if len(octets) == 4:
                    reversed_ip = ".".join(reversed(octets))
                    query_host = f"{reversed_ip}.zen.spamhaus.org"
            except Exception:
                pass
        elif observable.type == "Domain":
            query_host = f"{value}.dbl.spamhaus.org"
            
        if not query_host:
            latency = (time.perf_counter() - start_time) * 1000.0
            return ProviderResult(
                provider_name="Spamhaus",
                provider_status="ERROR",
                evidence=[],
                lookup_time_ms=latency,
                error_message="Invalid IP or domain format for Spamhaus DNSBL"
            )
            
        listed = False
        resolved_ip = "127.0.0.1" # standard loopback default, not listed
        
        try:
            # Settle A record resolution
            addr_info = await asyncio.wait_for(
                loop.getaddrinfo(query_host, None, family=socket.AF_INET, type=socket.SOCK_STREAM),
                timeout=timeout
            )
            if addr_info:
                resolved_ip = addr_info[0][4][0]
                # If resolved IP starts with 127.0., it is blocked on Spamhaus
                if resolved_ip.startswith("127.0."):
                    listed = True
        except socket.gaierror:
            # Host name not found means NOT listed on blocklist (standard DNSBL behavior)
            listed = False
        except asyncio.TimeoutError:
            latency = (time.perf_counter() - start_time) * 1000.0
            return ProviderResult(
                provider_name="Spamhaus",
                provider_status="UNAVAILABLE",
                evidence=[],
                lookup_time_ms=latency,
                error_message="DNS query timed out"
            )
        except Exception as e:
            latency = (time.perf_counter() - start_time) * 1000.0
            return ProviderResult(
                provider_name="Spamhaus",
                provider_status="ERROR",
                evidence=[],
                lookup_time_ms=latency,
                error_message=str(e)
            )

        latency = (time.perf_counter() - start_time) * 1000.0
        
        if listed:
            evidence_list.append(ThreatEvidence(
                provider="Spamhaus",
                observable=value,
                observable_type=observable.type,
                classification="malicious",
                severity="HIGH",
                provider_confidence=0.95,
                technical_details={"dnsbl_response": resolved_ip, "dnsbl_query": query_host},
                metadata={"version": "1.0.0", "lookup_latency_ms": latency}
            ))
            status = "SUCCESS"
        else:
            status = "NO_DATA"
            
        return ProviderResult(
            provider_name="Spamhaus",
            provider_status=status,
            evidence=evidence_list,
            lookup_time_ms=latency,
            cache_hit=False
        )
