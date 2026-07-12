import asyncio
import time
import socket
import logging
from typing import List, Dict, Any
from models.threat_intelligence_model import ThreatObservable, ThreatEvidence, ProviderResult
from threat_intelligence.base_provider import BaseThreatProvider
from config.provider_config import PROVIDER_CONFIGS

logger = logging.getLogger("DNSProvider")

class DNSProvider(BaseThreatProvider):
    def name(self) -> str:
        return "DNS"

    def supported_observables(self) -> List[str]:
        return ["Domain", "IP Address"]

    async def lookup(self, observable: ThreatObservable) -> ProviderResult:
        start_time = time.perf_counter()
        value = observable.value
        meta = PROVIDER_CONFIGS.get("DNS", {})
        
        evidence_list = []
        details: Dict[str, Any] = {
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": []
        }
        
        loop = asyncio.get_event_loop()
        
        try:
            if observable.type == "Domain":
                # 1. Resolve A and AAAA records using standard getaddrinfo
                try:
                    addr_info = await loop.getaddrinfo(
                        value, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
                    )
                    for family, _, _, _, sockaddr in addr_info:
                        ip = sockaddr[0]
                        if family == socket.AF_INET:
                            if ip not in details["a_records"]:
                                details["a_records"].append(ip)
                        elif family == socket.AF_INET6:
                            if ip not in details["aaaa_records"]:
                                details["aaaa_records"].append(ip)
                except Exception as e:
                    logger.debug(f"Failed resolving IP addresses for {value}: {e}")

                # 2. Resolve MX and TXT records using nslookup subprocess (built-in, cross-platform)
                for qtype in ["MX", "TXT", "NS"]:
                    try:
                        # Command options based on Windows
                        cmd = f"nslookup -type={qtype} {value}"
                        proc = await asyncio.create_subprocess_shell(
                            cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=2.0)
                        output = stdout.decode("utf-8", errors="ignore")
                        
                        # Parse nslookup output lines
                        for line in output.splitlines():
                            line_cleaned = line.strip()
                            if qtype == "MX" and "mail exchanger" in line_cleaned:
                                parts = line_cleaned.split("mail exchanger =")
                                if len(parts) > 1:
                                    details["mx_records"].append(parts[1].strip())
                            elif qtype == "NS" and "nameserver =" in line_cleaned:
                                parts = line_cleaned.split("nameserver =")
                                if len(parts) > 1:
                                    details["ns_records"].append(parts[1].strip())
                            elif qtype == "TXT" and ('text =' in line_cleaned or '"' in line_cleaned):
                                if "text =" in line_cleaned:
                                    parts = line_cleaned.split("text =")
                                    txt_val = parts[1].strip().strip('"')
                                else:
                                    txt_val = line_cleaned.strip('"')
                                if txt_val and txt_val not in details["txt_records"]:
                                    details["txt_records"].append(txt_val)
                    except Exception as e:
                        logger.debug(f"Subprocess DNS {qtype} resolution failed for {value}: {e}")
            else:
                # IP address lookup: reverse DNS resolution
                try:
                    host_info = await loop.getnameinfo((value, 0), 0)
                    details["reverse_dns"] = host_info[0]
                except Exception as e:
                    logger.debug(f"Reverse DNS lookup failed for {value}: {e}")
                    
        except Exception as e:
            latency = (time.perf_counter() - start_time) * 1000.0
            return ProviderResult(
                provider_name="DNS",
                provider_status="ERROR",
                evidence=[],
                lookup_time_ms=latency,
                error_message=str(e)
            )

        latency = (time.perf_counter() - start_time) * 1000.0
        
        # Check if we resolved anything
        has_data = any(len(v) > 0 for k, v in details.items() if isinstance(v, list)) or "reverse_dns" in details
        status = "SUCCESS" if has_data else "NO_DATA"
        
        if status == "SUCCESS":
            evidence_list.append(ThreatEvidence(
                provider="DNS",
                observable=value,
                observable_type=observable.type,
                classification="clean",
                severity="INFO",
                provider_confidence=1.0,
                technical_details=details,
                metadata={"version": "1.0.0", "lookup_latency_ms": latency}
            ))

        return ProviderResult(
            provider_name="DNS",
            provider_status=status,
            evidence=evidence_list,
            lookup_time_ms=latency,
            cache_hit=False
        )
