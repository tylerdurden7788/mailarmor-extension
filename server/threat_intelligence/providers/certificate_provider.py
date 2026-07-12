import asyncio
import time
import ssl
import socket
import logging
from typing import List
from models.threat_intelligence_model import ThreatObservable, ThreatEvidence, ProviderResult
from threat_intelligence.base_provider import BaseThreatProvider
from config.provider_config import PROVIDER_CONFIGS

logger = logging.getLogger("CertificateProvider")

class CertificateProvider(BaseThreatProvider):
    def name(self) -> str:
        return "Certificate"

    def supported_observables(self) -> List[str]:
        return ["Domain"]

    async def lookup(self, observable: ThreatObservable) -> ProviderResult:
        start_time = time.perf_counter()
        domain = observable.value
        meta = PROVIDER_CONFIGS.get("Certificate", {})
        timeout = meta.get("timeout", 2.5)
        
        evidence_list = []
        details = {
            "issuer": "Unknown",
            "valid_from": "Unknown",
            "valid_to": "Unknown",
            "subject_alt_names": [],
            "self_signed": False,
            "expired": False,
            "validation_error": None
        }
        
        loop = asyncio.get_event_loop()
        
        try:
            # 1. Standard SSL context with no hostname validation to get peer cert
            # We use a thread pool to avoid blocking the event loop on socket creation/connect
            def get_ssl_details():
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE  # No SSL validation, just collect cert
                
                with socket.create_connection((domain, 443), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        return cert
                        
            cert = await loop.run_in_executor(None, get_ssl_details)
            
            if cert:
                # Parse issuer
                issuer_parts = []
                for rdns in cert.get("issuer", []):
                    for k, v in rdns:
                        if k == "commonName" or k == "organizationName":
                            issuer_parts.append(v)
                details["issuer"] = ", ".join(issuer_parts) if issuer_parts else "Unknown"
                
                # Parse validity
                details["valid_from"] = cert.get("notBefore", "Unknown")
                details["valid_to"] = cert.get("notAfter", "Unknown")
                
                # Check expiration
                if details["valid_to"] != "Unknown":
                    try:
                        # e.g., "May  5 07:11:49 2026 GMT"
                        expire_dt = ssl.cert_time_to_seconds(details["valid_to"])
                        if time.time() > expire_dt:
                            details["expired"] = True
                    except Exception:
                        pass
                        
                # Subject Alt Names
                details["subject_alt_names"] = [
                    v for k, v in cert.get("subjectAltName", [])
                    if k == "DNS"
                ]
                
                # Self-signed detection: if issuer equals subject
                subject_parts = []
                for rdns in cert.get("subject", []):
                    for k, v in rdns:
                        if k == "commonName" or k == "organizationName":
                            subject_parts.append(v)
                subject_str = ", ".join(subject_parts) if subject_parts else "Unknown"
                if subject_str == details["issuer"] and subject_str != "Unknown":
                    details["self_signed"] = True

        except ssl.SSLError as e:
            # SSL validation issue (like expired, self-signed, invalid chain)
            details["validation_error"] = str(e)
            if "self signed" in str(e).lower():
                details["self_signed"] = True
            elif "expired" in str(e).lower():
                details["expired"] = True
        except Exception as e:
            # Connection errors, port closed, timeout, etc.
            latency = (time.perf_counter() - start_time) * 1000.0
            return ProviderResult(
                provider_name="Certificate",
                provider_status="UNAVAILABLE",
                evidence=[],
                lookup_time_ms=latency,
                error_message=str(e)
            )

        latency = (time.perf_counter() - start_time) * 1000.0
        
        # Generate informational telemetry evidence
        evidence_list.append(ThreatEvidence(
            provider="Certificate",
            observable=domain,
            observable_type="Domain",
            classification="clean",
            severity="INFO",
            provider_confidence=1.0,
            technical_details=details,
            metadata={"version": "1.0.0", "lookup_latency_ms": latency}
        ))
        
        return ProviderResult(
            provider_name="Certificate",
            provider_status="SUCCESS",
            evidence=evidence_list,
            lookup_time_ms=latency,
            cache_hit=False
        )
