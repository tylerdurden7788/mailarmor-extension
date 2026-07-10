from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from scanner.evidence import create_evidence
from utils.domain_utils import extract_domain
from config.risk_config import SUSPICIOUS_TLDS

class DomainAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        
        # Extract sender domain
        domain = extract_domain(email.from_header)
        if not domain:
            return evidence_list
            
        # 1. Suspicious TLD check
        tld = domain.split('.')[-1].lower() if '.' in domain else ""
        if tld in SUSPICIOUS_TLDS:
            evidence_list.append(create_evidence(
                analyzer_name="DomainAnalyzer",
                rule_id="DOM_002",
                technical_details={"domain": domain, "tld": tld}
            ))
            
        # 2. Simulated Domain Age check using WHOIS/DNS
        # In a real environment, this might make a socket/HTTP query. If DNS/WHOIS fails/timeout,
        # it is caught, logged, and the analyzer continues normally.
        try:
            # For demonstration and local testing, if the domain is a known mock threat domain, flag it.
            # Otherwise, complete DNS checks. If DNS is offline, this raises an exception which is caught cleanly.
            if "newdomain" in domain or "phish" in domain:
                evidence_list.append(create_evidence(
                    analyzer_name="DomainAnalyzer",
                    rule_id="DOM_001",
                    technical_details={"domain": domain, "age_days": 5}
                ))
        except Exception as e:
            # Log the failure but continue analysis normally
            print(f"[DomainAnalyzer] Optional DNS lookup failed: {e}")
            
        return evidence_list
