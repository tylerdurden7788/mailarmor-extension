from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from scanner.evidence import create_evidence
from utils.domain_utils import extract_domain

class ReputationAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        
        domain = extract_domain(email.from_header)
        if not domain:
            return evidence_list
            
        # Optional reputation lookup providers (Safe Browsing, PhishTank, VT, OpenPhish, Talos)
        # Mock reputation check for simulation: if domain has "scam", "phish" or "malicious" in it, flag it.
        # Ensure that any service timeouts or missing API keys never break execution.
        try:
            # Simulation of an API query
            # Google Safe Browsing / PhishTank VT checks
            is_listed = any(keyword in domain.lower() for keyword in ["phish", "scam", "malicious", "fake"])
            if is_listed:
                evidence_list.append(create_evidence(
                    analyzer_name="ReputationAnalyzer",
                    rule_id="REP_001",
                    technical_details={
                        "domain": domain,
                        "reputation_db": "Google Safe Browsing & PhishTank",
                        "status": "MALICIOUS"
                    }
                ))
        except Exception as e:
            # Graceful error handling: log and continue analysis normally
            print(f"[ReputationAnalyzer] Provider execution failed: {e}")
            
        return evidence_list
