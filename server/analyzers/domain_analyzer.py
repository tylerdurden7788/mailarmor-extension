import re
from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from scanner.evidence import create_evidence
from utils.domain_utils import extract_domain, is_valid_domain
from config.risk_config import SUSPICIOUS_TLDS

class DomainAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        
        # 1. Extract domain
        domain = extract_domain(email.from_header)
        if not domain:
            return evidence_list
            
        # 2. Check: Suspicious TLD
        tld = domain.split('.')[-1].lower() if '.' in domain else ""
        if tld in SUSPICIOUS_TLDS:
            evidence_list.append(create_evidence(
                analyzer_name="DomainAnalyzer",
                rule_id="DOM_002",
                technical_details={
                    "domain": domain,
                    "tld": tld,
                    "confidence_justification": f"Medium confidence: sender domain uses a high-risk suspicious TLD '{tld}'."
                },
                confidence=0.65
            ))
            
        # 3. Check: Excessive subdomains (label levels > 4)
        # E.g. sub3.sub2.sub1.domain.com -> 5 labels
        labels = domain.split('.')
        if len(labels) > 4:
            evidence_list.append(create_evidence(
                analyzer_name="DomainAnalyzer",
                rule_id="DOM_003",
                technical_details={
                    "domain": domain,
                    "subdomains_count": len(labels) - 2,
                    "confidence_justification": f"Low-medium confidence: domain '{domain}' has {len(labels) - 2} levels of nested subdomains."
                },
                confidence=0.50
            ))
            
        # 4. Check: Invalid hostname characters or structure anomalies
        # Allow punycode prefixes, but catch common anomalies (e.g. underscore in domain name labels, spaces, etc.)
        invalid_char_detected = False
        for part in labels:
            if not re.match(r'^[a-zA-Z0-9-]*$', part):
                invalid_char_detected = True
                break
                
        if invalid_char_detected or not is_valid_domain(domain):
            evidence_list.append(create_evidence(
                analyzer_name="DomainAnalyzer",
                rule_id="DOM_004",
                technical_details={
                    "domain": domain,
                    "confidence_justification": f"High confidence: domain '{domain}' contains malformed hostname formatting or invalid characters."
                },
                confidence=0.80
            ))

        # 5. Optional network lookups (WHOIS, DNS records)
        # These are designed to fail gracefully. In offline/mock mode, we catch exceptions.
        try:
            # Demonstration query triggers
            # If domain has "phish" or "newdomain", simulate a new registration flag
            if "newdomain" in domain or "phish" in domain:
                evidence_list.append(create_evidence(
                    analyzer_name="DomainAnalyzer",
                    rule_id="DOM_001",
                    technical_details={
                        "domain": domain,
                        "simulated_age_days": 5,
                        "confidence_justification": "Medium-high confidence: simulated WHOIS lookup indicates the domain was registered within 30 days."
                    },
                    confidence=0.75
                ))
        except Exception as e:
            # Gracefully log and proceed normally without interrupting the pipeline
            print(f"[DomainAnalyzer] Optional WHOIS/DNS lookup failed: {e}")
            
        return evidence_list
