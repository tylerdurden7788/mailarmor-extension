import re
from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from scanner.evidence import create_evidence
from utils.domain_utils import extract_domain
from config.trusted_org_registry import TRUSTED_ORGANIZATIONS, find_organization_by_name, find_organization_by_domain

class BrandAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        
        # 1. Parse clean sender details
        from_raw = email.from_header
        sender_display_name = ""
        from_email = ""
        
        match = re.search(r'^(.*?)\s*<([^>]+)>', from_raw)
        if match:
            sender_display_name = match.group(1).strip(' \'"')
            from_email = match.group(2).strip()
        else:
            from_email = from_raw.strip()
            
        from_domain = extract_domain(from_email)
        if not from_domain:
            return evidence_list
            
        # 2. Check for Brand Impersonation using TRUSTED_ORGANIZATIONS registry
        if sender_display_name:
            # See if the display name matches any trusted brand
            org_key, org_info = find_organization_by_name(sender_display_name)
            if org_key:
                # Check if From domain belongs to this organization
                sender_org_key, _ = find_organization_by_domain(from_domain)
                if sender_org_key != org_key:
                    # Unofficial domain claiming brand display name!
                    # Calculate dynamic confidence: if domain looks like the brand (typosquatting simulation)
                    confidence = 0.90
                    is_lookalike = org_key in from_domain.lower()
                    if is_lookalike:
                        confidence = 0.95 # Higher confidence due to active domain lookalike
                        
                    evidence_list.append(create_evidence(
                        analyzer_name="BrandAnalyzer",
                        rule_id="BRD_001",
                        technical_details={
                            "claimed_brand": org_key,
                            "display_name": sender_display_name,
                            "sender_domain": from_domain,
                            "is_lookalike_domain": is_lookalike,
                            "confidence_justification": f"Very High confidence: display name claims brand '{org_info['org_name']}', but domain '{from_domain}' is not registered under official, regional or historical lists."
                        },
                        confidence=confidence
                    ))
                    
                    # Check if the display name claims a specific trusted department (e.g. Billing, Security)
                    for dept in org_info["trusted_departments"]:
                        if dept in sender_display_name.lower():
                            evidence_list.append(create_evidence(
                                analyzer_name="BrandAnalyzer",
                                rule_id="BRD_002",
                                technical_details={
                                    "claimed_brand": org_key,
                                    "claimed_department": dept,
                                    "display_name": sender_display_name,
                                    "sender_domain": from_domain,
                                    "confidence_justification": f"Very High confidence: display name claims department '{dept}' of '{org_info['org_name']}' on unofficial domain '{from_domain}'."
                                },
                                confidence=0.95
                            ))
                            break
                            
        return evidence_list
