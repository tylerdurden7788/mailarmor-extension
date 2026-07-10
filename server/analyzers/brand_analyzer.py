import re
from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from scanner.evidence import create_evidence
from utils.domain_utils import extract_domain
from config.brand_registry import BRAND_REGISTRY

class BrandAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        
        # Extract sender domain
        domain = extract_domain(email.from_header)
        if not domain:
            return evidence_list
            
        # Get sender display name
        sender_display_name = ""
        match = re.search(r'^(.*?)\s*<', email.from_header)
        if match:
            sender_display_name = match.group(1).strip(' \'"')
            
        for brand_name, brand_info in BRAND_REGISTRY.items():
            official_domains = brand_info.get("official_domains", [])
            display_names = brand_info.get("display_names", [])
            
            # Check if brand keywords are in display name or if domain contains brand name but is unofficial
            brand_in_display = any(name.lower() in sender_display_name.lower() for name in display_names)
            brand_in_domain = brand_name.lower() in domain.lower()
            
            if brand_in_display or brand_in_domain:
                # If it matches, check if the sender domain is in official_domains list
                is_official = domain.lower() in [d.lower() for d in official_domains]
                if not is_official:
                    evidence_list.append(create_evidence(
                        analyzer_name="BrandAnalyzer",
                        rule_id="BRD_001",
                        technical_details={
                            "brand_spoofed": brand_name,
                            "display_name": sender_display_name,
                            "sender_domain": domain,
                            "official_domains": official_domains
                        }
                    ))
                    
        return evidence_list
