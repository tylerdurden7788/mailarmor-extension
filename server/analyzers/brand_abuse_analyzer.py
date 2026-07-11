from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

from utils.domain_utils import extract_domain

class BrandAbuseAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        text_lower = context.canonicalized_text.lower()
        # Find mentioned brands
        brands = ["microsoft", "paypal", "netflix", "amazon", "google", "chase", "fedex"]
        matched_brands = [b for b in brands if b in text_lower]
        
        # In brand abuse, brand is mentioned but the sender domain does not match the brand's official domain
        sender_domain = extract_domain(email.from_header).lower() if email.from_header else ""
        
        abuse_detected = False
        abused_brand = ""
        
        for brand in matched_brands:
            if brand not in sender_domain:
                abuse_detected = True
                abused_brand = brand
                break
                
        if abuse_detected and ("Authority" in context.soc_eng_techniques or "Urgency" in context.soc_eng_techniques):
            evidence_list.append(create_evidence(
                analyzer_name="BrandAbuseAnalyzer",
                rule_id="SEM_026",
                technical_details={
                    "technique_detected": "Brand Abuse / Logo Hijack",
                    "objective_inferred": "Authority Leverage / Trust spoofs",
                    "victim_action_identified": "Log in to brand portal",
                    "explainability_summary": f"Detected authority pretext referencing '{abused_brand}' sending from mismatching domain '{sender_domain}'."
                },
                confidence=0.85
            ))
        return evidence_list
