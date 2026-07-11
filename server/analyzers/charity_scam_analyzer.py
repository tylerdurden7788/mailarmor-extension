from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class CharityScamAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        text_lower = context.canonicalized_text.lower()
        is_charity = any(kw in text_lower for kw in ["donate", "disaster", "relief", "charity", "victim support", "contribution"])
        has_finance = any(f.value == "financial_reference" for f in context.features if f.category == "financial")
        
        if is_charity and has_finance:
            evidence_list.append(create_evidence(
                analyzer_name="CharityScamAnalyzer",
                rule_id="SEM_021",
                technical_details={
                    "technique_detected": "Charity Donation Scam",
                    "objective_inferred": "Fake NGO fundraising collection",
                    "victim_action_identified": "Donate funds to support cause",
                    "explainability_summary": "Detected urgent donation plea targeting fake crisis relief."
                },
                confidence=0.75
            ))
        return evidence_list
