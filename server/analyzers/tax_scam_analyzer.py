from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class TaxScamAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        text_lower = context.canonicalized_text.lower()
        is_gov = any(kw in text_lower for kw in ["irs", "tax refund", "revenue service", "government audit"])
        has_action = any(act in context.victim_actions for act in ["Log in", "Enter password", "Transfer money"])
        
        if is_gov and (has_action or "Fear" in context.soc_eng_techniques):
            evidence_list.append(create_evidence(
                analyzer_name="TaxScamAnalyzer",
                rule_id="SEM_022",
                technical_details={
                    "technique_detected": "IRS / Tax Government Scam",
                    "objective_inferred": "Credential Harvesting or Fine Collection",
                    "victim_action_identified": "Verify details or make payment",
                    "explainability_summary": "Detected tax/IRS impersonation alert demanding immediate payment or details input."
                },
                confidence=0.85
            ))
        return evidence_list
