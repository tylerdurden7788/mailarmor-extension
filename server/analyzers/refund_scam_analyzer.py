from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class RefundScamAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        text_lower = context.canonicalized_text.lower()
        is_refund = "refund" in text_lower or "overcharge" in text_lower or "reimbursement" in text_lower
        has_login = "Log in" in context.victim_actions
        
        if is_refund and has_login:
            evidence_list.append(create_evidence(
                analyzer_name="RefundScamAnalyzer",
                rule_id="SEM_023",
                technical_details={
                    "technique_detected": "Refund Processing Scam",
                    "objective_inferred": "Credential Harvesting",
                    "victim_action_identified": "Log in to claim refund",
                    "explainability_summary": "Detected refund opportunity claiming overcharge requires secure login verification."
                },
                confidence=0.80
            ))
        return evidence_list
