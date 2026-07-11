from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class BusinessEmailCompromiseAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        is_bec = "Payment Diversion" in context.intents or "Update payroll" in context.victim_actions
        has_authority = "Authority" in context.soc_eng_techniques
        
        if is_bec and has_authority:
            evidence_list.append(create_evidence(
                analyzer_name="BusinessEmailCompromiseAnalyzer",
                rule_id="SEM_005",
                technical_details={
                    "technique_detected": "Business Email Compromise",
                    "objective_inferred": "Payment Diversion / Financial Fraud",
                    "victim_action_identified": "Update accounts or process wires",
                    "explainability_summary": "Detected internal business pretexting attempting to divert financial assets."
                },
                confidence=0.90
            ))
        return evidence_list
