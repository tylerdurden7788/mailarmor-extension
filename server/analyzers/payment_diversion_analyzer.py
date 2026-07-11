from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class PaymentDiversionAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        is_diversion = "Payment Diversion" in context.intents
        has_action = "Update banking information" in context.victim_actions
        
        if is_diversion or has_action:
            evidence_list.append(create_evidence(
                analyzer_name="PaymentDiversionAnalyzer",
                rule_id="SEM_007",
                technical_details={
                    "technique_detected": "Payment Diversion",
                    "objective_inferred": "Bank Account Redirection",
                    "victim_action_identified": "Update routing/account numbers",
                    "explainability_summary": "Detected instructions requesting revision of bank account routing details."
                },
                confidence=0.90
            ))
        return evidence_list
