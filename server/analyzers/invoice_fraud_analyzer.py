from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class InvoiceFraudAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        is_invoice = "Invoice Approval" in context.intents
        has_urgency = "Urgency" in context.soc_eng_techniques
        
        if is_invoice and has_urgency:
            evidence_list.append(create_evidence(
                analyzer_name="InvoiceFraudAnalyzer",
                rule_id="SEM_006",
                technical_details={
                    "technique_detected": "Invoice Fraud",
                    "objective_inferred": "Invoice Payment Approval",
                    "victim_action_identified": "Process billing payment",
                    "explainability_summary": "Detected request seeking immediate processing of past-due billing invoice."
                },
                confidence=0.85
            ))
        return evidence_list
