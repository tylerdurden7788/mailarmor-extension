from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class PayrollFraudAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        has_payroll = "Update payroll" in context.victim_actions
        has_deposit = any("deposit" in f.context_snippet.lower() or "salary" in f.context_snippet.lower() for f in context.features if f.category == "financial")
        
        if has_payroll or (has_deposit and "routing" in context.canonicalized_text.lower()):
            evidence_list.append(create_evidence(
                analyzer_name="PayrollFraudAnalyzer",
                rule_id="SEM_009",
                technical_details={
                    "technique_detected": "Payroll Direct Deposit Fraud",
                    "objective_inferred": "Salary redirection",
                    "victim_action_identified": "Update salary deposit routing",
                    "explainability_summary": "Detected request seeking payroll direct deposit routing updates."
                },
                confidence=0.85
            ))
        return evidence_list
