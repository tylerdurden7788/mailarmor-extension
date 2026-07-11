from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class CEOFraudAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        has_ceo = any("ceo" in f.context_snippet.lower() or "president" in f.context_snippet.lower() for f in context.features if f.category == "identity")
        has_urgency = "Urgency" in context.soc_eng_techniques
        
        if has_ceo and has_urgency:
            evidence_list.append(create_evidence(
                analyzer_name="CEOFraudAnalyzer",
                rule_id="SEM_008",
                technical_details={
                    "technique_detected": "CEO Fraud / Executive Impersonation",
                    "objective_inferred": "Executive Task Compliance",
                    "victim_action_identified": "Perform urgent transaction",
                    "explainability_summary": "Detected executive-level persona claiming high urgency and authority."
                },
                confidence=0.95
            ))
        return evidence_list
