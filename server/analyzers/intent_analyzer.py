from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class IntentAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        if context.intents:
            evidence_list.append(create_evidence(
                analyzer_name="IntentAnalyzer",
                rule_id="SEM_001",
                technical_details={
                    "technique_detected": "Intent Classification",
                    "objective_inferred": ", ".join(context.intents),
                    "explainability_summary": f"Classified semantic intents: {', '.join(context.intents)}"
                },
                confidence=0.85
            ))
        return evidence_list
