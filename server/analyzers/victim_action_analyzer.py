from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class VictimActionAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        if context.victim_actions:
            evidence_list.append(create_evidence(
                analyzer_name="VictimActionAnalyzer",
                rule_id="SEM_002",
                technical_details={
                    "technique_detected": "Victim Action Extraction",
                    "victim_action_identified": ", ".join(context.victim_actions),
                    "explainability_summary": f"Detected expected victim actions: {', '.join(context.victim_actions)}"
                },
                confidence=0.85
            ))
        return evidence_list
