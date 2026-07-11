from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class SocialEngineeringAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        if context.soc_eng_techniques:
            evidence_list.append(create_evidence(
                analyzer_name="SocialEngineeringAnalyzer",
                rule_id="SEM_003",
                technical_details={
                    "technique_detected": "Social Engineering Tactics",
                    "manipulation_tactics": context.soc_eng_techniques,
                    "explainability_summary": f"Identified social engineering vectors: {', '.join(context.soc_eng_techniques)}"
                },
                confidence=0.85
            ))
        return evidence_list
