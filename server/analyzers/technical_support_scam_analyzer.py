from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class TechnicalSupportScamAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        has_support = any("support" in f.context_snippet.lower() or "helpdesk" in f.context_snippet.lower() for f in context.features if f.category == "identity")
        has_fear = "Fear" in context.soc_eng_techniques
        
        if has_support and has_fear:
            evidence_list.append(create_evidence(
                analyzer_name="TechnicalSupportScamAnalyzer",
                rule_id="SEM_014",
                technical_details={
                    "technique_detected": "Technical Support Scam",
                    "objective_inferred": "Remote access installation",
                    "victim_action_identified": "Contact IT Support / Install Remote software",
                    "explainability_summary": "Detected virus alert or IT helpdesk spoof requesting user action."
                },
                confidence=0.80
            ))
        return evidence_list
