from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class BlackmailExtortionAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        has_threat = any(f.value == "coercion_threat" for f in context.features if f.category == "scam_rewards")
        has_fear = "Fear" in context.soc_eng_techniques
        
        if has_threat and has_fear:
            evidence_list.append(create_evidence(
                analyzer_name="BlackmailExtortionAnalyzer",
                rule_id="SEM_025",
                technical_details={
                    "technique_detected": "Blackmail / Extortion Threat",
                    "objective_inferred": "Ransom Payment via Bitcoin",
                    "victim_action_identified": "Transfer bitcoin to ransom address",
                    "explainability_summary": "Detected extortion message threatening video leak or device lock demands."
                },
                confidence=0.90
            ))
        return evidence_list
