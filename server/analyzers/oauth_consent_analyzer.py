from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class OAuthConsentAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        has_oauth = "OAuth Consent" in context.intents or "Approve OAuth" in context.victim_actions
        
        if has_oauth:
            evidence_list.append(create_evidence(
                analyzer_name="OAuthConsentAnalyzer",
                rule_id="SEM_011",
                technical_details={
                    "technique_detected": "OAuth Consent Phishing",
                    "objective_inferred": "Third-Party App Scope Grant",
                    "victim_action_identified": "Approve application scopes",
                    "explainability_summary": "Detected semantic intent to grant mailbox or file read privileges to third-party app."
                },
                confidence=0.90
            ))
        return evidence_list
