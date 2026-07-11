from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class AccountTakeoverAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        has_lock = any("lock" in f.context_snippet.lower() or "suspend" in f.context_snippet.lower() for f in context.features if f.category == "urgency")
        has_auth = any(f.value == "auth_factor" for f in context.features if f.category == "credential")
        
        if has_lock and has_auth:
            evidence_list.append(create_evidence(
                analyzer_name="AccountTakeoverAnalyzer",
                rule_id="SEM_010",
                technical_details={
                    "technique_detected": "Account Takeover Prevention Scam",
                    "objective_inferred": "Account Recovery/Reactivation",
                    "victim_action_identified": "Input login factors",
                    "explainability_summary": "Detected account security lock pretext asking user to confirm password details."
                },
                confidence=0.80
            ))
        return evidence_list
