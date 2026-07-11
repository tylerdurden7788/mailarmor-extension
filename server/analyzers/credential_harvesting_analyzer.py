from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class CredentialHarvestingAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        is_cred_intent = "Credential Collection" in context.intents
        has_login_action = any(act in context.victim_actions for act in ["Log in", "Enter password", "Enter OTP"])
        
        if is_cred_intent or has_login_action:
            # Check false positive protection: verified domain
            # (In production we'd bypass if SPF/DKIM is valid and matches official brand)
            evidence_list.append(create_evidence(
                analyzer_name="CredentialHarvestingAnalyzer",
                rule_id="SEM_004",
                technical_details={
                    "technique_detected": "Credential Harvesting",
                    "objective_inferred": "Credential Collection",
                    "victim_action_identified": "Input credentials",
                    "explainability_summary": "Detected prompt seeking user log-in credentials or authentication factors."
                },
                confidence=0.85
            ))
        return evidence_list
