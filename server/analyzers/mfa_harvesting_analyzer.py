from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class MFAHarvestingAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        has_mfa_action = any(act in context.victim_actions for act in ["Enter OTP", "Approve MFA"])
        
        if has_mfa_action:
            evidence_list.append(create_evidence(
                analyzer_name="MFAHarvestingAnalyzer",
                rule_id="SEM_012",
                technical_details={
                    "technique_detected": "MFA / OTP Harvesting",
                    "objective_inferred": "Session Takeover Bypass",
                    "victim_action_identified": "Provide verification token",
                    "explainability_summary": "Detected pretext requesting entry of OTP codes or approving push codes."
                },
                confidence=0.85
            ))
        return evidence_list
