from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class JobScamAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        text_lower = context.canonicalized_text.lower()
        is_job = any(kw in text_lower for kw in ["hiring", "recruit", "work from home", "position", "career", "salary bonus"])
        has_check = "check" in text_lower or "deposit" in text_lower
        
        if is_job and has_check and "Greed" in context.soc_eng_techniques:
            evidence_list.append(create_evidence(
                analyzer_name="JobScamAnalyzer",
                rule_id="SEM_020",
                technical_details={
                    "technique_detected": "Job/Recruitment Scam",
                    "objective_inferred": "Check cashing fraud",
                    "victim_action_identified": "Deposit check or register info",
                    "explainability_summary": "Detected work-from-home hiring offer with cash-incentive check cashing."
                },
                confidence=0.80
            ))
        return evidence_list
