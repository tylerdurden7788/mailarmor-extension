from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class BankingScamAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        text_lower = context.canonicalized_text.lower()
        sender_raw = email.from_header.lower() if email.from_header else ""
        is_bank = any(kw in text_lower or kw in sender_raw for kw in ["bank", "chase", "wells fargo", "citi", "bank of america"])
        has_auth = any(f.value == "auth_factor" for f in context.features if f.category == "credential")
        
        if is_bank and has_auth:
            evidence_list.append(create_evidence(
                analyzer_name="BankingScamAnalyzer",
                rule_id="SEM_016",
                technical_details={
                    "technique_detected": "Banking Impersonation Scam",
                    "objective_inferred": "Credential Harvesting",
                    "victim_action_identified": "Log in to secure portal",
                    "explainability_summary": "Detected bank notification requesting account confirmation or security code entry."
                },
                confidence=0.85
            ))
        return evidence_list
