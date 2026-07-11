from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class CryptocurrencyScamAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        has_crypto = any(f.value == "alternative_payment" for f in context.features if f.category == "financial")
        
        if has_crypto:
            evidence_list.append(create_evidence(
                analyzer_name="CryptocurrencyScamAnalyzer",
                rule_id="SEM_018",
                technical_details={
                    "technique_detected": "Cryptocurrency Redirection Scam",
                    "objective_inferred": "Alternative Asset redirection",
                    "victim_action_identified": "Transfer digital assets",
                    "explainability_summary": "Detected instructions requesting payments to crypto wallet addresses."
                },
                confidence=0.85
            ))
        return evidence_list
