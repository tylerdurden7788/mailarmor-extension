from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class InvestmentScamAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        text_lower = context.canonicalized_text.lower()
        is_investment = any(kw in text_lower for kw in ["investment", "stocks", "trading", "profit", "shares", "returns"])
        has_greed = "Greed" in context.soc_eng_techniques
        
        if is_investment and has_greed:
            evidence_list.append(create_evidence(
                analyzer_name="InvestmentScamAnalyzer",
                rule_id="SEM_017",
                technical_details={
                    "technique_detected": "Investment / Get-Rich-Quick Scam",
                    "objective_inferred": "Asset transfer",
                    "victim_action_identified": "Register or transfer capital",
                    "explainability_summary": "Detected high-yield profit pretext seeking capital funding."
                },
                confidence=0.80
            ))
        return evidence_list
