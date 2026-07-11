from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class RomanceScamAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        text_lower = context.canonicalized_text.lower()
        is_romance = any(kw in text_lower for kw in ["love", "dear", "sweetheart", "meet you", "lonely", "dating"])
        has_money = any(kw in text_lower for kw in ["transfer", "send", "money", "bank", "cash", "pay", "help"])
        
        if is_romance and has_money:
            evidence_list.append(create_evidence(
                analyzer_name="RomanceScamAnalyzer",
                rule_id="SEM_019",
                technical_details={
                    "technique_detected": "Romance / Emotional Pretext Scam",
                    "objective_inferred": "Financial relief request",
                    "victim_action_identified": "Transfer funds to online contact",
                    "explainability_summary": "Detected emotional relationship hook seeking cash transfers."
                },
                confidence=0.80
            ))
        return evidence_list
