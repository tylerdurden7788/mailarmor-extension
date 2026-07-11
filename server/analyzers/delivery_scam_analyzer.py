from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class DeliveryScamAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        text_lower = context.canonicalized_text.lower()
        is_delivery = any(brand in text_lower for brand in ["fedex", "ups", "usps", "dhl", "parcel", "shipment"])
        has_deadline = any(f.value == "deadline_indicator" for f in context.features if f.category == "urgency")
        
        if is_delivery and has_deadline:
            evidence_list.append(create_evidence(
                analyzer_name="DeliveryScamAnalyzer",
                rule_id="SEM_015",
                technical_details={
                    "technique_detected": "Parcel Delivery Scam",
                    "objective_inferred": "Address validation / Customs fee collection",
                    "victim_action_identified": "Input tracking details or pay fee",
                    "explainability_summary": "Detected shipping carrier notification demanding immediate action or address verification."
                },
                confidence=0.80
            ))
        return evidence_list
