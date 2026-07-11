from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class QRPhishingAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        has_qr_action = "Scan QR code" in context.victim_actions
        
        if has_qr_action:
            evidence_list.append(create_evidence(
                analyzer_name="QRPhishingAnalyzer",
                rule_id="SEM_013",
                technical_details={
                    "technique_detected": "QR Code Phishing (Quishing)",
                    "objective_inferred": "Scan offline link redirection",
                    "victim_action_identified": "Scan mobile code matrix",
                    "explainability_summary": "Detected instructions requesting user to scan QR image to proceed."
                },
                confidence=0.85
            ))
        return evidence_list
