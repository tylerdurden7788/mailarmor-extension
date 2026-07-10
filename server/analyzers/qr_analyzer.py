from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from scanner.evidence import create_evidence

class QRAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        # Reserved dedicated analyzer for QR-code phishing detection
        # Returns basic info telemetry about active status in this version
        return []
