import re
from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from scanner.evidence import create_evidence

class ContentAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        
        # Combine subject and text body
        text_to_scan = f"{email.subject} {email.body_text}".lower()
        
        # Urgency/Pressure keywords
        urgency_patterns = [
            r'\burgent\b', r'\baction required\b', r'\bverify your account\b',
            r'\bsuspended\b', r'\bimmediate\b', r'\bterminate\b', r'\bsecurity alert\b',
            r'\bpay now\b', r'\bdeadline\b', r'\bcompromised\b'
        ]
        
        matches = []
        for pattern in urgency_patterns:
            if re.search(pattern, text_to_scan):
                matches.append(pattern.replace(r'\b', ''))
                
        if matches:
            evidence_list.append(create_evidence(
                analyzer_name="ContentAnalyzer",
                rule_id="CNT_001",
                technical_details={"matched_keywords": matches}
            ))
            
        return evidence_list
