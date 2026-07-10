import re
from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from scanner.evidence import create_evidence

class SenderAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        
        # 1. Reply-To versus From address mismatch
        from_email = email.from_header.lower()
        reply_to_email = email.reply_to.lower()
        
        # Parse clean email address inside brackets if any
        from_match = re.search(r'<([^>]+)>', from_email)
        from_addr = from_match.group(1) if from_match else from_email
        
        reply_match = re.search(r'<([^>]+)>', reply_to_email)
        reply_addr = reply_match.group(1) if reply_match else reply_to_email
        
        if reply_addr and from_addr and reply_addr.strip() != from_addr.strip():
            evidence_list.append(create_evidence(
                analyzer_name="SenderAnalyzer",
                rule_id="SND_001",
                technical_details={"from_address": from_addr, "reply_to_address": reply_addr}
            ))
            
        # 2. Display Name Corporate/System Role Spoofing (e.g., support, alert, account)
        sender_display_name = ""
        match = re.search(r'^(.*?)\s*<', email.from_header)
        if match:
            sender_display_name = match.group(1).strip(' \'"')
            
        suspicious_roles = ["support", "security", "billing", "admin", "accounts", "service", "system"]
        for role in suspicious_roles:
            if role in sender_display_name.lower():
                evidence_list.append(create_evidence(
                    analyzer_name="SenderAnalyzer",
                    rule_id="SND_002",
                    technical_details={"display_name": sender_display_name, "flagged_keyword": role}
                ))
                break
                
        return evidence_list
