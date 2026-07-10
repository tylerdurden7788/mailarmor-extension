import re
from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from scanner.evidence import create_evidence

class AuthenticationAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        
        auth_headers = email.auth_headers or {}
        
        # Check if auth headers are available
        has_auth_info = False
        
        # 1. Inspect DMARC results
        dmarc_header = auth_headers.get("Authentication-Results", "")
        if dmarc_header:
            has_auth_info = True
            # Scan for dmarc=fail or dmarc=none
            if re.search(r'\bdmarc=fail\b', dmarc_header, re.IGNORECASE):
                evidence_list.append(create_evidence(
                    analyzer_name="AuthenticationAnalyzer",
                    rule_id="AUTH_001",
                    technical_details={"header": "Authentication-Results", "status": "dmarc=fail"}
                ))
                
        # 2. Inspect SPF / DKIM results
        spf_header = auth_headers.get("Received-SPF", "") or auth_headers.get("Authentication-Results", "")
        dkim_header = auth_headers.get("DKIM-Signature", "") or auth_headers.get("Authentication-Results", "")
        
        if spf_header or dkim_header:
            has_auth_info = True
            spf_fail = spf_header and re.search(r'\bspf=fail\b|\bspf=softfail\b', spf_header, re.IGNORECASE)
            dkim_fail = dkim_header and re.search(r'\bdkim=fail\b', dkim_header, re.IGNORECASE)
            
            if spf_fail or dkim_fail:
                evidence_list.append(create_evidence(
                    analyzer_name="AuthenticationAnalyzer",
                    rule_id="AUTH_002",
                    technical_details={
                        "spf_status": "fail/softfail" if spf_fail else "pass/none",
                        "dkim_status": "fail" if dkim_fail else "pass/none"
                    }
                ))
                
        # 3. Fallback behavior if auth headers are missing
        if not has_auth_info:
            evidence_list.append(create_evidence(
                analyzer_name="AuthenticationAnalyzer",
                rule_id="AUTH_003",
                technical_details={"message": "Authentication headers were omitted or stripped"}
            ))
            
        return evidence_list
