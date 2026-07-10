import re
from urllib.parse import urlparse
from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from scanner.evidence import create_evidence
from utils.url_utils import is_ip_address_url, is_shortened_url

class UrlAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        
        for link in email.urls:
            # 1. Display versus Actual mismatch check
            if link.has_mismatch:
                evidence_list.append(create_evidence(
                    analyzer_name="UrlAnalyzer",
                    rule_id="URL_001",
                    technical_details={"actual_url": link.actual_url, "display_text": link.display_text}
                ))
                
            # 2. Raw IP address URLs check
            if is_ip_address_url(link.actual_url):
                evidence_list.append(create_evidence(
                    analyzer_name="UrlAnalyzer",
                    rule_id="URL_002",
                    technical_details={"url": link.actual_url}
                ))
                
            # 3. URL Shortener check
            if is_shortened_url(link.actual_url):
                evidence_list.append(create_evidence(
                    analyzer_name="UrlAnalyzer",
                    rule_id="URL_003",
                    technical_details={"url": link.actual_url}
                ))
                
            # 4. HTTPS usage check
            if link.actual_url.lower().startswith("http://"):
                evidence_list.append(create_evidence(
                    analyzer_name="UrlAnalyzer",
                    rule_id="URL_005",
                    technical_details={"url": link.actual_url}
                ))
                
            # 5. Path complexity & credential parameter leakage
            parsed = urlparse(link.actual_url)
            query = parsed.query.lower()
            if any(p in query for p in ["email=", "user=", "token=", "pass=", "pwd="]):
                evidence_list.append(create_evidence(
                    analyzer_name="UrlAnalyzer",
                    rule_id="URL_004",
                    technical_details={"url": link.actual_url, "matched_query": parsed.query}
                ))
                
        return evidence_list
