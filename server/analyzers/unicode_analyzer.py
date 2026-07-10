from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from scanner.evidence import create_evidence
from utils.domain_utils import extract_domain
from utils.unicode_utils import is_mixed_script, punycode_decode, get_confusables_count

class UnicodeAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        
        # 1. Inspect sender domain for mixed-script homoglyphs
        domain = extract_domain(email.from_header)
        if domain:
            decoded = punycode_decode(domain)
            
            # Check for homoglyph / mixed script attacks
            if is_mixed_script(decoded) or get_confusables_count(decoded) > 0:
                evidence_list.append(create_evidence(
                    analyzer_name="UnicodeAnalyzer",
                    rule_id="UNI_001",
                    technical_details={
                        "raw_domain": domain,
                        "decoded_unicode": decoded,
                        "is_mixed_script": is_mixed_script(decoded),
                        "confusables_count": get_confusables_count(decoded)
                    }
                ))
            elif domain.lower().startswith("xn--"):
                # Punycode display warning
                evidence_list.append(create_evidence(
                    analyzer_name="UnicodeAnalyzer",
                    rule_id="UNI_002",
                    technical_details={"raw_domain": domain, "decoded_unicode": decoded}
                ))
                
        # 2. Inspect all hyperlink URLs
        for link in email.urls:
            try:
                # Extract hostname
                from urllib.parse import urlparse
                parsed = urlparse(link.actual_url)
                host = parsed.hostname or ""
                decoded_host = punycode_decode(host)
                
                if is_mixed_script(decoded_host) or get_confusables_count(decoded_host) > 0:
                    evidence_list.append(create_evidence(
                        analyzer_name="UnicodeAnalyzer",
                        rule_id="UNI_001",
                        technical_details={
                            "raw_url": link.actual_url,
                            "decoded_unicode_host": decoded_host,
                            "is_mixed_script": is_mixed_script(decoded_host),
                            "confusables_count": get_confusables_count(decoded_host)
                        }
                    ))
            except Exception:
                pass
                
        return evidence_list
