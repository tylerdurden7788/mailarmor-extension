import re
from urllib.parse import urlparse
from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from scanner.evidence import create_evidence
from utils.domain_utils import extract_domain
from utils.unicode_utils import is_mixed_script, punycode_decode, get_confusables_count

class UnicodeAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        
        # Helper set of domains checked to avoid duplicate checks in this analyzer run
        domains_checked = set()
        
        # 1. Inspect sender domain
        from_domain = extract_domain(email.from_header)
        if from_domain:
            self._check_domain_unicode(from_domain, "sender_domain", evidence_list, domains_checked)
            
        # 2. Inspect all hyperlink URLs
        for link in email.urls:
            try:
                parsed = urlparse(link.actual_url)
                host = parsed.hostname or ""
                if host:
                    self._check_domain_unicode(host.lower(), "hyperlink_host", evidence_list, domains_checked)
            except Exception:
                pass
                
        return evidence_list

    def _check_domain_unicode(self, domain: str, source: str, evidence_list: list, checked: set) -> None:
        if domain in checked:
            return
        checked.add(domain)
        
        decoded = punycode_decode(domain)
        is_mixed = is_mixed_script(decoded)
        confusables = get_confusables_count(decoded)
        is_puny = domain.lower().startswith("xn--")
        
        if is_mixed or confusables > 0:
            # Active homoglyph / mixed script attack
            # High confidence calculation
            confidence = 0.98 if is_puny else 0.90
            
            # Retrieve character codes for explanation
            char_details = [f"{c}(U+{ord(c):04X})" for c in decoded if ord(c) > 127]
            
            evidence_list.append(create_evidence(
                analyzer_name="UnicodeAnalyzer",
                rule_id="UNI_001",
                technical_details={
                    "raw_domain": domain,
                    "decoded_unicode": decoded,
                    "source": source,
                    "is_mixed_script": is_mixed,
                    "confusables_count": confusables,
                    "non_ascii_characters": char_details,
                    "confidence_justification": f"Very High confidence ({confidence}): domain '{decoded}' mixes writing scripts or uses confusable letters (e.g. Cyrillic lookalikes)."
                },
                confidence=confidence
            ))
        elif is_puny:
            # Normal Punycode domain
            evidence_list.append(create_evidence(
                analyzer_name="UnicodeAnalyzer",
                rule_id="UNI_002",
                technical_details={
                    "raw_domain": domain,
                    "decoded_unicode": decoded,
                    "source": source,
                    "confidence_justification": "Medium confidence (0.70): Punycode domain detected. Requires visibility check since IDN domains are less common for official services."
                },
                confidence=0.70
            ))
