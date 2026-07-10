import re
from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from scanner.evidence import create_evidence

class HtmlAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        
        body_html = email.body_html or ""
        
        # 1. Password input/Credential forms check
        has_password_form = any(form.has_password_input for form in email.forms)
        # Fallback check using raw HTML text regex in case form structures were incomplete
        if not has_password_form:
            if re.search(r'type=["\']password["\']', body_html, re.IGNORECASE):
                has_password_form = True
                
        if has_password_form:
            evidence_list.append(create_evidence(
                analyzer_name="HtmlAnalyzer",
                rule_id="HTML_001",
                technical_details={"has_password_fields": True}
            ))
            
        # 2. JavaScript redirects & Meta refresh checks
        # Detect meta refresh
        has_meta_refresh = False
        if re.search(r'http-equiv=["\']refresh["\']', body_html, re.IGNORECASE):
            has_meta_refresh = True
            
        # Detect js redirects
        has_js_redirect = False
        js_patterns = [r'window\.location', r'location\.replace', r'location\.href', r'document\.location']
        if any(re.search(pat, body_html, re.IGNORECASE) for pat in js_patterns):
            has_js_redirect = True
            
        if has_meta_refresh or has_js_redirect:
            evidence_list.append(create_evidence(
                analyzer_name="HtmlAnalyzer",
                rule_id="HTML_002",
                technical_details={
                    "meta_refresh": has_meta_refresh,
                    "javascript_redirect": has_js_redirect
                }
            ))
            
        # 3. Hidden CSS overlay / invisible text detection
        has_css_hiding = False
        css_patterns = [
            r'display:\s*none', r'visibility:\s*hidden', 
            r'font-size:\s*0px', r'opacity:\s*0',
            r'color:\s*#ffffff', r'color:\s*white' # White-on-white text hiding
        ]
        if any(re.search(pat, body_html, re.IGNORECASE) for pat in css_patterns):
            has_css_hiding = True
            
        if has_css_hiding:
            evidence_list.append(create_evidence(
                analyzer_name="HtmlAnalyzer",
                rule_id="HTML_003",
                technical_details={"css_hiding_detected": True}
            ))
            
        return evidence_list
