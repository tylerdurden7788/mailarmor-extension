from urllib.parse import urlparse
from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.html_model import HTMLContext
from scanner.evidence import create_evidence
from utils.domain_utils import extract_domain
from config.trusted_org_registry import find_organization_by_domain

class FormAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, HTMLContext):
            return evidence_list
            
        forms = context.forms
        inputs = context.inputs
        
        metadata = {
            "analyzer_version": "2.0.0",
            "rule_version": "2.0.0",
            "data_source": "DOM HTML Form Elements"
        }
        
        sender_domain = extract_domain(email.from_header)
        
        for form in forms:
            has_password = any(inp.type == "password" for inp in form.inputs)
            has_text = any(inp.type in ["text", "email"] for inp in form.inputs)
            
            # Check: Form Action Target (HTML_001)
            action = form.action
            is_external = False
            action_domain = ""
            
            if action:
                try:
                    parsed = urlparse(action)
                    if parsed.netloc:
                        action_domain = extract_domain(parsed.netloc)
                        if action_domain != sender_domain:
                            is_external = True
                except Exception:
                    pass
                    
            # Avoid flagging OAuth callback targets or legitimate organization domains
            is_trusted_action = False
            if action_domain:
                org_key, _ = find_organization_by_domain(action_domain)
                if org_key or action_domain in {"google.com", "microsoft.com", "github.com", "paypal.com", "amazon.com"}:
                    is_trusted_action = True
                    
            # 1. Trigger form credential harvesting (HTML_001)
            if has_password:
                confidence = 0.60
                if is_external and not is_trusted_action:
                    confidence = 0.95 # External untrusted target + password field = Extremely high risk!
                    
                evidence_list.append(create_evidence(
                    analyzer_name="FormAnalyzer",
                    rule_id="HTML_001",
                    technical_details={
                        "form_action": action,
                        "action_domain": action_domain,
                        "is_external": is_external,
                        "is_trusted_action": is_trusted_action,
                        "has_password": has_password,
                        "inputs_count": len(form.inputs),
                        "dom_path": form.dom_path,
                        "metadata": metadata
                    },
                    confidence=confidence
                ))
                
            # 2. Check: Hidden inputs abuse (HTML_007)
            hidden_count = sum(1 for inp in form.inputs if inp.is_hidden)
            if hidden_count > 10:
                evidence_list.append(create_evidence(
                    analyzer_name="FormAnalyzer",
                    rule_id="HTML_007",
                    technical_details={
                        "form_action": action,
                        "hidden_inputs_count": hidden_count,
                        "dom_path": form.dom_path,
                        "metadata": metadata
                    },
                    confidence=0.55
                ))
                
        return evidence_list
