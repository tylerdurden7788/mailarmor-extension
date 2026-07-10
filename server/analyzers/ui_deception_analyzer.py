from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.html_model import HTMLContext, DOMNode
from scanner.evidence import create_evidence
from utils.domain_utils import extract_domain
from config.trusted_org_registry import TRUSTED_ORGANIZATIONS

class UIDeceptionAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, HTMLContext) or not context.root_node:
            return evidence_list
            
        root = context.root_node
        metadata = {
            "analyzer_version": "2.0.0",
            "rule_version": "2.0.0",
            "data_source": "DOM HTML Text & Element Layouts"
        }
        
        sender_domain = extract_domain(email.from_header)
        
        # 1. Check: Visual Impersonation (HTML_008)
        # Search for brand names in raw text
        email_text = f"{email.subject} {root.inner_text}".lower()
        impersonated_brand = None
        
        for brand_key, brand_info in TRUSTED_ORGANIZATIONS.items():
            aliases = brand_info.get("aliases", [])
            matched_alias = None
            for alias in aliases:
                if alias in email_text:
                    matched_alias = alias
                    break
                    
            if matched_alias:
                official_domains = brand_info.get("official_domains", [])
                regional_domains = brand_info.get("regional_domains", [])
                all_official = set(official_domains + regional_domains)
                
                if sender_domain not in all_official:
                    impersonated_brand = brand_key
                    break
                    
        if impersonated_brand:
            evidence_list.append(create_evidence(
                analyzer_name="UIDeceptionAnalyzer",
                rule_id="HTML_008",
                technical_details={
                    "impersonated_brand": impersonated_brand,
                    "sender_domain": sender_domain,
                    "metadata": metadata
                },
                confidence=0.90
            ))
            
        # 2. Check: Deceptive visual widgets (like lock emoji secure badge tricks)
        lock_emojis = ["🔒", "🔑", "🛡️", "⚠️"]
        lock_findings = []
        
        def traverse_text(node: DOMNode):
            text = node.inner_text
            if any(le in text for le in lock_emojis):
                # Flag visual deception indicators
                if any(kw in text.lower() for kw in ["secure", "verify", "safety", "alert", "password"]):
                    lock_findings.append({
                        "tag": node.tag,
                        "text": text,
                        "dom_path": node.dom_path
                    })
            for child in node.children:
                traverse_text(child)
                
        traverse_text(root)
        
        if lock_findings:
            evidence_list.append(create_evidence(
                analyzer_name="UIDeceptionAnalyzer",
                rule_id="HTML_008",
                technical_details={
                    "deceptive_elements": lock_findings,
                    "metadata": metadata
                },
                confidence=0.75
            ))
            
        return evidence_list
