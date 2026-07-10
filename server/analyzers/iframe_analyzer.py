from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.html_model import HTMLContext
from scanner.evidence import create_evidence

class IframeAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, HTMLContext):
            return evidence_list
            
        iframes = context.iframes
        metadata = {
            "analyzer_version": "2.0.0",
            "rule_version": "2.0.0",
            "data_source": "DOM HTML Iframe Elements"
        }
        
        findings = []
        for iframe in iframes:
            is_clickjacking = False
            w = str(iframe.width or "").strip().lower()
            h = str(iframe.height or "").strip().lower()
            
            # Detect full page / full screen overlays
            if w in ["100%", "100vw"] or h in ["100%", "100vh"]:
                is_clickjacking = True
                
            findings.append({
                "src": iframe.src,
                "sandbox": iframe.sandbox,
                "is_hidden": iframe.is_hidden,
                "is_clickjacking": is_clickjacking,
                "dom_path": iframe.dom_path
            })
            
        if findings:
            evidence_list.append(create_evidence(
                analyzer_name="IframeAnalyzer",
                rule_id="HTML_004",
                technical_details={
                    "iframe_findings": findings,
                    "metadata": metadata
                },
                confidence=0.80
            ))
            
        return evidence_list
