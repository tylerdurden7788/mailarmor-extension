from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.html_model import HTMLContext
from scanner.evidence import create_evidence

class MetaAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, HTMLContext):
            return evidence_list
            
        meta_tags = context.meta_tags
        base_tags = context.base_tags
        
        metadata = {
            "analyzer_version": "2.0.0",
            "rule_version": "2.0.0",
            "data_source": "DOM HTML Meta & Base Elements"
        }
        
        # 1. Check: Meta Refresh auto-redirect tags (HTML_009)
        meta_refreshes = []
        for meta in meta_tags:
            equiv = meta.get("http-equiv", "").lower()
            if equiv == "refresh":
                content = meta.get("content", "")
                meta_refreshes.append(content)
                
        if meta_refreshes:
            evidence_list.append(create_evidence(
                analyzer_name="MetaAnalyzer",
                rule_id="HTML_009",
                technical_details={
                    "meta_refreshes": meta_refreshes,
                    "metadata": metadata
                },
                confidence=0.85
            ))
            
        # 2. Check: Base URL overrides (HTML_009)
        if base_tags:
            evidence_list.append(create_evidence(
                analyzer_name="MetaAnalyzer",
                rule_id="HTML_009",
                technical_details={
                    "base_tags": base_tags,
                    "metadata": metadata
                },
                confidence=0.70
            ))
            
        return evidence_list
