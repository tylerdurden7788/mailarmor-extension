from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.html_model import HTMLContext, DOMNode
from scanner.evidence import create_evidence

class DOMAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, HTMLContext) or not context.root_node:
            return evidence_list
            
        root = context.root_node
        warnings = context.parser_warnings
        perf = context.performance_metadata
        
        metadata = {
            "analyzer_version": "2.0.0",
            "rule_version": "2.0.0",
            "cache_status": "HIT" if perf.get("traversal_cache_hits", 0) > 0 else "MISS",
            "data_source": "DOM HTML Struct Parser"
        }
        
        # 1. Check: Parser warning or malformed DOM (HTML_007)
        if warnings:
            evidence_list.append(create_evidence(
                analyzer_name="DOMAnalyzer",
                rule_id="HTML_007",
                technical_details={
                    "parser_warnings": warnings,
                    "metadata": metadata
                },
                confidence=0.50
            ))
            
        # 2. Check: Duplicate Forms (HTML_007)
        if len(context.forms) > 1:
            evidence_list.append(create_evidence(
                analyzer_name="DOMAnalyzer",
                rule_id="HTML_007",
                technical_details={
                    "forms_count": len(context.forms),
                    "forms_actions": [f.action for f in context.forms],
                    "metadata": metadata
                },
                confidence=0.60
            ))
            
        # 3. Check: Excessive DOM nesting depth (HTML_007)
        actual_depth = context.dom_statistics.get("max_depth", 0)
        if actual_depth > 15:
            evidence_list.append(create_evidence(
                analyzer_name="DOMAnalyzer",
                rule_id="HTML_007",
                technical_details={
                    "max_dom_depth": actual_depth,
                    "metadata": metadata
                },
                confidence=0.55
            ))
            
        return evidence_list
