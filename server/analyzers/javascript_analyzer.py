import re
from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.html_model import HTMLContext
from scanner.evidence import create_evidence

class JavaScriptAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, HTMLContext):
            return evidence_list
            
        scripts = context.scripts
        metadata = {
            "analyzer_version": "2.0.0",
            "rule_version": "2.0.0",
            "data_source": "DOM HTML JavaScript Elements"
        }
        
        script_warnings = []
        
        # Behavioral classifications mapping
        for script in scripts:
            content = script.content or ""
            src = script.src or ""
            
            # Skip empty nodes
            if not content and not src:
                continue
                
            categories_triggered = []
            details = {}
            
            # 1. Execution signatures
            if "eval(" in content or "function(" in content.lower():
                categories_triggered.append("execution")
                details["eval_usage"] = True
                
            # 2. Navigation signatures
            if any(p in content for p in ["window.location", "location.replace", "location.assign"]):
                categories_triggered.append("navigation")
                details["navigation_redirect"] = True
                
            # 3. DOM Manipulation signatures
            if "document.write" in content or "innerhtml" in content.lower():
                categories_triggered.append("dom_manipulation")
                details["dynamic_dom_write"] = True
                
            # 4. Timers
            if "settimeout" in content.lower() or "setinterval" in content.lower():
                categories_triggered.append("timers")
                details["timer_triggers"] = True
                
            # 5. Encoding
            if "unescape(" in content or re.search(r'\\x[0-9a-fA-F]{2}', content):
                categories_triggered.append("encoding")
                details["hex_encoding"] = True
                
            # 6. Networking
            if "xmlhttprequest" in content.lower() or "fetch(" in content.lower():
                categories_triggered.append("networking")
                details["dynamic_networking"] = True
                
            # 7. Browser Fingerprinting
            if any(fp in content for fp in ["navigator.userAgent", "screen.width", "navigator.plugins", "getcontext(\"2d\")"]):
                categories_triggered.append("fingerprinting")
                details["browser_fingerprinting"] = True
                
            if categories_triggered:
                script_warnings.append({
                    "src": src,
                    "categories": categories_triggered,
                    "dom_path": script.dom_path,
                    "details": details
                })
                
        # Generate evidence if any suspicious script categories are matched
        if script_warnings:
            evidence_list.append(create_evidence(
                analyzer_name="JavaScriptAnalyzer",
                rule_id="HTML_005",
                technical_details={
                    "script_warnings": script_warnings,
                    "metadata": metadata
                },
                confidence=0.85
            ))
            
        return evidence_list
