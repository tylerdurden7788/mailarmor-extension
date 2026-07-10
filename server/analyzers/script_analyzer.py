from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.attachment_model import AttachmentContext
from scanner.evidence import create_evidence

class ScriptAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, AttachmentContext):
            return evidence_list
            
        metadata = {
            "analyzer_version": "2.0.0",
            "rule_version": "2.0.0",
            "data_source": "Script Source Code Scanners"
        }
        
        for att in context.attachments:
            ext = att.extension.lower()
            features = context.extracted_features.get(att.filename, {})
            script_meta = features.get("script_metadata", {})
            
            # Script extension matching
            script_extensions = [".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".sh"]
            if ext in script_extensions or script_meta:
                suspicious_apis = script_meta.get("suspicious_apis", [])
                has_obf = script_meta.get("has_obfuscation", False)
                
                confidence = 0.90
                # If there are execution hooks or obfuscations, boost risk description
                evidence_list.append(create_evidence(
                    analyzer_name="ScriptAnalyzer",
                    rule_id="ATT_009",
                    technical_details={
                        "filename": att.filename,
                        "extension": ext,
                        "suspicious_apis": suspicious_apis,
                        "has_obfuscation": has_obf,
                        "metadata": metadata
                    },
                    confidence=confidence
                ))
                
        return evidence_list
