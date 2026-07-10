from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.attachment_model import AttachmentContext
from scanner.evidence import create_evidence

class ImageAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, AttachmentContext):
            return evidence_list
            
        metadata = {
            "analyzer_version": "2.0.0",
            "rule_version": "2.0.0",
            "data_source": "Image Elements & EXIF Metadata"
        }
        
        for att in context.attachments:
            mime = att.detected_mime
            features = context.extracted_features.get(att.filename, {})
            svg_meta = features.get("svg_metadata", {})
            
            # SVG script exploit check (ATT_010)
            if mime == "image/svg+xml" and svg_meta:
                has_scripts = svg_meta.get("has_scripts", False)
                handlers = svg_meta.get("event_handlers_found", [])
                
                if has_scripts or handlers:
                    evidence_list.append(create_evidence(
                        analyzer_name="ImageAnalyzer",
                        rule_id="ATT_010",
                        technical_details={
                            "filename": att.filename,
                            "has_scripts": has_scripts,
                            "event_handlers": handlers,
                            "metadata": metadata
                        },
                        confidence=0.85
                    ))
                    
        return evidence_list
