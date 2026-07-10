from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.attachment_model import AttachmentContext
from scanner.evidence import create_evidence

class EmbeddedContentAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, AttachmentContext):
            return evidence_list
            
        metadata = {
            "analyzer_version": "2.0.0",
            "rule_version": "2.0.0",
            "data_source": "Embedded Object Telemetry"
        }
        
        for att in context.attachments:
            features = context.extracted_features.get(att.filename, {})
            
            # Check for embedded objects or files nested inside
            embedded_objs = features.get("embedded_objects", [])
            pdf_meta = features.get("pdf_metadata", {})
            
            # If the PDF claims to have embedded files
            if pdf_meta.get("has_embedded_files") or embedded_objs:
                evidence_list.append(create_evidence(
                    analyzer_name="EmbeddedContentAnalyzer",
                    rule_id="ATT_011",
                    technical_details={
                        "filename": att.filename,
                        "embedded_objects": embedded_objs,
                        "pdf_has_embedded": pdf_meta.get("has_embedded_files"),
                        "metadata": metadata
                    },
                    confidence=0.90
                ))
                
        return evidence_list
