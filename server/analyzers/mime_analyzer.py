from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.attachment_model import AttachmentContext
from scanner.evidence import create_evidence

class MIMEAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, AttachmentContext):
            return evidence_list
            
        metadata = {
            "analyzer_version": "2.0.0",
            "rule_version": "2.0.0",
            "data_source": "Attachment Metadata"
        }
        
        for att in context.attachments:
            declared = att.declared_mime.lower().strip()
            detected = att.detected_mime.lower().strip()
            
            # Allow common generic defaults without warning
            if declared in ["application/octet-stream", "application/x-download", "binary/octet-stream"]:
                continue
                
            # If declared and detected are incompatible
            if declared != detected:
                # Basic mismatch logic
                # Clean up subtypes (e.g. text/plain vs application/x-bat)
                is_mismatch = True
                
                # Check for standard overlaps
                if "zip" in declared and "zip" in detected:
                    is_mismatch = False
                elif "officedocument" in declared and "officedocument" in detected:
                    is_mismatch = False
                elif "officedocument" in declared and "zip" in detected:
                    is_mismatch = False
                elif "pdf" in declared and "pdf" in detected:
                    is_mismatch = False
                elif ("octet-stream" in declared or "download" in declared):
                    is_mismatch = False
                    
                if is_mismatch:
                    evidence_list.append(create_evidence(
                        analyzer_name="MIMEAnalyzer",
                        rule_id="ATT_005",
                        technical_details={
                            "filename": att.filename,
                            "declared_mime": att.declared_mime,
                            "detected_mime": att.detected_mime,
                            "metadata": metadata
                        },
                        confidence=0.80
                    ))
                    
        return evidence_list
