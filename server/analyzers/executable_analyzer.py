from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.attachment_model import AttachmentContext
from scanner.evidence import create_evidence

class ExecutableAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, AttachmentContext):
            return evidence_list
            
        metadata = {
            "analyzer_version": "2.0.0",
            "rule_version": "2.0.0",
            "data_source": "PE/ELF/Mach-O Binary Headers"
        }
        
        for att in context.attachments:
            mime = att.detected_mime
            
            if mime == "application/x-msdownload" or att.extension in [".exe", ".dll", ".sys", ".scr", ".com", ".msi"]:
                evidence_list.append(create_evidence(
                    analyzer_name="ExecutableAnalyzer",
                    rule_id="ATT_001",
                    technical_details={
                        "filename": att.filename,
                        "detected_mime": mime,
                        "extension": att.extension,
                        "metadata": metadata
                    },
                    confidence=0.95
                ))
                
        return evidence_list
