import re
from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.attachment_model import AttachmentContext
from scanner.evidence import create_evidence
from config.risk_config import DANGEROUS_EXTENSIONS, OFFICE_MACRO_EXTENSIONS

class ExtensionAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, AttachmentContext):
            return evidence_list
            
        metadata = {
            "analyzer_version": "2.0.0",
            "rule_version": "2.0.0",
            "data_source": "Attachment File Name Extensions"
        }
        
        for att in context.attachments:
            filename = att.filename.lower()
            ext = att.extension
            
            # 1. Double extension check (e.g. invoice.pdf.exe)
            # Find all dot segments (excluding hidden files starting with dot)
            segments = [s for s in filename.split(".") if s]
            if len(segments) > 2:
                # Triggers double extension warning
                evidence_list.append(create_evidence(
                    analyzer_name="ExtensionAnalyzer",
                    rule_id="ATT_003",
                    technical_details={
                        "filename": att.filename,
                        "extensions_chain": segments[1:],
                        "metadata": metadata
                    },
                    confidence=0.90
                ))
                
            extra_dangerous = DANGEROUS_EXTENSIONS.union({".lnk", ".iso", ".img"})
            if ext in extra_dangerous:
                evidence_list.append(create_evidence(
                    analyzer_name="ExtensionAnalyzer",
                    rule_id="ATT_001",
                    technical_details={
                        "filename": att.filename,
                        "extension": ext,
                        "metadata": metadata
                    },
                    confidence=0.85
                ))
                
            # 3. Check: Macro-enabled extensions (ATT_002)
            if ext in OFFICE_MACRO_EXTENSIONS:
                evidence_list.append(create_evidence(
                    analyzer_name="ExtensionAnalyzer",
                    rule_id="ATT_002",
                    technical_details={
                        "filename": att.filename,
                        "extension": ext,
                        "metadata": metadata
                    },
                    confidence=0.75
                ))
                
        return evidence_list
