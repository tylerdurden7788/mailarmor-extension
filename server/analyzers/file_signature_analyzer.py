import os
from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.attachment_model import AttachmentContext
from scanner.evidence import create_evidence

class FileSignatureAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, AttachmentContext):
            return evidence_list
            
        metadata = {
            "analyzer_version": "2.0.0",
            "rule_version": "2.0.0",
            "data_source": "Attachment File Signatures"
        }
        
        for att in context.attachments:
            ext = att.extension.lower()
            detected = att.detected_mime.lower()
            
            # Map detected mime to valid extensions
            valid_extensions = {
                "application/x-msdownload": [".exe", ".dll", ".sys", ".scr", ".com", ".msi"],
                "application/pdf": [".pdf"],
                "application/zip": [".zip", ".docx", ".xlsx", ".pptx", ".jar"],
                "application/vnd.rar": [".rar"],
                "application/x-7z-compressed": [".7z"],
                "application/gzip": [".gz", ".tar.gz"],
                "image/png": [".png"],
                "image/jpeg": [".jpg", ".jpeg"],
                "image/gif": [".gif"],
                "image/svg+xml": [".svg"]
            }
            
            # If the file signature points to an executable, but extension is something else (e.g. docx, txt, pdf)
            if detected == "application/x-msdownload" and ext not in valid_extensions["application/x-msdownload"]:
                evidence_list.append(create_evidence(
                    analyzer_name="FileSignatureAnalyzer",
                    rule_id="ATT_005",
                    technical_details={
                        "filename": att.filename,
                        "detected_mime": att.detected_mime,
                        "declared_extension": ext,
                        "magic_bytes": att.magic_bytes,
                        "masquerade_detected": True,
                        "metadata": metadata
                    },
                    confidence=0.95
                ))
            elif detected in valid_extensions and ext and ext not in valid_extensions[detected]:
                # General signature mismatch
                # Check for close overlaps (e.g. zip vs docx is okay)
                if detected == "application/zip" and ext in [".docx", ".xlsx", ".pptx", ".jar"]:
                    continue
                # Flag mismatch
                evidence_list.append(create_evidence(
                    analyzer_name="FileSignatureAnalyzer",
                    rule_id="ATT_005",
                    technical_details={
                        "filename": att.filename,
                        "detected_mime": att.detected_mime,
                        "declared_extension": ext,
                        "magic_bytes": att.magic_bytes,
                        "metadata": metadata
                    },
                    confidence=0.85
                ))
                
        return evidence_list
