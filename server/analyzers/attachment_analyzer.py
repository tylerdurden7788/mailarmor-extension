from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from scanner.evidence import create_evidence
from config.risk_config import DANGEROUS_EXTENSIONS, OFFICE_MACRO_EXTENSIONS, ARCHIVE_EXTENSIONS

class AttachmentAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        
        for attachment in email.attachments:
            filename = attachment.filename.lower()
            
            # 1. Dangerous executable/script extensions check
            is_dangerous = any(filename.endswith(ext) for ext in DANGEROUS_EXTENSIONS)
            if is_dangerous:
                evidence_list.append(create_evidence(
                    analyzer_name="AttachmentAnalyzer",
                    rule_id="ATT_001",
                    technical_details={"filename": attachment.filename, "content_type": attachment.content_type}
                ))
                
            # 2. Office macro-enabled extensions check
            is_office_macro = any(filename.endswith(ext) for ext in OFFICE_MACRO_EXTENSIONS)
            if is_office_macro:
                evidence_list.append(create_evidence(
                    analyzer_name="AttachmentAnalyzer",
                    rule_id="ATT_002",
                    technical_details={"filename": attachment.filename}
                ))
                
            # 3. Double extension check
            if attachment.has_double_extension:
                evidence_list.append(create_evidence(
                    analyzer_name="AttachmentAnalyzer",
                    rule_id="ATT_003",
                    technical_details={"filename": attachment.filename}
                ))
                
            # 4. Password-protected archive check (simulation)
            # In production, we'd attempt to read the archive directory structure. If it's encrypted, flag it.
            # We simulate this behavior for `.zip` or `.rar` attachments that contain "pass" or "secure" in their name,
            # or custom headers.
            if any(filename.endswith(ext) for ext in ARCHIVE_EXTENSIONS):
                # Simulating a password protected match
                if "protected" in filename or "secure" in filename:
                    evidence_list.append(create_evidence(
                        analyzer_name="AttachmentAnalyzer",
                        rule_id="ATT_004",
                        technical_details={"filename": attachment.filename}
                    ))
                    
        return evidence_list
