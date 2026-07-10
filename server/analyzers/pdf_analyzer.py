from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.attachment_model import AttachmentContext
from scanner.evidence import create_evidence

class PDFAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, AttachmentContext):
            return evidence_list
            
        metadata = {
            "analyzer_version": "2.0.0",
            "rule_version": "2.0.0",
            "data_source": "PDF Object Structure Streams"
        }
        
        for att in context.attachments:
            features = context.extracted_features.get(att.filename, {})
            pdf_meta = features.get("pdf_metadata", {})
            
            if not pdf_meta:
                continue
                
            has_js = pdf_meta.get("has_javascript", False)
            has_open = pdf_meta.get("has_openaction", False)
            has_launch = pdf_meta.get("has_launchaction", False)
            has_embed = pdf_meta.get("has_embedded_files", False)
            urls = pdf_meta.get("external_urls", [])
            
            # 1. Trigger PDF JavaScript stream or open/launch auto triggers (ATT_006)
            if has_js or has_open or has_launch:
                evidence_list.append(create_evidence(
                    analyzer_name="PDFAnalyzer",
                    rule_id="ATT_006",
                    technical_details={
                        "filename": att.filename,
                        "has_javascript": has_js,
                        "has_openaction": has_open,
                        "has_launchaction": has_launch,
                        "metadata": metadata
                    },
                    confidence=0.85
                ))
                
            # 2. Trigger embedded attachments within PDF (ATT_011)
            if has_embed:
                evidence_list.append(create_evidence(
                    analyzer_name="PDFAnalyzer",
                    rule_id="ATT_011",
                    technical_details={
                        "filename": att.filename,
                        "embedded_files_found": True,
                        "metadata": metadata
                    },
                    confidence=0.90
                ))
                
            # 3. Check for external URLs parsed out of streams
            if urls:
                evidence_list.append(create_evidence(
                    analyzer_name="PDFAnalyzer",
                    rule_id="ATT_006",
                    technical_details={
                        "filename": att.filename,
                        "external_urls_in_pdf": urls,
                        "metadata": metadata
                    },
                    confidence=0.70
                ))
                
        return evidence_list
