from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.attachment_model import AttachmentContext
from scanner.evidence import create_evidence

class OfficeDocumentAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, AttachmentContext):
            return evidence_list
            
        metadata = {
            "analyzer_version": "2.0.0",
            "rule_version": "2.0.0",
            "data_source": "Microsoft Office OpenXML & OLE OLEStreams"
        }
        
        for att in context.attachments:
            features = context.extracted_features.get(att.filename, {})
            office_meta = features.get("office_metadata", {})
            
            if not office_meta:
                continue
                
            has_macros = office_meta.get("has_macros", False)
            has_dde = office_meta.get("has_dde", False)
            templates = office_meta.get("external_templates", [])
            
            # 1. Trigger Office Macro warning (ATT_008)
            if has_macros:
                evidence_list.append(create_evidence(
                    analyzer_name="OfficeDocumentAnalyzer",
                    rule_id="ATT_008",
                    technical_details={
                        "filename": att.filename,
                        "has_macros": True,
                        "metadata": metadata
                    },
                    confidence=0.85
                ))
                
            # 2. Trigger DDE Hook warning (ATT_008)
            if has_dde:
                evidence_list.append(create_evidence(
                    analyzer_name="OfficeDocumentAnalyzer",
                    rule_id="ATT_008",
                    technical_details={
                        "filename": att.filename,
                        "has_dde": True,
                        "metadata": metadata
                    },
                    confidence=0.90
                ))
                
            # 3. Trigger External templates injection check
            if templates:
                evidence_list.append(create_evidence(
                    analyzer_name="OfficeDocumentAnalyzer",
                    rule_id="ATT_008",
                    technical_details={
                        "filename": att.filename,
                        "external_templates_count": len(templates),
                        "metadata": metadata
                    },
                    confidence=0.70
                ))
                
        return evidence_list
