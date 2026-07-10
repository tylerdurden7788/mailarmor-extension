from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.attachment_model import AttachmentContext
from scanner.evidence import create_evidence

class ArchiveAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, AttachmentContext):
            return evidence_list
            
        metadata = {
            "analyzer_version": "2.0.0",
            "rule_version": "2.0.0",
            "data_source": "Archive Directory Metadata"
        }
        
        for att in context.attachments:
            features = context.extracted_features.get(att.filename, {})
            archive_meta = features.get("archive_metadata", {})
            
            if not archive_meta.get("is_archive"):
                continue
                
            # 1. Check: Password-protected archive (ATT_004)
            if archive_meta.get("is_encrypted"):
                evidence_list.append(create_evidence(
                    analyzer_name="ArchiveAnalyzer",
                    rule_id="ATT_004",
                    technical_details={
                        "filename": att.filename,
                        "metadata": metadata
                    },
                    confidence=0.85
                ))
                
            # 2. Check: Zip Bomb (ATT_007)
            if archive_meta.get("is_zip_bomb"):
                evidence_list.append(create_evidence(
                    analyzer_name="ArchiveAnalyzer",
                    rule_id="ATT_007",
                    technical_details={
                        "filename": att.filename,
                        "total_files": archive_meta.get("total_files_count"),
                        "total_uncompressed_bytes": archive_meta.get("total_uncompressed_bytes"),
                        "metadata": metadata
                    },
                    confidence=0.95
                ))
                
            # 3. Check: Max Recursion Depth / Nesting levels
            max_depth = archive_meta.get("max_nested_depth", 1)
            if max_depth > 3:
                evidence_list.append(create_evidence(
                    analyzer_name="ArchiveAnalyzer",
                    rule_id="ATT_007",
                    technical_details={
                        "filename": att.filename,
                        "recursion_depth": max_depth,
                        "metadata": metadata
                    },
                    confidence=0.80
                ))
                
            # 4. Check if nested files contain executables (masquerading inside zip)
            files = archive_meta.get("files", [])
            nested_execs = []
            for f in files:
                fn = f["filename"].lower()
                if any(fn.endswith(ext) for ext in [".exe", ".bat", ".vbs", ".cmd", ".js", ".scr"]):
                    nested_execs.append(f["filename"])
                    
            if nested_execs:
                # Trigger script/installer warning
                evidence_list.append(create_evidence(
                    analyzer_name="ArchiveAnalyzer",
                    rule_id="ATT_009",
                    technical_details={
                        "filename": att.filename,
                        "nested_executables": nested_execs,
                        "metadata": metadata
                    },
                    confidence=0.90
                ))
                
        return evidence_list
