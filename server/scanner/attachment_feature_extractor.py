import io
import re
import os
import zipfile
import tarfile
import gzip
import base64
from typing import List, Dict, Any, Tuple
from models.email_model import EmailAttachment
from models.attachment_model import ParsedAttachment
from models.html_model import DocumentGraph

class AttachmentFeatureExtractor:
    @staticmethod
    def extract_features(
        att: EmailAttachment, 
        parsed: ParsedAttachment, 
        archive_limits: Dict[str, int]
    ) -> Dict[str, Any]:
        """
        Runs file-type specific static scanners on decoded payload bytes.
        """
        features = {
            "file_type": parsed.detected_mime,
            "size_bytes": parsed.size_bytes,
            "sha256": parsed.sha256,
            "archive_metadata": {},
            "pdf_metadata": {},
            "office_metadata": {},
            "script_metadata": {},
            "svg_metadata": {},
            "embedded_objects": [],
            "warnings": []
        }
        
        raw_bytes = b""
        if att.content_base64:
            try:
                raw_bytes = base64.b64decode(att.content_base64)
            except Exception:
                pass
                
        if not raw_bytes:
            return features
            
        # Dispatch checks based on detected MIME
        mime = parsed.detected_mime
        
        # 1. Archive checks
        is_ooxml = "officedocument" in mime
        if mime in ["application/zip", "application/x-zip-compressed"] or is_ooxml:
            # Standard ZIP and OOXML containers
            features["archive_metadata"] = AttachmentFeatureExtractor._scan_zip(
                raw_bytes, archive_limits, features["warnings"]
            )
            # If it's an OOXML document, perform office specific macro-checks
            if is_ooxml:
                features["office_metadata"] = AttachmentFeatureExtractor._scan_ooxml(features["archive_metadata"])
                
        elif mime == "application/vnd.rar":
            # Rar metadata check placeholder
            features["archive_metadata"] = {"is_archive": True, "type": "RAR"}
        elif mime == "application/x-7z-compressed":
            features["archive_metadata"] = {"is_archive": True, "type": "7z"}
        elif mime == "application/gzip":
            features["archive_metadata"] = {"is_archive": True, "type": "GZIP"}
            
        # 2. PDF checks
        elif mime == "application/pdf":
            features["pdf_metadata"] = AttachmentFeatureExtractor._scan_pdf(raw_bytes)
            
        # 3. OLE legacy MS Office files
        elif mime in ["application/x-ole-storage", "application/msword-doc", "application/msword-xls", "application/msword-ppt"]:
            features["office_metadata"] = AttachmentFeatureExtractor._scan_ole(raw_bytes)
            
        # 4. SVG checks
        elif mime == "image/svg+xml":
            features["svg_metadata"] = AttachmentFeatureExtractor._scan_svg(raw_bytes)
            
        # 5. Executable / Scripts checks
        elif mime in ["application/x-msdownload", "application/javascript", "text/vbscript", "application/x-powershell", "application/x-bat"]:
            features["script_metadata"] = AttachmentFeatureExtractor._scan_script_or_binary(raw_bytes, parsed.extension)
            
        return features

    @staticmethod
    def _scan_zip(raw_bytes: bytes, limits: Dict[str, int], warnings: List[str]) -> Dict[str, Any]:
        """
        Statically inspects ZIP files and protects against ZIP bomb patterns.
        """
        meta = {
            "is_archive": True,
            "type": "ZIP",
            "files": [],
            "total_uncompressed_bytes": 0,
            "total_files_count": 0,
            "max_nested_depth": 1,
            "is_encrypted": False,
            "is_zip_bomb": False
        }
        
        try:
            with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
                infolist = zf.infolist()
                meta["total_files_count"] = len(infolist)
                
                # Check file list limit
                if len(infolist) > limits.get("max_files", 100):
                    warnings.append("Archive contains too many files. Scanning was truncated.")
                    
                for info in infolist[:limits.get("max_files", 100)]:
                    # Check encryption flag
                    if info.flag_bits & 0x1:
                        meta["is_encrypted"] = True
                        
                    meta["total_uncompressed_bytes"] += info.file_size
                    
                    # Track file names inside
                    meta["files"].append({
                        "filename": info.filename,
                        "size_bytes": info.file_size,
                        "compressed_size": info.compress_size
                    })
                    
                    # Guess nesting depth based on paths
                    depth = len(info.filename.split("/"))
                    meta["max_nested_depth"] = max(meta["max_nested_depth"], depth)
                    
                # Zip bomb signature: uncompressed to compressed ratio > 100
                compressed_total = len(raw_bytes)
                uncompressed_total = meta["total_uncompressed_bytes"]
                ratio = uncompressed_total / max(compressed_total, 1)
                
                if ratio > 100.0 or uncompressed_total > limits.get("max_uncompressed_bytes", 100 * 1024 * 1024):
                    meta["is_zip_bomb"] = True
                    warnings.append("Zip bomb signature detected based on decompression expansion ratio.")
                    
        except Exception as e:
            warnings.append(f"Failed to parse ZIP archive structure: {e}")
            
        return meta

    @staticmethod
    def _scan_ooxml(zip_meta: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scans OOXML OpenXML formats (.docx, .xlsx, .pptx) for macros or DDE.
        """
        office = {"has_macros": False, "has_dde": False, "external_templates": []}
        files = [f["filename"] for f in zip_meta.get("files", [])]
        
        for f in files:
            # VBA Macro folder indicator
            if "vbaProject.bin" in f or "vbaData.bin" in f:
                office["has_macros"] = True
            # External relationships / templates indicators
            if f.endswith(".rels"):
                office["external_templates"].append(f)
                
        return office

    @staticmethod
    def _scan_ole(raw_bytes: bytes) -> Dict[str, Any]:
        """
        Scans legacy compound OLE documents (doc, xls) for macros or DDE indicators.
        """
        office = {"has_macros": False, "has_dde": False}
        magic_hex = raw_bytes.hex()
        
        # Static VBA signature searches
        if "Attribut VB_" in raw_bytes.decode("utf-8", errors="ignore"):
            office["has_macros"] = True
            
        # DDE / DDEAUTO commands search
        if b"DDE" in raw_bytes or b"DDEAUTO" in raw_bytes:
            office["has_dde"] = True
            
        return office

    @staticmethod
    def _scan_pdf(raw_bytes: bytes) -> Dict[str, Any]:
        """
        Statically checks PDF stream dictionaries for active hooks.
        """
        pdf = {
            "has_javascript": False,
            "has_openaction": False,
            "has_launchaction": False,
            "has_embedded_files": False,
            "external_urls": []
        }
        
        # Scans for PDF dictionary action keywords
        # e.g. /JavaScript, /JS, /OpenAction, /Launch, /EmbeddedFiles
        content = raw_bytes.decode("utf-8", errors="ignore")
        
        content_lower = content.lower()
        if "/javascript" in content_lower or "/js" in content_lower:
            pdf["has_javascript"] = True
        if "/openaction" in content_lower:
            pdf["has_openaction"] = True
        if "/launch" in content_lower:
            pdf["has_launchaction"] = True
        if "/embeddedfiles" in content_lower:
            pdf["has_embedded_files"] = True
            
        # Extract potential external URLs inside PDF action links
        urls = re.findall(r'https?://[^\s<>"]+', content)
        if urls:
            # unique list up to 10 urls
            pdf["external_urls"] = list(set(urls))[:10]
            
        return pdf

    @staticmethod
    def _scan_svg(raw_bytes: bytes) -> Dict[str, Any]:
        """
        Scans SVG content for inline script elements.
        """
        svg = {"has_scripts": False, "event_handlers_found": []}
        content = raw_bytes.decode("utf-8", errors="ignore").lower()
        
        if "<script" in content or "foreignobject" in content:
            svg["has_scripts"] = True
            
        # Common onload, onclick events in SVG
        handlers = re.findall(r'\bon[a-z]+\s*=', content)
        if handlers:
            svg["event_handlers_found"] = list(set(handlers))
            
        return svg

    @staticmethod
    def _scan_script_or_binary(raw_bytes: bytes, ext: str) -> Dict[str, Any]:
        """
        Statically checks scripts/binaries for dangerous execution hooks.
        """
        script = {"has_obfuscation": False, "suspicious_apis": []}
        content = raw_bytes.decode("utf-8", errors="ignore")
        
        suspicious_keywords = [
            "wscript.shell", "powershell", "bypass", "exec", "eval", "system",
            "downloadstring", "downloadfile", "invoke-expression", "iex", "cmd.exe",
            "runas", "regsvr32", "rundll32", "schtasks"
        ]
        
        for kw in suspicious_keywords:
            if kw in content.lower():
                script["suspicious_apis"].append(kw)
                
        # Obfuscation patterns
        if len(re.findall(r'\\x[0-9a-fA-F]{2}', content)) > 20:
            script["has_obfuscation"] = True
            
        return script
