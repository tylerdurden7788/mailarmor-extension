import base64
import hashlib
import os
from typing import Tuple, List
from models.email_model import EmailAttachment
from models.attachment_model import ParsedAttachment

class AttachmentParser:
    @staticmethod
    def parse_attachment(att: EmailAttachment) -> ParsedAttachment:
        """
        Parses an EmailAttachment by decoding its payload, calculating hashes,
        and validating its magic bytes signature.
        """
        warnings = []
        filename = att.filename or "untitled"
        declared_mime = att.content_type or "application/octet-stream"
        
        # 1. Decode base64
        raw_bytes = b""
        if att.content_base64:
            try:
                raw_bytes = base64.b64decode(att.content_base64)
            except Exception as e:
                warnings.append(f"Failed to decode base64 payload: {e}")
                
        size_bytes = len(raw_bytes) if raw_bytes else att.size_bytes
        
        # 2. Calculate Hashes
        md5 = hashlib.md5(raw_bytes).hexdigest() if raw_bytes else ""
        sha1 = hashlib.sha1(raw_bytes).hexdigest() if raw_bytes else ""
        sha256 = hashlib.sha256(raw_bytes).hexdigest() if raw_bytes else ""
        
        # 3. Detect magic bytes and signature MIME
        detected_mime, magic_hex = AttachmentParser.detect_signature(raw_bytes, filename)
        
        # 4. Get clean extension
        _, ext = os.path.splitext(filename)
        ext = ext.lower()
        
        return ParsedAttachment(
            filename=filename,
            extension=ext,
            declared_mime=declared_mime,
            detected_mime=detected_mime,
            magic_bytes=magic_hex,
            size_bytes=size_bytes,
            sha256=sha256,
            sha1=sha1,
            md5=md5,
            parser_warnings=warnings
        )
        
    @staticmethod
    def detect_signature(raw_bytes: bytes, filename: str) -> Tuple[str, str]:
        """
        Scans magic bytes header to determine file signature.
        """
        if not raw_bytes:
            return "application/octet-stream", ""
            
        header = raw_bytes[:16]
        magic_hex = header.hex()
        
        # Check standard headers
        if header.startswith(b"MZ"):
            return "application/x-msdownload", magic_hex
        elif header.startswith(b"%PDF"):
            return "application/pdf", magic_hex
        elif header.startswith(b"PK\x03\x04"):
            # Check if it could be an OpenXML office doc based on filename
            ext = os.path.splitext(filename.lower())[1]
            if ext in [".docx", ".xlsx", ".pptx"]:
                return f"application/vnd.openxmlformats-officedocument.{ext[1:]}", magic_hex
            return "application/zip", magic_hex
        elif header.startswith(b"Rar!\x1a\x07\x00") or header.startswith(b"Rar!\x1a\x07\x01\x00"):
            return "application/vnd.rar", magic_hex
        elif header.startswith(b"7z\xbc\xaf\x27\x1c"):
            return "application/x-7z-compressed", magic_hex
        elif header.startswith(b"\x1f\x8b"):
            return "application/gzip", magic_hex
        elif header.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png", magic_hex
        elif header.startswith(b"\xff\xd8\xff"):
            return "image/jpeg", magic_hex
        elif header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
            return "image/gif", magic_hex
        elif header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            # OLE97-2003 Office document (doc, xls, ppt)
            ext = os.path.splitext(filename.lower())[1]
            if ext in [".doc", ".xls", ".ppt"]:
                return f"application/msword-{ext[1:]}", magic_hex
            return "application/x-ole-storage", magic_hex
            
        # Text-based format detections
        text_prefix = raw_bytes[:512].decode("utf-8", errors="ignore").strip().lower()
        if text_prefix.startswith("<svg") or (text_prefix.startswith("<?xml") and "<svg" in text_prefix):
            return "image/svg+xml", magic_hex
            
        # Default fallback based on filename extension if no binary signature matched
        ext = os.path.splitext(filename.lower())[1]
        mimes = {
            ".txt": "text/plain",
            ".html": "text/html",
            ".htm": "text/html",
            ".js": "application/javascript",
            ".vbs": "text/vbscript",
            ".ps1": "application/x-powershell",
            ".bat": "application/x-bat",
            ".cmd": "application/x-bat",
            ".sh": "application/x-sh",
            ".xml": "text/xml",
            ".json": "application/json"
        }
        
        return mimes.get(ext, "application/octet-stream"), magic_hex
