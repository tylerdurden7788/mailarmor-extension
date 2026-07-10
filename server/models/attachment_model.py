from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Any, Optional
from models.html_model import DocumentGraph

class ParsedAttachment(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    filename: str
    extension: str
    declared_mime: str
    detected_mime: str
    magic_bytes: str
    size_bytes: int
    sha256: str
    sha1: str
    md5: str
    parser_warnings: List[str] = Field(default_factory=list)

class AttachmentContext(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    attachments: List[ParsedAttachment] = Field(default_factory=list)
    document_graph: Optional[DocumentGraph] = None
    
    # Feature Extraction Layer properties
    extracted_features: Dict[str, Any] = Field(default_factory=dict)
    
    # Configuration / Performance Limits
    max_attachment_size: int = 10 * 1024 * 1024 # 10 MB limit for deep extraction
    archive_limits: Dict[str, int] = Field(default_factory=lambda: {
        "max_depth": 3,
        "max_files": 100,
        "max_uncompressed_bytes": 100 * 1024 * 1024 # 100 MB
    })
    
    # Provider Placeholder Stubs
    ocr_output: Optional[str] = None
    qr_detections: List[str] = Field(default_factory=list)
    sandbox_results: Optional[Dict[str, Any]] = None
    malware_scan_results: Optional[Dict[str, Any]] = None
