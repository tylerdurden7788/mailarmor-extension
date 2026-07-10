from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class Link(BaseModel):
    actual_url: str = Field(description="The actual destination URL (href)")
    display_text: str = Field(description="The displayed link text")
    is_button: bool = Field(default=False, description="True if link style indicates it is a button")
    has_mismatch: bool = Field(default=False, description="True if display text and actual destination mismatch significantly")

class EmailForm(BaseModel):
    action: Optional[str] = None
    method: Optional[str] = None
    inputs: List[Dict[str, Any]] = Field(default_factory=list)
    has_password_input: bool = False

class EmailAttachment(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    content_base64: Optional[str] = None
    is_dangerous: bool = False
    has_double_extension: bool = False
    is_executable: bool = False

class ReceivedHop(BaseModel):
    by: Optional[str] = None
    from_host: Optional[str] = Field(None, alias="from")
    date: Optional[str] = None
    raw: str

class Email(BaseModel):
    # Envelope & Headers
    subject: str = Field(default="", description="Value of the Subject header")
    from_header: str = Field(default="", description="Value of the From header")
    sender_header: str = Field(default="", description="Value of the Sender header")
    reply_to: str = Field(default="", description="Value of the Reply-To header")
    return_path: str = Field(default="", description="Value of the Return-Path header")
    envelope_sender: str = Field(default="", description="Envelope sender address")
    message_id: str = Field(default="", description="Value of the Message-ID header")
    date: str = Field(default="", description="Value of the Date header")
    received_chain: List[ReceivedHop] = Field(default_factory=list, description="Parsed Received headers chain")
    auth_headers: Dict[str, str] = Field(default_factory=dict, description="SPF, DKIM, DMARC, Authentication-Results headers")
    
    # MIME details
    mime_structure: Dict[str, Any] = Field(default_factory=dict, description="Parsed MIME tree structure")
    charset: str = Field(default="utf-8", description="Character encoding of the body")
    content_type: str = Field(default="text/plain", description="Primary content type")
    boundary: str = Field(default="", description="Multipart boundary marker if present")
    user_agent_mailer: str = Field(default="", description="Value of User-Agent or X-Mailer headers")
    
    # Normalized body text
    body_text: str = Field(default="", description="Normalized plain text body")
    body_html: str = Field(default="", description="Normalized HTML body")
    
    # Extracted assets
    urls: List[Link] = Field(default_factory=list, description="Hyperlinks found in body")
    forms: List[EmailForm] = Field(default_factory=list, description="HTML forms found in body")
    images: List[Dict[str, Any]] = Field(default_factory=list, description="Images referenced in HTML body")
    attachments: List[EmailAttachment] = Field(default_factory=list, description="Attachments found in MIME structure")
    embedded_resources: List[Dict[str, Any]] = Field(default_factory=list, description="CID or inline embedded assets")
