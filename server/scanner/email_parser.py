import re
import email
from email import policy
from html.parser import HTMLParser
from typing import Dict, Any, List
from models.email_model import Email, Link, EmailForm, EmailAttachment, ReceivedHop
from utils.domain_utils import extract_domain
from utils.string_utils import decode_html_text, normalize_whitespace

class EmailHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.forms = []
        self.images = []
        self.current_link = None
        self.current_form = None
        self.has_hidden_elements = False
        self.hidden_inputs_count = 0
        self.js_redirects_found = False
        self.iframes_count = 0
        self.meta_refresh_found = False
        self.inline_scripts_count = 0
        self.external_scripts_count = 0
        self.base64_data_uris_count = 0

    def handle_starttag(self, tag, attrs):
        attrs_dict = {k.lower(): v for k, v in attrs}
        
        # Link extraction
        if tag == "a":
            href = attrs_dict.get("href", "")
            cls = attrs_dict.get("class", "").lower()
            role = attrs_dict.get("role", "").lower()
            style = attrs_dict.get("style", "").lower()
            
            # Button detection
            is_button = "btn" in cls or "button" in cls or role == "button" or "button" in style
            self.current_link = {
                "actual_url": href,
                "display_text": "",
                "is_button": is_button,
                "has_mismatch": False
            }
            
        # Form extraction
        elif tag == "form":
            self.current_form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "post").lower(),
                "inputs": [],
                "has_password_input": False
            }
            
        # Input extraction
        elif tag == "input" and self.current_form is not None:
            input_type = attrs_dict.get("type", "text").lower()
            name = attrs_dict.get("name", "")
            val = attrs_dict.get("value", "")
            self.current_form["inputs"].append({
                "type": input_type,
                "name": name,
                "value": val
            })
            if input_type == "password":
                self.current_form["has_password_input"] = True
            if input_type == "hidden":
                self.hidden_inputs_count += 1
                
        # Image extraction
        elif tag == "img":
            src = attrs_dict.get("src", "")
            if src.startswith("data:image/") and ";base64," in src:
                self.base64_data_uris_count += 1
            self.images.append({
                "src": src,
                "alt": attrs_dict.get("alt", ""),
                "id": attrs_dict.get("id", ""),
                "style": attrs_dict.get("style", "")
            })
            
        # Meta refresh check
        elif tag == "meta":
            equiv = attrs_dict.get("http-equiv", "").lower()
            if equiv == "refresh":
                self.meta_refresh_found = True
                
        # iframe detection
        elif tag == "iframe":
            self.iframes_count += 1
            
        # Script checks
        elif tag == "script":
            if "src" in attrs_dict:
                self.external_scripts_count += 1
            else:
                self.inline_scripts_count += 1
                
        # Inspect for display hiding in styles
        style_str = attrs_dict.get("style", "").replace(" ", "").lower()
        if "display:none" in style_str or "visibility:hidden" in style_str or "font-size:0" in style_str:
            self.has_hidden_elements = True

    def handle_data(self, data):
        if self.current_link is not None:
            self.current_link["display_text"] += data
            
        # JavaScript redirect keywords
        if "window.location" in data or "location.replace" in data or "location.href" in data:
            self.js_redirects_found = True

    def handle_endtag(self, tag):
        if tag == "a" and self.current_link is not None:
            self.current_link["display_text"] = self.current_link["display_text"].strip()
            self.links.append(self.current_link)
            self.current_link = None
        elif tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


class EmailParser:
    @staticmethod
    def parse_raw_mime(raw_mime: str) -> Email:
        """
        Parses standard raw MIME RFC822 string into Email model.
        """
        msg = email.message_from_string(raw_mime, policy=policy.default)
        
        # Headers extraction
        from_header = msg.get("From", "")
        sender_header = msg.get("Sender", "")
        reply_to = msg.get("Reply-To", "")
        return_path = msg.get("Return-Path", "")
        message_id = msg.get("Message-ID", "")
        date_header = msg.get("Date", "")
        user_agent = msg.get("User-Agent", "") or msg.get("X-Mailer", "")
        content_type = msg.get_content_type()
        boundary = msg.get_boundary() or ""
        charset = msg.get_content_charset() or "utf-8"
        
        # Envelope sender extraction from Return-Path
        envelope_sender = ""
        if return_path:
            match = re.search(r'<([^>]+)>', return_path)
            envelope_sender = match.group(1) if match else return_path
            
        # Authentication headers
        auth_headers = {}
        for h in ["Authentication-Results", "Received-SPF", "DKIM-Signature", "ARC-Authentication-Results"]:
            val = msg.get(h)
            if val:
                auth_headers[h] = str(val)
                
        # Received chain
        received_chain = []
        for recv in msg.get_all("Received", []):
            received_chain.append(ReceivedHop(raw=str(recv)))
            
        # Extract bodies & attachments
        body_text = ""
        body_html = ""
        attachments = []
        embedded_resources = []
        
        for part in msg.walk():
            maintype = part.get_content_maintype()
            disposition = part.get_content_disposition()
            
            if maintype == 'multipart':
                continue
                
            if disposition == 'attachment' or part.get_filename():
                filename = part.get_filename() or "untitled"
                payload = part.get_payload(decode=True) or b""
                size = len(payload)
                
                # Check extension rules
                has_double_ext = len(re.findall(r'\.[a-zA-Z0-9]+', filename)) > 1
                is_executable = any(filename.lower().endswith(ext) for ext in [".exe", ".bat", ".vbs", ".cmd", ".js"])
                
                attachments.append(EmailAttachment(
                    filename=filename,
                    content_type=part.get_content_type(),
                    size_bytes=size,
                    has_double_extension=has_double_ext,
                    is_executable=is_executable
                ))
            else:
                subtype = part.get_content_subtype()
                payload = part.get_payload(decode=True) or b""
                text_content = payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
                
                if subtype == 'plain':
                    body_text += text_content
                elif subtype == 'html':
                    body_html += text_content
                    
        # Parse display details
        sender_email = ""
        sender_display_name = ""
        if from_header:
            match = re.search(r'^(.*?)\s*<([^>]+)>', from_header)
            if match:
                sender_display_name = match.group(1).strip(' \'"')
                sender_email = match.group(2).strip()
            else:
                sender_email = from_header.strip()
                
        sender_domain = extract_domain(sender_email)
        
        # HTML Parse details
        html_parser = EmailHTMLParser()
        if body_html:
            html_parser.feed(body_html)
            
        urls = [Link(**l) for l in html_parser.links]
        forms = [EmailForm(**f) for f in html_parser.forms]
        
        return Email(
            subject=msg.get("Subject", ""),
            from_header=from_header,
            sender_header=sender_header,
            reply_to=reply_to,
            return_path=return_path,
            envelope_sender=envelope_sender,
            message_id=message_id,
            date=date_header,
            received_chain=received_chain,
            auth_headers=auth_headers,
            charset=charset,
            content_type=content_type,
            boundary=boundary,
            user_agent_mailer=user_agent,
            body_text=body_text,
            body_html=body_html,
            urls=urls,
            forms=forms,
            images=html_parser.images,
            attachments=attachments
        )

    @classmethod
    def parse_api_payload(cls, payload: Dict[str, Any]) -> Email:
        """
        Parses extension format payload { subject, sender, body } into Email model.
        """
        subject = payload.get("subject", "")
        sender_raw = payload.get("sender", "")
        body_raw = payload.get("body", "")
        
        # Extract display name vs address
        sender_display_name = ""
        sender_email = sender_raw
        match = re.search(r'^(.*?)\s*<([^>]+)>', sender_raw)
        if match:
            sender_display_name = match.group(1).strip(' \'"')
            sender_email = match.group(2).strip()
            
        sender_domain = extract_domain(sender_email)
        
        # Detect HTML vs plain
        body_html = ""
        body_text = ""
        if "<html" in body_raw.lower() or "<div" in body_raw.lower() or "<p" in body_raw.lower() or "<a " in body_raw.lower():
            body_html = body_raw
            # Strip tags for fallback plain text
            body_text = re.sub(r'<[^>]+>', '', body_raw)
        else:
            body_text = body_raw
            body_html = f"<div>{body_raw}</div>"
            
        # HTML Parse details
        html_parser = EmailHTMLParser()
        if body_html:
            html_parser.feed(body_html)
            
        urls = []
        for l in html_parser.links:
            # Perform basic mismatch detection
            display = normalize_whitespace(l["display_text"])
            actual = l["actual_url"]
            has_mismatch = False
            if display.startswith("http") and display != actual:
                has_mismatch = True
            urls.append(Link(
                actual_url=actual,
                display_text=display,
                is_button=l["is_button"],
                has_mismatch=has_mismatch
            ))
            
        forms = [EmailForm(**f) for f in html_parser.forms]
        
        # Try extracting attachments from body metadata if present in payload
        attachments = []
        for att in payload.get("attachments", []):
            attachments.append(EmailAttachment(
                filename=att.get("filename", ""),
                content_type=att.get("content_type", "application/octet-stream"),
                size_bytes=att.get("size_bytes", 0),
                has_double_extension=len(re.findall(r'\.[a-zA-Z0-9]+', att.get("filename", ""))) > 1,
                is_executable=any(att.get("filename", "").lower().endswith(ext) for ext in [".exe", ".bat", ".vbs", ".js"])
            ))

        return Email(
            subject=subject,
            from_header=sender_raw,
            sender_header="",
            reply_to=payload.get("reply_to", ""),
            return_path=payload.get("return_path", ""),
            envelope_sender="",
            message_id=payload.get("message_id", ""),
            date=payload.get("date", ""),
            auth_headers=payload.get("auth_headers", {}),
            body_text=normalize_whitespace(decode_html_text(body_text)),
            body_html=body_html,
            urls=urls,
            forms=forms,
            images=html_parser.images,
            attachments=attachments
        )
