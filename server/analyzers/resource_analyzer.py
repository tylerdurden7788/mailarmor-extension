from urllib.parse import urlparse
from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.html_model import HTMLContext
from scanner.evidence import create_evidence
from utils.domain_utils import extract_domain

class ResourceAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, HTMLContext):
            return evidence_list
            
        resources = context.embedded_resources
        images = context.images
        
        metadata = {
            "analyzer_version": "2.0.0",
            "rule_version": "2.0.0",
            "data_source": "DOM HTML Resource Loading Paths"
        }
        
        sender_domain = extract_domain(email.from_header)
        untrusted_scripts = []
        tracking_pixels = []
        data_uris_count = 0
        
        # 1. Evaluate resources: scripts, style overlays, fonts, favicons
        for res in resources:
            src = res.src
            if src.startswith("data:"):
                data_uris_count += 1
                continue
                
            try:
                parsed = urlparse(src)
                if parsed.netloc:
                    res_domain = extract_domain(parsed.netloc)
                    # Scripts loaded from external non-brand domains
                    if res.resource_type == "script" and res_domain != sender_domain:
                        if res_domain not in {"localhost", "127.0.0.1", "google.com", "microsoft.com", "github.com", "cloudflare.com"}:
                            untrusted_scripts.append(src)
            except Exception:
                pass
                
        # 2. Check: Tracking pixels (1x1 images loaded externally)
        for img in images:
            src = img.src
            # Skip base64 images
            if src.startswith("data:"):
                continue
                
            # If image source points to different domain
            try:
                parsed = urlparse(src)
                if parsed.netloc:
                    img_domain = extract_domain(parsed.netloc)
                    if img_domain != sender_domain:
                        # Common tracking parameter signatures
                        if any(p in src.lower() for p in ["track", "pixel", "open", "log", "stat"]):
                            tracking_pixels.append(src)
            except Exception:
                pass
                
        # Trigger remote script load warning (HTML_006)
        if untrusted_scripts:
            evidence_list.append(create_evidence(
                analyzer_name="ResourceAnalyzer",
                rule_id="HTML_006",
                technical_details={
                    "untrusted_scripts": untrusted_scripts,
                    "metadata": metadata
                },
                confidence=0.70
            ))
            
        # Trigger tracking pixels (supporting evidence)
        if tracking_pixels:
            evidence_list.append(create_evidence(
                analyzer_name="ResourceAnalyzer",
                rule_id="HTML_003",
                technical_details={
                    "tracking_pixels": tracking_pixels,
                    "metadata": metadata
                },
                confidence=0.50
            ))
            
        return evidence_list
