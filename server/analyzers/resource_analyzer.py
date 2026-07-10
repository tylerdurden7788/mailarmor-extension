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
        data_uris = []
        blob_urls = []
        svgs = []
        embedded_fonts = []
        manifest_files = []
        external_media = []
        inline_images = []
        
        # 1. Evaluate resources: scripts, styles, fonts, favicons, etc.
        for res in resources:
            src = res.src or ""
            res_lower = src.lower()
            
            if src.startswith("data:"):
                data_uris.append(src)
                if "image/" in src:
                    inline_images.append(src)
                continue
                
            if src.startswith("blob:"):
                blob_urls.append(src)
                continue
                
            if res_lower.endswith(".svg"):
                svgs.append(src)
            elif any(f in res_lower for f in [".woff", ".woff2", ".ttf", ".otf"]):
                embedded_fonts.append(src)
            elif "manifest" in res_lower or res_lower.endswith(".webmanifest"):
                manifest_files.append(src)
            elif any(m in res_lower for m in [".mp4", ".mp3", ".ogg", ".webm", ".avi"]):
                external_media.append(src)
                
            try:
                parsed = urlparse(src)
                if parsed.netloc:
                    res_domain = extract_domain(parsed.netloc)
                    if res.resource_type == "script" and res_domain != sender_domain:
                        if res_domain not in {"localhost", "127.0.0.1", "google.com", "microsoft.com", "github.com", "cloudflare.com"}:
                            untrusted_scripts.append(src)
            except Exception:
                pass
                
        # 2. Check: Tracking pixels (1x1 images loaded externally)
        for img in images:
            src = img.src or ""
            if src.startswith("data:"):
                continue
            try:
                parsed = urlparse(src)
                if parsed.netloc:
                    img_domain = extract_domain(parsed.netloc)
                    if img_domain != sender_domain:
                        if any(p in src.lower() for p in ["track", "pixel", "open", "log", "stat"]):
                            tracking_pixels.append(src)
            except Exception:
                pass
                
        # Trigger remote script load warning (HTML_006)
        if untrusted_scripts or blob_urls or svgs or embedded_fonts or manifest_files or external_media or data_uris:
            evidence_list.append(create_evidence(
                analyzer_name="ResourceAnalyzer",
                rule_id="HTML_006",
                technical_details={
                    "untrusted_scripts": untrusted_scripts,
                    "blob_urls": blob_urls,
                    "svgs": svgs,
                    "embedded_fonts": embedded_fonts,
                    "manifest_files": manifest_files,
                    "external_media": external_media,
                    "data_uris_count": len(data_uris),
                    "inline_images_count": len(inline_images),
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
