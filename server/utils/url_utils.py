import re
from urllib.parse import urlparse, unquote

def clean_url(url: str) -> str:
    """
    Trims, cleans and decodes encoded components of the URL.
    """
    if not url:
        return ""
    return unquote(url.strip())

def is_ip_address_url(url: str) -> bool:
    """
    Checks if the URL host is a raw IP address (v4 or v6).
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        # Match IPv4
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
            return True
        # Match IPv6
        if host.startswith('[') and host.endswith(']'):
            return True
    except Exception:
        pass
    return False

def is_shortened_url(url: str) -> bool:
    """
    Checks if the domain is a known URL shortener service.
    """
    shorteners = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rebrand.ly", 
        "is.gd", "buff.ly", "adf.ly", "ow.ly", "bl.ink"
    }
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().replace("www.", "")
        return host in shorteners
    except Exception:
        return False
