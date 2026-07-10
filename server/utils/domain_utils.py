import re
from urllib.parse import urlparse

def extract_domain(sender_str: str) -> str:
    """
    Extracts cleaner domain name from a sender header string.
    E.g. "Google Security <no-reply@security.google.com>" -> "security.google.com"
    """
    if not sender_str:
        return ""
    
    # Try finding email inside angle brackets
    match = re.search(r'<([^>]+)>', sender_str)
    email = match.group(1) if match else sender_str
    
    # Clean whitespace and split
    email = email.strip()
    if '@' in email:
        return email.split('@')[-1].lower()
    
    return email.lower()

def is_valid_domain(domain: str) -> bool:
    """
    Simple check to determine if domain matches standard characters.
    """
    if not domain:
        return False
    return bool(re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain))
