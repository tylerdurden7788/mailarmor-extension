import re
import html

def normalize_whitespace(text: str) -> str:
    """
    Collapses multiple spaces, tabs, and line breaks into single variants.
    """
    if not text:
        return ""
    # Normalize unicode spaces
    text = text.replace('\xa0', ' ')
    return re.sub(r'\s+', ' ', text).strip()

def decode_html_text(text: str) -> str:
    """
    Decodes HTML entity encodings recursively (e.g. &amp; -> &).
    """
    if not text:
        return ""
    prev = ""
    curr = text
    # Loop to handle double-encoded characters
    for _ in range(5):
        prev = curr
        curr = html.unescape(curr)
        if curr == prev:
            break
    return curr
