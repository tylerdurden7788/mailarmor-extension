import re

def is_mixed_script(text: str) -> bool:
    """
    Detects mixed-script strings (e.g. mixture of Latin and Cyrillic/Greek characters),
    which is the signature of IDN homoglyph attacks.
    """
    if not text:
        return False
    
    has_latin = False
    has_cyrillic = False
    has_greek = False
    
    for char in text:
        code = ord(char)
        # Check standard Latin
        if (65 <= code <= 90) or (97 <= code <= 122):
            has_latin = True
        # Check Cyrillic block
        elif 0x0400 <= code <= 0x04FF:
            has_cyrillic = True
        # Check Greek block
        elif 0x0370 <= code <= 0x03FF:
            has_greek = True
            
    # If the text uses a combination of multiple alphabets
    scripts_detected = sum([has_latin, has_cyrillic, has_greek])
    return scripts_detected > 1

def punycode_decode(domain: str) -> str:
    """
    Converts punycode IDN (e.g. xn--pypal-43d.com) into standard Unicode.
    """
    if not domain:
        return ""
    try:
        # Check parts of the domain
        parts = domain.split('.')
        decoded_parts = []
        for part in parts:
            if part.lower().startswith("xn--"):
                decoded_parts.append(part.encode("ascii").decode("idna"))
            else:
                decoded_parts.append(part)
        return ".".join(decoded_parts)
    except Exception:
        pass
    return domain.lower()

def get_confusables_count(text: str) -> int:
    """
    Checks count of common confusable characters (Cyrillic lookalikes of a, c, e, o, p, y, x).
    """
    # Cyrillic lookalikes commonly used
    confusables = {
        '\u0430': 'a', # Cyrillic small letter a
        '\u0441': 'c', # Cyrillic small letter es
        '\u0435': 'e', # Cyrillic small letter ie
        '\u043e': 'o', # Cyrillic small letter o
        '\u0440': 'p', # Cyrillic small letter er
        '\u0443': 'y', # Cyrillic small letter u
        '\u0445': 'x', # Cyrillic small letter ha
    }
    count = 0
    for char in text:
        if char in confusables:
            count += 1
    return count
