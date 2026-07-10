import re
import urllib.parse
import unicodedata
from typing import List, Tuple
from utils.unicode_utils import punycode_decode

class URLCanonicalizer:
    @staticmethod
    def canonicalize(url: str) -> str:
        """
        Distinct URL canonicalization stage before normalization.
        Standardizes scheme, host, default ports, trailing slashes, and resolves dot-segments.
        """
        if not url:
            return ""
            
        url = url.strip()
        # Parse URL
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            return url
            
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        
        # 1. Remove default ports
        if ":" in netloc:
            host, port = netloc.split(":", 1)
            if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
                netloc = host
                
        # 2. Resolve dot-segments in path (e.g. /a/b/../c -> /a/c)
        path = parsed.path
        if path:
            segments = []
            for segment in path.split("/"):
                if segment == "..":
                    if segments:
                        segments.pop()
                elif segment != "." and segment != "":
                    segments.append(segment)
            path = "/" + "/".join(segments)
            # Retain trailing slash if it existed in the original path
            if parsed.path.endswith("/") and not path.endswith("/"):
                path += "/"
        else:
            path = "/"
            
        # Reconstruct canonical URL
        canonical = urllib.parse.urlunparse((
            scheme,
            netloc,
            path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
        
        return canonical

class URLNormalizer:
    @staticmethod
    def normalize(url: str) -> Tuple[str, List[str]]:
        """
        Applies structural normalizations on canonical URL.
        Decodes percent encodings (max 3 recursion cycles), punycode, and Unicode NFC formats.
        Returns: (normalized_url, warnings)
        """
        warnings = []
        if not url:
            return "", warnings
            
        # 1. Recursive percent decoding (cap at 3 iterations to prevent DoS)
        curr_url = url
        decoding_steps = 0
        for i in range(4):
            decoded = urllib.parse.unquote(curr_url)
            if decoded == curr_url:
                break
            decoding_steps += 1
            if i == 3:
                warnings.append("Excessive recursive percent encoding detected (> 3 cycles). Truncated decoding.")
                break
            curr_url = decoded
            
        if decoding_steps > 1:
            warnings.append("Double percent encoding detected.")
            
        # Parse components
        try:
            parsed = urllib.parse.urlparse(curr_url)
        except Exception as e:
            return curr_url, [f"Failed to parse during normalization: {e}"]
            
        scheme = parsed.scheme.lower()
        host = parsed.netloc.lower()
        
        # 2. Unicode normalization (NFC)
        host = unicodedata.normalize("NFC", host)
        
        # 3. Punycode decoding
        host = punycode_decode(host)
        
        # 4. Collapse duplicate slashes in path (retaining double slash after scheme)
        path = parsed.path
        if path:
            path = re.sub(r'/{2,}', '/', path)
            
        # Reconstruct normalized URL
        normalized = urllib.parse.urlunparse((
            scheme,
            host,
            path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
        
        return normalized, warnings
