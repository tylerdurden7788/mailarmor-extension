import os
import urllib.parse
from typing import Tuple, List, Dict
from models.url_model import ParsedURL
from scanner.url_normalizer import URLCanonicalizer, URLNormalizer
from utils.entropy_strategies import ShannonEntropyStrategy

class URLParser:
    @staticmethod
    def parse(raw_url: str, original_url: str = None) -> Tuple[ParsedURL, List[str]]:
        """
        Parses a raw URL into an immutable ParsedURL model after canonicalization and normalization.
        Returns: (parsed_url_object, list_of_normalization_warnings)
        """
        warnings = []
        if not raw_url:
            raise ValueError("URL cannot be empty")
            
        # 1. Canonicalize
        canonical = URLCanonicalizer.canonicalize(raw_url)
        
        # 2. Normalize
        normalized, norm_warnings = URLNormalizer.normalize(canonical)
        warnings.extend(norm_warnings)
        
        # 3. Parse details
        try:
            parsed = urllib.parse.urlparse(normalized)
        except Exception as e:
            raise ValueError(f"Failed to parse normalized URL: {e}")
            
        scheme = parsed.scheme.lower()
        host = parsed.netloc.lower()
        
        # Extract username/password if present
        username = parsed.username
        password = parsed.password
        
        # Extract hostname clean (removing credentials)
        hostname = parsed.hostname or ""
        
        # Extract port
        port = parsed.port
        
        # Extract root domain & public suffix (basic matching for testing)
        root_domain, public_suffix, subdomains = URLParser._extract_domain_pieces(hostname)
        
        # Extract query parameters
        query_dict = {}
        if parsed.query:
            query_dict = dict(urllib.parse.parse_qsl(parsed.query))
            
        # Extract file extension
        path = parsed.path
        file_ext = None
        if path:
            _, ext = os.path.splitext(path)
            if ext:
                file_ext = ext.lower()
                
        # Character entropy using Shannon Entropy
        entropy_calc = ShannonEntropyStrategy()
        entropy = entropy_calc.calculate_entropy(normalized)
        
        parsed_url_obj = ParsedURL(
            scheme=scheme,
            host=hostname,
            root_domain=root_domain,
            public_suffix=public_suffix,
            subdomains=subdomains,
            port=port,
            username=username,
            password=password,
            path=path,
            query_params=query_dict,
            fragment=parsed.fragment or None,
            file_extension=file_ext,
            length=len(normalized),
            character_entropy=entropy,
            raw_url=original_url or raw_url,
            normalized_url=normalized
        )
        
        return parsed_url_obj, warnings

    @staticmethod
    def _extract_domain_pieces(hostname: str) -> Tuple[str, str, List[str]]:
        """
        Splits a hostname into (root_domain, public_suffix, list_of_subdomains).
        Uses a standard mapping for common public suffixes.
        """
        if not hostname:
            return "", "", []
            
        # Match common double suffixes (co.uk, com.au, org.uk, net.au, gov.uk etc.)
        double_suffixes = {
            "co.uk", "me.uk", "org.uk", "net.uk", "ltd.uk", "plc.uk", "sch.uk",
            "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
            "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp", "ad.jp", "co.in", "firm.in",
            "net.in", "org.in", "gen.in", "ind.in", "com.tw", "net.tw", "org.tw"
        }
        
        parts = hostname.split('.')
        if len(parts) == 1:
            return hostname, "", []
            
        # Check if the last two parts match a known double suffix
        if len(parts) >= 3:
            potential_double = ".".join(parts[-2:])
            if potential_double in double_suffixes:
                public_suffix = potential_double
                root_domain = ".".join(parts[-3:])
                subdomains = parts[:-3]
                return root_domain, public_suffix, subdomains
                
        # Fallback to single suffix
        public_suffix = parts[-1]
        root_domain = ".".join(parts[-2:])
        subdomains = parts[:-2]
        return root_domain, public_suffix, subdomains
