import re
from urllib.parse import urlparse

class IOCNormalizer:
    @staticmethod
    def normalize_domain(value: str) -> str:
        """Standardizes domains: lowercases, strips spaces, removes protocol and path."""
        cleaned = value.strip().lower()
        if "://" in cleaned:
            # Strip protocol
            cleaned = cleaned.split("://", 1)[1]
        # Split path or port if any
        cleaned = cleaned.split("/", 1)[0]
        cleaned = cleaned.split(":", 1)[0]
        # Strip trailing dot
        if cleaned.endswith("."):
            cleaned = cleaned[:-1]
        return cleaned.strip()

    @staticmethod
    def normalize_url(value: str) -> str:
        """Standardizes URLs: lowercases host portion, removes trailing slashes and fragments."""
        cleaned = value.strip()
        # Parse URL
        if not re.match(r'^[a-zA-Z]+://', cleaned):
            cleaned = "http://" + cleaned
        try:
            parsed = urlparse(cleaned)
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            path = parsed.path
            # Standardize empty path or trailing slash
            if not path:
                path = "/"
            query = f"?{parsed.query}" if parsed.query else ""
            
            # Reconstruct without fragment
            normalized = f"{scheme}://{netloc}{path}{query}"
            if normalized.endswith("/") and path == "/":
                normalized = normalized[:-1]
            return normalized
        except Exception:
            return value.strip().lower()

    @staticmethod
    def normalize_email(value: str) -> str:
        """Standardizes email addresses: lowercases and removes display names/whitespace."""
        cleaned = value.strip().lower()
        # Match angle brackets email format
        match = re.search(r'<([^>]+)>', cleaned)
        if match:
            cleaned = match.group(1)
        return cleaned.strip()

    @staticmethod
    def normalize_ip(value: str) -> str:
        """Standardizes IP addresses: strips whitespace."""
        return value.strip()

    @staticmethod
    def normalize_hash(value: str) -> str:
        """Standardizes hashes: lowercases and removes non-hex characters."""
        cleaned = value.strip().lower()
        return re.sub(r'[^a-f0-9]', '', cleaned)

    @staticmethod
    def normalize(value: str, obs_type: str) -> str:
        """Orchestrates normalization based on Observable type."""
        if obs_type == "Domain":
            return IOCNormalizer.normalize_domain(value)
        elif obs_type == "URL":
            return IOCNormalizer.normalize_url(value)
        elif obs_type == "Email Address":
            return IOCNormalizer.normalize_email(value)
        elif obs_type == "IP Address":
            return IOCNormalizer.normalize_ip(value)
        elif obs_type == "File Hash":
            return IOCNormalizer.normalize_hash(value)
        return value.strip()
