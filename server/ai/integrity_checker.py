import hashlib

class IntegrityChecker:
    def compute_hash(self, text: str) -> str:
        """Computes SHA-256 hash of text."""
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

# Global integrity checker instance
integrity_checker = IntegrityChecker()
