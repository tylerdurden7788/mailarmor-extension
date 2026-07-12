import re
from typing import Tuple

class SecretRedactor:
    def redact(self, text: str) -> Tuple[str, int]:
        """
        Scans and redacts passwords, authentication tokens, API keys, and bearer tokens.
        """
        redacted = text
        count = 0

        # Patterns matching secrets
        patterns = [
            r"sk-ant-[a-zA-Z0-9_-]{32,}",
            r"sk-[a-zA-Z0-9]{20,}",
            r"Bearer\s+[a-zA-Z0-9\._-]{16,}",
            r"(?i)password\s*[:=]\s*[^\s,\'\"]+",
            r"(?i)api[-_]key\s*[:=]\s*[^\s,\'\"]+"
        ]

        for pattern in patterns:
            matches = re.findall(pattern, redacted)
            for match in matches:
                redacted = redacted.replace(match, "[REDACTED_SECRET]")
                count += 1

        return redacted, count

# Global secret redactor instance
secret_redactor = SecretRedactor()
