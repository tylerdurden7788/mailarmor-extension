import re
from typing import Tuple, Dict

class PIIRedactor:
    def redact(self, text: str) -> Tuple[str, Dict[str, str], int]:
        """
        Redacts email addresses and phone numbers.
        Returns: (redacted_text, lookup_map, redaction_count)
        """
        lookup = {}
        redacted = text
        count = 0

        # 1. Redact Emails
        email_regex = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_regex, redacted)
        for idx, email in enumerate(sorted(list(set(emails)))):
            placeholder = f"[REDACTED_EMAIL_{idx + 1}]"
            lookup[placeholder] = email
            redacted = redacted.replace(email, placeholder)
            count += 1

        # 2. Redact Phone numbers (matches simple standard digits format)
        phone_regex = r'\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'
        phones = re.findall(phone_regex, redacted)
        for idx, phone in enumerate(sorted(list(set(phones)))):
            placeholder = f"[REDACTED_PHONE_{idx + 1}]"
            lookup[placeholder] = phone
            redacted = redacted.replace(phone, placeholder)
            count += 1

        return redacted, lookup, count

# Global PII redactor instance
pii_redactor = PIIRedactor()
