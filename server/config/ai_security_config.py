import re

# Central AI Security Settings
SECURITY_POLICY_VERSION = "1.0.0"
MAX_PROMPT_SIZE = 20000

# Allowed Capabilities
ALLOWED_CAPABILITIES = [
    "email_threat_analysis",
    "email_threat_explainability"
]

# Blocked Prompt Patterns (Prompt Injection / Override check regexes)
BLOCKED_PROMPT_PATTERNS = [
    r"(?i)ignore\s+(?:all\s+)?previous\s+instructions",
    r"(?i)reveal\s+(?:your\s+)?system\s+prompt",
    r"(?i)act\s+as\s+(?:a\s+)?developer",
    r"(?i)forget\s+(?:your\s+)?rules",
    r"(?i)developer\s+mode",
    r"(?i)dan\s+mode",
    r"(?i)system\s+override"
]

# Blocked Response Patterns (Sensitive key/secret formats in responses)
BLOCKED_RESPONSE_PATTERNS = [
    r"sk-ant-[a-zA-Z0-9_-]{32,}",
    r"AI_SECRET_[a-zA-Z0-9_-]+",
    r"Bearer\s+[a-zA-Z0-9\._-]{16,}"
]

# PII Redaction Policy
REDACT_EMAIL = True
REDACT_PHONE = True
REDACT_NAMES = True

# Secret Redaction Policy
REDACT_API_KEYS = True
REDACT_CREDENTIALS = True
REDACT_BEARER_TOKENS = True
