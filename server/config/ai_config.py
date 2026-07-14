import os

# Centralized AI Configuration settings
CLAUDE_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-20241022")
TEMPERATURE = 0.0
MAX_TOKENS = 1000
TIMEOUT_SEC = 15.0
RETRY_COUNT = 2
RETRY_DELAY_SEC = 1.0

# Hard Token Budget limits
TOKEN_BUDGET = 4000  # maximum input tokens allowed per query
PROMPT_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0.0"

# API Configuration
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
