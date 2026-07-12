import logging
from typing import Dict, Any, List
from utils.structured_logger import structured_logger

logger = logging.getLogger("AISecurityLogger")

class AISecurityLogger:
    def log_security_event(self, event_type: str, request_id: str, severity: str, details: Dict[str, Any]) -> None:
        """
        Logs structured AI security incident events.
        Redacts sensitive values or raw details from details.
        """
        # Redact potentially sensitive keys
        safe_details = {k: v for k, v in details.items() if k not in ["secret_value", "pii_value", "raw_prompt", "raw_response"]}
        safe_details["event_type"] = event_type
        safe_details["severity"] = severity
        safe_details["request_id"] = request_id
        
        # Dispatch structured logger
        if severity in ["HIGH", "CRITICAL"]:
            structured_logger.error(f"AI Security Violation [{event_type}]", None, safe_details)
        elif severity == "WARNING":
            structured_logger.warning(f"AI Security Warning [{event_type}]", None, safe_details)
        else:
            structured_logger.info(f"AI Security Audit [{event_type}]", None, safe_details)

# Global security logger instance
ai_security_logger = AISecurityLogger()
