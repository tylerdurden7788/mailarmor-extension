import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

class StructuredLogger:
    def __init__(self, name: str = "MailArmourStructured"):
        self.logger = logging.getLogger(name)
        
    def _clean_details(self, details: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not details:
            return {}
        clean = dict(details)
        # Strip sensitive API keys or credentials
        for key in list(clean.keys()):
            if "key" in key.lower() or "token" in key.lower() or "auth" in key.lower() or "password" in key.lower():
                clean[key] = "[REDACTED]"
        return clean

    def _log(self, level: str, event: str, provider_name: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> None:
        log_payload = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "level": level,
            "event": event,
            "provider_name": provider_name,
            "details": self._clean_details(details)
        }
        log_str = json.dumps(log_payload)
        if level == "DEBUG":
            self.logger.debug(log_str)
        elif level == "INFO":
            self.logger.info(log_str)
        elif level == "WARNING":
            self.logger.warning(log_str)
        elif level == "ERROR":
            self.logger.error(log_str)

    def debug(self, event: str, provider_name: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> None:
        self._log("DEBUG", event, provider_name, details)

    def info(self, event: str, provider_name: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> None:
        self._log("INFO", event, provider_name, details)

    def warning(self, event: str, provider_name: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> None:
        self._log("WARNING", event, provider_name, details)

    def error(self, event: str, provider_name: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> None:
        self._log("ERROR", event, provider_name, details)

# Global singleton logger instance
structured_logger = StructuredLogger()
