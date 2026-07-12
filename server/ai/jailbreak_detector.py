import re
from typing import Tuple, List

class JailbreakDetector:
    def detect_jailbreak(self, text: str) -> Tuple[bool, List[str], str]:
        """
        Scans input for common jailbreak behaviors.
        Returns: (is_jailbreak, violations, severity)
        """
        violations = []
        severity = "INFO"
        
        patterns = {
            "Ignore previous instructions": r"(?i)ignore\s+(?:all\s+)?previous\s+instructions",
            "Reveal system prompt": r"(?i)reveal\s+(?:your\s+)?system\s+prompt",
            "DAN Mode override": r"(?i)dan\s+mode",
            "Developer Mode roleplay": r"(?i)developer\s+mode",
            "Forget rules/instructions": r"(?i)forget\s+(?:your\s+)?(?:rules|instructions)"
        }

        for name, pattern in patterns.items():
            if re.search(pattern, text):
                violations.append(f"Jailbreak signature match: '{name}'")
                severity = "HIGH"

        is_jailbreak = len(violations) > 0
        return is_jailbreak, violations, severity

# Global jailbreak detector instance
jailbreak_detector = JailbreakDetector()
