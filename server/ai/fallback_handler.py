from typing import Dict, Any
from models.decision_model import DecisionModel
from config.ai_config import SCHEMA_VERSION

class FallbackHandler:
    def get_fallback_verdict(self, model: DecisionModel, error_msg: str) -> Dict[str, Any]:
        """
        Generates a deterministic local threat classification fallback to safeguard pipeline operations.
        Ensures the local rule engine verdict is preserved.
        """
        # Determine a compatible attack type
        attack_type = "Unknown"
        if model.attack_types:
            attack_type = model.attack_types[0]
        elif model.risk_level in ["Critical", "High"]:
            attack_type = "Phishing"

        return {
            "attack_type": attack_type,
            "confidence": model.confidence,
            "user_explanation": "A potential security risk was detected. Please review the highlighted flags.",
            "technical_explanation": (
                f"Local rules triggered a risk assessment of '{model.risk_level}'. "
                f"AI orchestration failed over to local fallback. Diagnostic: {error_msg}"
            ),
            "uncertainties": ["AI analysis unavailable due to processing error"],
            "schema_version": SCHEMA_VERSION
        }

# Global fallback handler instance
fallback_handler = FallbackHandler()
