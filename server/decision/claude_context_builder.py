from typing import Dict, Any
from models.decision_model import DecisionModel

class ClaudeContextBuilder:
    @staticmethod
    def build(model: DecisionModel) -> Dict[str, Any]:
        """
        Creates a clean, token-efficient structured context for Claude.
        """
        evidence_summary = []
        for ev in model.correlated_evidence:
            details = ev.technical_details or {}
            evidence_summary.append({
                "rule_id": ev.triggered_rule,
                "analyzer_name": ev.analyzer_name,
                "confidence": ev.confidence,
                "priority": details.get("priority", "Informational"),
                "quality": details.get("quality", "Unknown"),
                "description": details.get("explainability_summary", "")
            })
            
        return {
            "risk_level": model.risk_level,
            "attack_types": model.attack_types,
            "confidence_score": model.confidence,
            "evidence_count": len(evidence_summary),
            "evidence": evidence_summary
        }
