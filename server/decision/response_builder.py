from typing import Dict, Any
from models.decision_model import DecisionModel

class ResponseBuilder:
    @staticmethod
    def build(model: DecisionModel) -> Dict[str, Any]:
        """
        Formats the final DecisionModel into a clean, backward-compatible API dict.
        """
        evidence_summary = []
        for ev in model.correlated_evidence:
            details = ev.technical_details or {}
            evidence_summary.append({
                "rule_id": ev.triggered_rule,
                "analyzer_name": ev.analyzer_name,
                "confidence": ev.confidence,
                "priority": details.get("priority", "Informational"),
                "description": details.get("explainability_summary", "")
            })
            
        return {
            "verdict": model.verdict,
            "confidence": model.confidence,
            "explanation": model.user_explanation,
            "technical_explanation": model.technical_explanation,
            "recommendations": model.recommendations,
            "attack_categories": model.attack_types,
            "evidence_summary": evidence_summary,
            "risk_level": model.risk_level,
            "decision_trace": model.decision_trace,
            "metadata": {
                "decision_engine_version": "2.0.0",
                "rules_version": "2.0.0",
                "evidence_count": len(model.evidence_report.evidence_list),
                "correlated_count": len(model.correlated_evidence)
            }
        }
        
    @staticmethod
    def build_legacy_compatible(model: DecisionModel) -> Dict[str, Any]:
        """
        Builds a legacy compatible format if the extension expects the old schema directly.
        """
        base = ResponseBuilder.build(model)
        # Add legacy fields if any existed in previous versions
        base["is_dangerous"] = model.verdict == "DANGEROUS"
        base["is_suspicious"] = model.verdict == "SUSPICIOUS"
        return base
