from typing import List
from models.decision_model import DecisionModel

class ExplainabilityEngine:
    @staticmethod
    def generate(model: DecisionModel) -> DecisionModel:
        """
        Generates user-facing and administrator technical explanations.
        """
        verdict = model.verdict
        attacks = model.attack_types
        triggered_rules = [ev.triggered_rule for ev in model.correlated_evidence]
        
        if verdict in ["DANGEROUS", "SUSPICIOUS"]:
            user_explanation = (
                f"This email has been flagged as {verdict.lower()} because it contains indicators of "
                f"potential {', '.join(attacks) if attacks else 'phishing or deception'}."
            )
            technical_explanation = (
                f"Decision Engine triggered {verdict} based on rules: {', '.join(triggered_rules)}. "
                f"Risk assessment: {model.risk_level} severity."
            )
        else:
            user_explanation = "This email appears safe. No suspicious visual, HTML, or semantic indicators were found."
            technical_explanation = f"Analysis concluded with SAFE/LIKELY_SAFE verdict. Triggered indicators: {', '.join(triggered_rules) if triggered_rules else 'none'}."
            
        trace = list(model.decision_trace)
        trace.append("EXPLANATION_GENERATED: Created technical and non-technical summaries.")
        
        return DecisionModel(
            evidence_report=model.evidence_report,
            classified_evidence=model.classified_evidence,
            correlated_evidence=model.correlated_evidence,
            ignored_evidence=model.ignored_evidence,
            conflicting_evidence=model.conflicting_evidence,
            suppressed_evidence=model.suppressed_evidence,
            confidence=model.confidence,
            risk_level=model.risk_level,
            attack_types=model.attack_types,
            recommendations=model.recommendations,
            verdict=model.verdict,
            technical_explanation=technical_explanation,
            user_explanation=user_explanation,
            decision_trace=trace,
            metadata=model.metadata
        )
