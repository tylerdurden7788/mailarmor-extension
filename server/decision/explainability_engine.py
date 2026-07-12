from typing import List
from models.decision_model import DecisionModel

class ExplainabilityEngine:
    @staticmethod
    def generate(model: DecisionModel) -> DecisionModel:
        """
        Generates user-facing and administrator technical explanations citing threat intelligence.
        """
        verdict = model.verdict
        attacks = model.attack_types
        triggered_rules = [ev.triggered_rule for ev in model.correlated_evidence]
        
        # Threat intelligence citations
        ti_providers = []
        high_agreement = False
        poor_reputation = False
        campaign_match = False
        
        for target, stats in model.ioc_consensus.items():
            ti_providers.extend(stats.get("supporting_providers", []))
            if stats.get("agreement_score", 0.0) >= 0.50:
                high_agreement = True
            if stats.get("severity") in ["HIGH", "CRITICAL"]:
                poor_reputation = True
            if stats.get("campaign_tags"):
                campaign_match = True
                
        ti_providers = list(set(ti_providers))
        
        if verdict in ["DANGEROUS", "SUSPICIOUS"]:
            # Non-technical explanation templates
            if high_agreement:
                user_explanation = "This website has been reported as malicious by multiple independent security providers."
            elif campaign_match:
                user_explanation = "The sender's infrastructure matches previously reported phishing campaigns."
            elif poor_reputation:
                user_explanation = "The domain has a poor reputation across several intelligence feeds."
            else:
                user_explanation = (
                    f"This email has been flagged as {verdict.lower()} because it contains indicators of "
                    f"potential {', '.join(attacks) if attacks else 'phishing or deception'}."
                )
                
            technical_explanation = (
                f"Decision Engine triggered {verdict} based on rules: {', '.join(triggered_rules)}. "
                f"Risk assessment: {model.risk_level} severity. "
            )
            if ti_providers:
                technical_explanation += f"Supporting intelligence: {', '.join(ti_providers)}."
        else:
            user_explanation = "This email appears safe. No suspicious visual, HTML, or semantic indicators were found."
            technical_explanation = f"Analysis concluded with SAFE/LIKELY_SAFE verdict. Triggered indicators: {', '.join(triggered_rules) if triggered_rules else 'none'}."
            if ti_providers:
                technical_explanation += f" Telemetry collected from: {', '.join(ti_providers)}."
            
        trace = list(model.decision_trace)
        trace.append("EXPLANATION_GENERATED: Created technical and non-technical summaries citing threat providers.")
        
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
            metadata=model.metadata,
            
            threat_intelligence_summary=model.threat_intelligence_summary,
            ioc_consensus=model.ioc_consensus
        )
