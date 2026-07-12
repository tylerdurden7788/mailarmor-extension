from typing import Dict, Any, Optional
from models.decision_model import DecisionModel
from config.decision_rules import VERDICT_MAPPINGS

class VerdictFusion:
    @staticmethod
    def fuse(model: DecisionModel, claude_response: Optional[Dict[str, Any]] = None) -> DecisionModel:
        """
        Merges local rule outcomes with AI context analysis into a final deterministic verdict.
        """
        # Determine local confidence tier
        conf = model.confidence
        if conf >= 0.60:
            tier = "High"
        elif conf >= 0.40:
            tier = "Moderate"
        else:
            tier = "Low"
            
        # Lookup base verdict
        local_verdict = VERDICT_MAPPINGS.get((model.risk_level, tier), "UNKNOWN")
        
        # Default safety fallback if not found in map
        if local_verdict == "UNKNOWN":
            if model.risk_level in ["Critical", "High"]:
                local_verdict = "DANGEROUS"
            elif model.risk_level == "Medium":
                local_verdict = "SUSPICIOUS"
            elif model.risk_level == "Low":
                local_verdict = "LIKELY_SAFE"
            else:
                local_verdict = "SAFE"
                
        # Enforce overrides: local critical indicators CANNOT be downgraded by Claude
        has_critical = any(
            (ev.technical_details or {}).get("priority") == "Critical"
            for ev in model.correlated_evidence
        )
        
        final_verdict = local_verdict
        
        if claude_response:
            ai_confidence = claude_response.get("confidence", 0.0)
            ai_type = claude_response.get("attack_type", "Unknown")
            
            # If Claude is highly confident it's a threat, we can upgrade local verdict
            if ai_confidence >= 0.70 and ai_type != "Safe" and local_verdict in ["SAFE", "LIKELY_SAFE", "UNKNOWN"]:
                final_verdict = "SUSPICIOUS"
                
            # Override downgrade: if local verdict is DANGEROUS/SUSPICIOUS due to critical evidence,
            # but Claude says SAFE, we override Claude and keep the critical/suspicious verdict.
            if has_critical and final_verdict in ["SAFE", "LIKELY_SAFE"]:
                final_verdict = "DANGEROUS"
                
        # Make sure that if there is absolutely no evidence, it is SAFE or LIKELY_SAFE
        if not model.correlated_evidence:
            final_verdict = "SAFE"
            
        trace = list(model.decision_trace)
        trace.append(f"VERDICT_FUSED: Fused local rule verdict '{local_verdict}' and Claude response to reach final verdict '{final_verdict}'.")
        
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
            verdict=final_verdict,
            technical_explanation=model.technical_explanation,
            user_explanation=model.user_explanation,
            decision_trace=trace,
            metadata=model.metadata,
            
            threat_intelligence_summary=model.threat_intelligence_summary,
            ioc_consensus=model.ioc_consensus
        )
