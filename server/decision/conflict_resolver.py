from typing import List
from models.decision_model import DecisionModel
from models.evidence_model import Evidence

class ConflictResolver:
    @staticmethod
    def resolve(model: DecisionModel) -> DecisionModel:
        """
        Resolves contradictory evidence based on precedence policies.
        """
        correlated = model.correlated_evidence
        resolved: List[Evidence] = []
        conflicting: List[Evidence] = []
        suppressed: List[Evidence] = []
        
        # Check authentication status
        # If SPF/DKIM is valid, it shouldn't override visual deception or homoglyph
        # Let's inspect the evidence list for critical rules and authentication status
        has_critical = any(
            (ev.technical_details or {}).get("priority") == "Critical" 
            for ev in correlated
        )
        has_auth_pass = any(
            ev.triggered_rule == "AUTH_001" or "auth" in ev.triggered_rule.lower() 
            for ev in model.evidence_report.evidence_list
        )
        
        for ev in correlated:
            details = ev.technical_details or {}
            rule_id = ev.triggered_rule
            
            # Auth bypass policy: verified critical rules override auth success
            if rule_id in ["AUTH_001", "AUTH_002", "AUTH_003"] and has_critical:
                # Mark authentication passes as conflicting/contextual when critical threats exist
                conflicting.append(ev)
                
                # Clone and adjust priority to low/contextual
                details_copy = dict(details)
                details_copy["priority"] = "Low"
                details_copy["conflict_context"] = "Superseded by critical threat indicators"
                
                ev_copy = Evidence(
                    evidence_id=ev.evidence_id,
                    analyzer_name=ev.analyzer_name,
                    category=ev.category,
                    severity=ev.severity,
                    triggered_rule=ev.triggered_rule,
                    technical_details=details_copy,
                    confidence=max(0.1, ev.confidence - 0.5),
                    risk_contribution=ev.risk_contribution,
                    explanation=ev.explanation,
                    recommendation=ev.recommendation,
                    timestamp=ev.timestamp
                )
                resolved.append(ev_copy)
            else:
                resolved.append(ev)
                
        trace = list(model.decision_trace)
        trace.append(f"CONFLICT_RESOLVED: Resolved {len(conflicting)} contradictory authentication/visual deception signals.")
        
        meta = dict(model.metadata)
        meta["conflict_resolved_count"] = len(conflicting)
        
        return DecisionModel(
            evidence_report=model.evidence_report,
            classified_evidence=model.classified_evidence,
            correlated_evidence=resolved,
            ignored_evidence=model.ignored_evidence,
            conflicting_evidence=conflicting,
            suppressed_evidence=suppressed,
            confidence=model.confidence,
            risk_level=model.risk_level,
            attack_types=model.attack_types,
            recommendations=model.recommendations,
            verdict=model.verdict,
            technical_explanation=model.technical_explanation,
            user_explanation=model.user_explanation,
            decision_trace=trace,
            metadata=meta
        )
