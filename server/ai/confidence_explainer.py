from models.decision_model import DecisionModel

class ConfidenceExplainer:
    def explain_confidence(self, model: DecisionModel) -> str:
        """
        Generates a factor-based explanation attributing the confidence score to specific factors.
        """
        conf_val = model.confidence
        evidence_list = model.correlated_evidence or []
        consensus = model.ioc_consensus or {}
        conflict = model.conflicting_evidence or []

        reasons = []
        
        # Factor 1: Local triggers count
        triggers_count = len(evidence_list)
        if triggers_count >= 3:
            reasons.append(f"high agreement among local security check engines ({triggers_count} active signals)")
        elif triggers_count == 1:
            reasons.append("a single isolated local trigger was flagged")
        else:
            reasons.append(f"moderate agreement among local security check engines ({triggers_count} active signals)")

        # Factor 2: Threat Intelligence consensus
        if consensus:
            active_ioc_providers = 0
            for stats in consensus.values():
                active_ioc_providers += stats.get("provider_count", 0)
            if active_ioc_providers > 0:
                reasons.append(f"supporting confirmation from threat intelligence providers (total provider hits: {active_ioc_providers})")

        # Factor 3: Conflict resolution
        if conflict:
            reasons.append(f"presence of conflicting evidence indicators ({len(conflict)} unresolved conflicts)")

        explanation_str = " and ".join(reasons) if reasons else "clean baseline check indicators"
        return f"Confidence score of {conf_val:.2f} is attributed to: {explanation_str}."

# Global confidence explainer instance
confidence_explainer = ConfidenceExplainer()
