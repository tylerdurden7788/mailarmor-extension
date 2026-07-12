from models.decision_model import DecisionModel

class ConfidenceEngine:
    @staticmethod
    def calculate(model: DecisionModel) -> DecisionModel:
        """
        Dynamically computes the overall decision confidence score based on evidence quality.
        Factors in threat intelligence agreement, freshness, and local-to-threat correlation.
        """
        correlated = model.correlated_evidence
        if not correlated:
            return model
            
        # Settle base confidence based on the highest priority evidence
        max_priority_score = 0.10
        critical_count = 0
        high_count = 0
        
        # Threat Intelligence bonus and penalty tracking
        ti_bonus = 0.0
        ti_penalty = 0.0
        
        for ev in correlated:
            details = ev.technical_details or {}
            priority = details.get("priority", "Informational")
            reliability = details.get("reliability", 0.70)
            
            # Map priority weights
            weight = 0.10
            if priority == "Critical":
                weight = 0.95
                critical_count += 1
            elif priority == "High":
                weight = 0.80
                high_count += 1
            elif priority == "Medium":
                weight = 0.60
            elif priority == "Low":
                weight = 0.45
                
            # Base confidence leverages both priority weight and the specific analyzer reliability
            base_score = weight * reliability
            if base_score > max_priority_score:
                max_priority_score = base_score
                
            # Threat intelligence specific metrics
            if ev.category == "THREAT_INT":
                agreement = details.get("agreement_score", 1.0)
                fresh = ev.freshness
                
                # Consensus agreement bonus
                if agreement >= 0.75:
                    ti_bonus += 0.08
                elif agreement >= 0.50:
                    ti_bonus += 0.04
                    
                # Conflict/Disagreement penalty
                if agreement < 0.25:
                    ti_penalty += 0.10
                    
                # Freshness adjustments
                if fresh in ["STALE", "ARCHIVED"]:
                    ti_penalty += 0.05
            else:
                # Local evidence correlated with threat consensus
                relationship = details.get("correlation_relationship", "independent")
                if relationship in ["supports", "independent_confirmation"]:
                    ti_bonus += 0.05
                elif relationship == "contradicts":
                    ti_penalty += 0.08
                    
        # Confidence adjustments / propagation
        confidence = max_priority_score + ti_bonus - ti_penalty
        
        # Agreement bonus: +0.05 for each high/critical indicator beyond the first
        total_strong_indicators = critical_count + high_count
        if total_strong_indicators > 1:
            confidence += (total_strong_indicators - 1) * 0.05
            
        # Upper bound constraint: Capped at 1.0, lower bound at 0.0
        # If there are no local critical/high indicators, cap overall confidence at 0.90
        # to prevent threat intelligence alone from driving full confidence.
        has_strong_local = any(ev.category != "THREAT_INT" and ev.severity in ["HIGH", "CRITICAL"] for ev in correlated)
        cap_limit = 1.0 if has_strong_local else 0.90
        
        confidence = min(cap_limit, max(0.0, confidence))
        
        trace = list(model.decision_trace)
        trace.append(f"CONFIDENCE_CALCULATED: Calculated dynamic confidence score of {confidence:.2f} (Bonus: +{ti_bonus:.2f}, Penalty: -{ti_penalty:.2f}).")
        
        meta = dict(model.metadata)
        meta["confidence_score"] = confidence
        
        return DecisionModel(
            evidence_report=model.evidence_report,
            classified_evidence=model.classified_evidence,
            correlated_evidence=model.correlated_evidence,
            ignored_evidence=model.ignored_evidence,
            conflicting_evidence=model.conflicting_evidence,
            suppressed_evidence=model.suppressed_evidence,
            confidence=confidence,
            risk_level=model.risk_level,
            attack_types=model.attack_types,
            recommendations=model.recommendations,
            verdict=model.verdict,
            technical_explanation=model.technical_explanation,
            user_explanation=model.user_explanation,
            decision_trace=trace,
            metadata=meta,
            
            threat_intelligence_summary=model.threat_intelligence_summary,
            ioc_consensus=model.ioc_consensus
        )
