from typing import List, Set
from models.decision_model import DecisionModel
from config.risk_taxonomy import RULE_TAXONOMY_MAP

class RiskEngine:
    @staticmethod
    def assess(model: DecisionModel) -> DecisionModel:
        """
        Determines attack category types and maps the overall risk level.
        """
        correlated = model.correlated_evidence
        attack_types: Set[str] = set()
        
        # 1. Map rule IDs to risk taxonomy categories
        for ev in correlated:
            # Map primary
            categories = RULE_TAXONOMY_MAP.get(ev.triggered_rule, [])
            for cat in categories:
                attack_types.add(cat)
            # Map merged supporting
            supporting = (ev.technical_details or {}).get("supporting_rules", [])
            for rule in supporting:
                categories = RULE_TAXONOMY_MAP.get(rule, [])
                for cat in categories:
                    attack_types.add(cat)
                
        # 2. Determine Risk Level based on highest priority
        max_priority = "Benign"
        priority_hierarchy = ["Critical", "High", "Medium", "Low", "Informational", "Benign"]
        
        for ev in correlated:
            details = ev.technical_details or {}
            prio = details.get("priority", "Informational")
            
            # Keep highest priority in hierarchy (smaller index means higher precedence)
            if prio in priority_hierarchy:
                if max_priority == "Benign" or priority_hierarchy.index(prio) < priority_hierarchy.index(max_priority):
                    max_priority = prio
                    
        # Map priority to risk level string
        risk_level = "Minimal"
        if max_priority == "Critical":
            risk_level = "Critical"
        elif max_priority == "High":
            risk_level = "High"
        elif max_priority == "Medium":
            risk_level = "Medium"
        elif max_priority == "Low":
            risk_level = "Low"
            
        trace = list(model.decision_trace)
        trace.append(f"RISK_ASSESSED: Determined risk level of '{risk_level}' with threat types: {list(attack_types)}.")
        
        meta = dict(model.metadata)
        meta["risk_level"] = risk_level
        meta["attack_types_count"] = len(attack_types)
        
        return DecisionModel(
            evidence_report=model.evidence_report,
            classified_evidence=model.classified_evidence,
            correlated_evidence=model.correlated_evidence,
            ignored_evidence=model.ignored_evidence,
            conflicting_evidence=model.conflicting_evidence,
            suppressed_evidence=model.suppressed_evidence,
            confidence=model.confidence,
            risk_level=risk_level,
            attack_types=list(attack_types),
            recommendations=model.recommendations,
            verdict=model.verdict,
            technical_explanation=model.technical_explanation,
            user_explanation=model.user_explanation,
            decision_trace=trace,
            metadata=meta
        )
