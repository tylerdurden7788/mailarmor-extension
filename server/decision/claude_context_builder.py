from typing import Dict, Any, List
from models.decision_model import DecisionModel

class ClaudeContextBuilder:
    @staticmethod
    def build(model: DecisionModel) -> Dict[str, Any]:
        """
        Creates a clean, token-efficient structured context for Claude.
        Summarizes threat intelligence and consensus findings without exposing raw JSON.
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
                "description": details.get("explainability_summary", ev.explanation)
            })
            
        # Summarize IOC Consensus information
        consensus_summary: List[Dict[str, Any]] = []
        for target, stats in model.ioc_consensus.items():
            consensus_summary.append({
                "target": target,
                "provider_count": stats.get("provider_count", 0),
                "agreement_score": stats.get("agreement_score", 0.0),
                "supporting_providers": stats.get("supporting_providers", []),
                "freshness": stats.get("freshness", "LIVE"),
                "campaign_tags": stats.get("campaign_tags", []),
                "severity": stats.get("severity", "INFO")
            })

        return {
            "risk_level": model.risk_level,
            "attack_types": model.attack_types,
            "confidence_score": model.confidence,
            "evidence_count": len(evidence_summary),
            "evidence": evidence_summary,
            
            # Threat intelligence context
            "threat_summary": model.threat_intelligence_summary,
            "ioc_consensus": consensus_summary
        }
