from typing import Dict, Any, List
from models.decision_model import DecisionModel

class AIContextBuilder:
    def build_context(self, model: DecisionModel) -> Dict[str, Any]:
        """
        Extracts a clean, token-efficient, and structured AI context dictionary from a DecisionModel.
        Excludes raw HTML, raw threat intelligence outputs, connection/cache flags, and logs.
        """
        evidence_summary: List[Dict[str, Any]] = []
        for ev in model.correlated_evidence:
            details = ev.technical_details or {}
            # Exclude raw credentials or huge metadata, select only essential summary tokens
            evidence_summary.append({
                "rule_id": ev.triggered_rule,
                "analyzer_name": ev.analyzer_name,
                "confidence": ev.confidence,
                "priority": details.get("priority", "Informational"),
                "quality": details.get("quality", "Unknown"),
                "description": details.get("explainability_summary", ev.explanation)
            })

        # Summarize IOC Consensus
        consensus_summary: List[Dict[str, Any]] = []
        for target, stats in model.ioc_consensus.items():
            # Exclude raw caches, include metadata summaries
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
            "threat_summary": model.threat_intelligence_summary,
            "ioc_consensus": consensus_summary
        }

# Global context builder instance
ai_context_builder = AIContextBuilder()
