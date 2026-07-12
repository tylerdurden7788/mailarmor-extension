from typing import List, Dict, Any
from models.decision_model import DecisionModel

class AttackChainBuilder:
    def build_attack_chain(self, model: DecisionModel) -> List[str]:
        """
        Constructs a structured chronological attack progression chain from verified evidence.
        Each node includes a confidence annotation and evidence rule citation.
        """
        evidence_list = model.correlated_evidence or []
        if not evidence_list:
            return ["No security triggers detected (Confidence: 1.0)"]

        # Group triggers by attack stage category
        entry_nodes = []
        deception_nodes = []
        action_nodes = []
        payload_nodes = []
        generic_nodes = []

        for ev in evidence_list:
            cat = ev.category.upper()
            rule = ev.triggered_rule
            conf = ev.confidence
            desc = ev.explanation or "Trigger match"

            node_str = f"{desc} (Confidence: {conf:.2f}) [{rule}]"

            if cat in ["AUTHENTICATION", "UNICODE", "SENDER", "DOMAIN"] or "BR" in rule or "DOM" in rule or "SND" in rule:
                entry_nodes.append(node_str)
            elif cat in ["CONTENT", "INTENT", "REPUTATION"] or "CT" in rule or "SOC" in rule or "INT" in rule:
                deception_nodes.append(node_str)
            elif cat in ["URL", "HTML", "FORM", "IFRAME", "JAVASCRIPT"] or "FRM" in rule or "URL" in rule:
                action_nodes.append(node_str)
            elif cat in ["ATTACHMENT", "MALWARE"] or "ATT" in rule:
                payload_nodes.append(node_str)
            else:
                generic_nodes.append(node_str)

        # Assemble stages chronologically
        chain = []
        if entry_nodes:
            chain.extend(entry_nodes)
        if deception_nodes:
            chain.extend(deception_nodes)
        if action_nodes:
            chain.extend(action_nodes)
        if payload_nodes:
            chain.extend(payload_nodes)
        if generic_nodes and not chain:
            chain.extend(generic_nodes)

        # Limit chain depth if configuration requires it
        from config.explanation_config import ATTACK_CHAIN_DEPTH
        return chain[:ATTACK_CHAIN_DEPTH]

# Global attack chain builder instance
attack_chain_builder = AttackChainBuilder()
