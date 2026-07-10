from typing import List, Dict, Any
from models.evidence_model import Evidence

class EvidenceCollector:
    @staticmethod
    def collect_and_process(raw_evidence: List[Evidence]) -> List[Evidence]:
        """
        Processes raw evidence:
        1. Deduplicates / merges identical rule triggers.
        2. Correlates related evidence items to build supporting linkages and dynamically boost confidence.
        """
        if not raw_evidence:
            return []
            
        # 1. Deduplication (Group by triggered_rule)
        grouped_evidence: Dict[str, List[Evidence]] = {}
        for ev in raw_evidence:
            grouped_evidence.setdefault(ev.triggered_rule, []).append(ev)
            
        merged_evidence: List[Evidence] = []
        for rule_id, evs in grouped_evidence.items():
            if len(evs) == 1:
                # Store supporting analyzer name list by default
                ev = evs[0]
                ev.technical_details["supporting_analyzers"] = [ev.analyzer_name]
                merged_evidence.append(ev)
            else:
                # Merge duplicate findings
                primary = evs[0]
                supporting_analyzers = list(set(e.analyzer_name for e in evs))
                primary.technical_details["supporting_analyzers"] = supporting_analyzers
                
                # Take maximum confidence and risk contribution
                max_confidence = max(e.confidence for e in evs)
                max_risk = max(e.risk_contribution for e in evs)
                
                primary.confidence = max_confidence
                primary.risk_contribution = max_risk
                
                # Merge technical details dictionaries
                merged_tech = {}
                for e in evs:
                    if isinstance(e.technical_details, dict):
                        merged_tech.update(e.technical_details)
                primary.technical_details.update(merged_tech)
                
                merged_evidence.append(primary)
                
        # 2. Correlation & Confidence Boosting
        # Let's map evidence by rule ID for quick lookup
        evidence_by_rule: Dict[str, Evidence] = {ev.triggered_rule: ev for ev in merged_evidence}
        
        # Define correlation rules: key (parent rule) gets supported by values (child rules)
        correlation_map = {
            "BRD_001": ["SND_002", "SND_003"],            # Brand Impersonation supported by Display-name / Free-email spoofing
            "BRD_002": ["SND_002", "SND_003"],            # Fake Department supported by Display-name / Free-email spoofing
            "HDR_001": ["BRD_001", "BRD_002", "SND_001"], # Header inconsistency supported by Brand spoofing or Reply-To mismatch
            "UNI_001": ["BRD_001", "DOM_002"]             # Homograph supported by Brand spoofing or suspicious TLD
        }
        
        for parent_rule, children_rules in correlation_map.items():
            if parent_rule in evidence_by_rule:
                parent_ev = evidence_by_rule[parent_rule]
                supporting_ids = []
                
                for child_rule in children_rules:
                    if child_rule in evidence_by_rule:
                        child_ev = evidence_by_rule[child_rule]
                        supporting_ids.append(child_ev.evidence_id)
                        
                if supporting_ids:
                    # Found correlation! Boost confidence by 15% per supporting indicator (capped at 1.0)
                    parent_ev.technical_details["supporting_evidence_ids"] = supporting_ids
                    boost = 0.15 * len(supporting_ids)
                    parent_ev.confidence = min(1.0, parent_ev.confidence + boost)
                    # Increase risk contribution proportionately due to stronger evidence correlation
                    parent_ev.risk_contribution = min(100.0, parent_ev.risk_contribution * (1.0 + boost))
                    
        return merged_evidence
