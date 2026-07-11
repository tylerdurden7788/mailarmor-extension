from typing import List, Dict, Set, Any
from models.decision_model import DecisionModel
from models.evidence_model import Evidence

class CorrelationEngine:
    @staticmethod
    def correlate(model: DecisionModel) -> DecisionModel:
        """
        Deduplicates evidence and builds correlation relationships.
        """
        raw_list = model.classified_evidence
        correlated: List[Evidence] = []
        ignored: List[Evidence] = []
        
        # Deduplication maps: group by target (domain, filename, or brand name)
        # e.g., if there's both an ID_001 homoglyph and a brand mismatch on the same brand, merge confidence
        seen_targets: Dict[str, Evidence] = {}
        
        for ev in raw_list:
            details = ev.technical_details or {}
            target_key = ""
            
            # Identify the unique target signature of the evidence
            if "domain" in details:
                target_key = f"domain:{details['domain']}"
            elif "filename" in details:
                target_key = f"file:{details['filename']}"
            elif "brand" in details:
                target_key = f"brand:{details['brand']}"
            elif "url" in details:
                target_key = f"url:{details['url']}"
            else:
                target_key = f"rule:{ev.triggered_rule}"
                
            if target_key in seen_targets:
                # Merge duplicate indicators
                existing_ev = seen_targets[target_key]
                existing_details = existing_ev.technical_details or {}
                
                # Boost confidence but do not double count risk
                new_confidence = min(1.0, existing_ev.confidence + (ev.confidence * 0.15))
                
                # Append supporting rules list to technical details
                supporting = existing_details.get("supporting_rules", [])
                if ev.triggered_rule not in supporting:
                    supporting.append(ev.triggered_rule)
                existing_details["supporting_rules"] = supporting
                existing_details["merged_confidence"] = new_confidence
                
                # Upgrade priority if new item has higher priority
                prio_hierarchy = ["Critical", "High", "Medium", "Low", "Informational", "Benign"]
                curr_prio = existing_details.get("priority", "Informational")
                new_prio = details.get("priority", "Informational")
                if curr_prio in prio_hierarchy and new_prio in prio_hierarchy:
                    if prio_hierarchy.index(new_prio) < prio_hierarchy.index(curr_prio):
                        existing_details["priority"] = new_prio
                        # Also upgrade severity of target evidence object
                        existing_ev.severity = ev.severity
                        
                # Update existing cloned evidence in-place (conceptually)
                # Since it's frozen, we will re-instantiate later.
                # Mark ev as ignored for risk contribution (duplicate)
                ignored.append(ev)
            else:
                # First time seeing this target
                # Clone details
                details_copy = dict(details)
                details_copy["supporting_rules"] = [ev.triggered_rule]
                details_copy["merged_confidence"] = ev.confidence
                
                ev_copy = Evidence(
                    evidence_id=ev.evidence_id,
                    analyzer_name=ev.analyzer_name,
                    category=ev.category,
                    severity=ev.severity,
                    triggered_rule=ev.triggered_rule,
                    technical_details=details_copy,
                    confidence=ev.confidence,
                    risk_contribution=ev.risk_contribution,
                    explanation=ev.explanation,
                    recommendation=ev.recommendation,
                    timestamp=ev.timestamp
                )
                seen_targets[target_key] = ev_copy
                correlated.append(ev_copy)
                
        # Build correlation graph logs
        trace = list(model.decision_trace)
        trace.append(f"CORRELATED: Deduplicated {len(raw_list)} items into {len(correlated)} threat chains. Ignored duplicates: {len(ignored)}.")
        
        meta = dict(model.metadata)
        meta["correlation_count"] = len(correlated)
        meta["ignored_duplicate_count"] = len(ignored)
        
        return DecisionModel(
            evidence_report=model.evidence_report,
            classified_evidence=model.classified_evidence,
            correlated_evidence=correlated,
            ignored_evidence=ignored,
            conflicting_evidence=model.conflicting_evidence,
            suppressed_evidence=model.suppressed_evidence,
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
