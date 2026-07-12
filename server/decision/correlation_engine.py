from typing import List, Dict, Set, Any
from models.decision_model import DecisionModel
from models.evidence_model import Evidence

class CorrelationEngine:
    @staticmethod
    def correlate(model: DecisionModel) -> DecisionModel:
        """
        Deduplicates evidence, builds threat consensus groups (IOC Consensus),
        and maps local-to-threat correlation relationships.
        """
        raw_list = model.classified_evidence
        correlated: List[Evidence] = []
        ignored: List[Evidence] = []
        
        # 1. Group all evidence by target key and split local vs threat
        # target_key -> List[Evidence]
        target_groups: Dict[str, List[Evidence]] = {}
        for ev in raw_list:
            details = ev.technical_details or {}
            target_key = ""
            if "domain" in details:
                target_key = f"domain:{details['domain']}"
            elif "filename" in details:
                target_key = f"file:{details['filename']}"
            elif "brand" in details:
                target_key = f"brand:{details['brand']}"
            elif "url" in details:
                target_key = f"url:{details['url']}"
            elif "ip" in details:
                target_key = f"ip:{details['ip']}"
            else:
                target_key = f"rule:{ev.triggered_rule}"
                
            target_groups.setdefault(target_key, []).append(ev)
            
        # 2. Build IOC Consensus for threat evidence per target key
        ioc_consensus_map: Dict[str, Dict[str, Any]] = {}
        
        for target_key, group in target_groups.items():
            threat_items = [ev for ev in group if ev.category == "THREAT_INT"]
            if not threat_items:
                continue
                
            # Aggregate stats
            provider_names = [ev.analyzer_name for ev in threat_items]
            unique_providers = list(set(provider_names))
            
            # Count detecting vs clean/no-data
            detecting_providers = []
            campaign_tags = set()
            freshness_hierarchy = ["LIVE", "RECENT", "STALE", "ARCHIVED"]
            best_freshness = "ARCHIVED"
            highest_severity = "INFO"
            severity_hierarchy = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            
            total_reliability = 0.0
            for ev in threat_items:
                details = ev.technical_details or {}
                # Extract tags
                tags = details.get("tags", [])
                for t in tags:
                    campaign_tags.add(t)
                
                # Check freshness
                fresh = ev.freshness
                if fresh in freshness_hierarchy:
                    if freshness_hierarchy.index(fresh) < freshness_hierarchy.index(best_freshness):
                        best_freshness = fresh
                        
                # Check severity
                sev = ev.severity
                if sev in severity_hierarchy:
                    if severity_hierarchy.index(sev) < severity_hierarchy.index(highest_severity):
                        highest_severity = sev
                        
                # Determine if it's a detection
                if ev.severity in ["MEDIUM", "HIGH", "CRITICAL"]:
                    detecting_providers.append(ev.analyzer_name)
                    total_reliability += ev.provider_reliability
                    
            detect_count = len(set(detecting_providers))
            total_count = len(unique_providers)
            
            agreement_score = 0.0
            if total_count > 0:
                agreement_score = detect_count / total_count
                
            # Average reliability of detecting providers
            avg_reliability = (total_reliability / detect_count) if detect_count > 0 else 0.80
            
            # Consensus confidence: agreement * reliability, bounded at 0.95
            consensus_confidence = min(0.95, agreement_score * avg_reliability)
            
            ioc_consensus_map[target_key] = {
                "provider_count": total_count,
                "detecting_providers": list(set(detecting_providers)),
                "supporting_providers": unique_providers,
                "agreement_score": agreement_score,
                "confidence": consensus_confidence,
                "freshness": best_freshness,
                "campaign_tags": list(campaign_tags),
                "severity": highest_severity
            }
            
        # 3. Settle correlation relationship and deduplicate target groups
        for target_key, group in target_groups.items():
            local_items = [ev for ev in group if ev.category != "THREAT_INT"]
            threat_items = [ev for ev in group if ev.category == "THREAT_INT"]
            
            # If no local items, this is an independent threat finding
            if not local_items:
                if threat_items:
                    # Settle consensus copy of threat evidence
                    consensus_stats = ioc_consensus_map[target_key]
                    primary_ev = threat_items[0]
                    
                    # Merge technical details
                    merged_details = dict(primary_ev.technical_details)
                    merged_details.update(consensus_stats)
                    
                    # Map rule ID based on severity
                    rule_id = "TI_004"
                    if consensus_stats["severity"] == "CRITICAL":
                        rule_id = "TI_001"
                    elif consensus_stats["severity"] in ["HIGH", "MEDIUM"]:
                        rule_id = "TI_002"
                    elif consensus_stats["severity"] == "LOW":
                        rule_id = "TI_003"
                        
                    consensus_ev = Evidence(
                        evidence_id=primary_ev.evidence_id,
                        analyzer_name="ThreatConsensus",
                        category="THREAT_INT",
                        severity=consensus_stats["severity"],
                        triggered_rule=rule_id,
                        technical_details=merged_details,
                        confidence=consensus_stats["confidence"],
                        risk_contribution=primary_ev.risk_contribution,
                        explanation=primary_ev.explanation,
                        recommendation=primary_ev.recommendation,
                        timestamp=primary_ev.timestamp,
                        
                        provider_reliability=primary_ev.provider_reliability,
                        freshness=consensus_stats["freshness"],
                        supporting_providers=consensus_stats["supporting_providers"],
                        agreement_score=consensus_stats["agreement_score"]
                    )
                    correlated.append(consensus_ev)
                    # Ignore the rest of threat items
                    for item in threat_items[1:]:
                        ignored.append(item)
                continue
                
            # Settle first local item as primary correlated item
            primary_local = local_items[0]
            local_details = dict(primary_local.technical_details)
            supporting_rules = local_details.get("supporting_rules", [primary_local.triggered_rule])
            
            # Map relation if threat data exists
            relationship = "independent"
            if target_key in ioc_consensus_map:
                consensus = ioc_consensus_map[target_key]
                detect_count = len(consensus["detecting_providers"])
                
                if detect_count > 0:
                    if primary_local.severity in ["HIGH", "CRITICAL"]:
                        relationship = "independent_confirmation"
                    else:
                        relationship = "supports"
                        
                    # Boost local confidence based on threat consensus
                    boost = consensus["agreement_score"] * 0.20
                    primary_local.confidence = min(1.0, primary_local.confidence + boost)
                else:
                    relationship = "contradicts"
                    
                local_details["threat_consensus"] = consensus
                local_details["supporting_providers"] = consensus["supporting_providers"]
                local_details["agreement_score"] = consensus["agreement_score"]
                
            local_details["correlation_relationship"] = relationship
            
            # Merge additional local items
            prio_hierarchy = ["Critical", "High", "Medium", "Low", "Informational", "Benign"]
            severity_hierarchy = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            
            for other_local in local_items[1:]:
                if other_local.triggered_rule not in supporting_rules:
                    supporting_rules.append(other_local.triggered_rule)
                
                # Boost confidence
                primary_local.confidence = min(1.0, primary_local.confidence + (other_local.confidence * 0.15))
                
                # Upgrade priority if new item has higher priority
                curr_prio = local_details.get("priority", "Informational")
                other_details = other_local.technical_details or {}
                other_prio = other_details.get("priority", "Informational")
                if curr_prio in prio_hierarchy and other_prio in prio_hierarchy:
                    if prio_hierarchy.index(other_prio) < prio_hierarchy.index(curr_prio):
                        local_details["priority"] = other_prio
                        
                # Also upgrade severity of target evidence object
                curr_sev = primary_local.severity
                other_sev = other_local.severity
                if curr_sev in severity_hierarchy and other_sev in severity_hierarchy:
                    if severity_hierarchy.index(other_sev) < severity_hierarchy.index(curr_sev):
                        primary_local.severity = other_sev
                        
                # Merge other_local technical details
                for k, v in other_details.items():
                    if k not in local_details and k not in ["priority", "reliability", "quality", "supporting_rules", "merged_confidence"]:
                        local_details[k] = v
                        
                ignored.append(other_local)
                
            # Merge ignored threat items
            for threat_item in threat_items:
                ignored.append(threat_item)
                
            local_details["supporting_rules"] = supporting_rules
            primary_local.technical_details = local_details
            correlated.append(primary_local)
            
        # Build correlation graph logs
        trace = list(model.decision_trace)
        trace.append(f"CORRELATED: Deduplicated {len(raw_list)} items into {len(correlated)} threat chains. Ignored duplicates: {len(ignored)}.")
        
        meta = dict(model.metadata)
        meta["correlation_count"] = len(correlated)
        meta["ignored_duplicate_count"] = len(ignored)
        meta["ioc_consensus"] = ioc_consensus_map
        
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
            metadata=meta,
            
            # Add threat summaries to DecisionModel
            threat_intelligence_summary={
                "provider_count": sum(c["provider_count"] for c in ioc_consensus_map.values()),
                "total_detections": sum(len(c["detecting_providers"]) for c in ioc_consensus_map.values())
            },
            ioc_consensus=ioc_consensus_map
        )
