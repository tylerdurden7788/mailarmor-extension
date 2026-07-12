from models.decision_model import DecisionModel

class DecisionTrace:
    @staticmethod
    def generate(model: DecisionModel) -> DecisionModel:
        """
        Finalizes the structured decision trace list.
        Incorporates threat intelligence consensus diagnostics.
        """
        trace = list(model.decision_trace)
        
        # Document consensus telemetry
        consensus_keys = list(model.ioc_consensus.keys())
        if consensus_keys:
            trace.append(f"DIAGNOSTIC: Threat intelligence consensus generated for targets: {', '.join(consensus_keys)}.")
            for target, stats in model.ioc_consensus.items():
                trace.append(
                    f"DIAGNOSTIC: target '{target}' has agreement of {stats.get('agreement_score', 0.0) * 100:.1f}% "
                    f"across {stats.get('provider_count', 0)} providers (Freshness: {stats.get('freshness', 'LIVE')}, Severity: {stats.get('severity', 'INFO')})."
                )
                
        # Append cache statistics if any
        from utils.metrics import metrics_collector
        decision_stats = metrics_collector.get_decision_statistics()
        trace.append(f"DIAGNOSTIC: Decision metrics - average agreement score: {decision_stats.get('average_agreement_score', 0.0):.2f}.")
        
        trace.append("TRACE_GENERATED: Decision pipeline trace finalized and ready for output.")
        
        return DecisionModel(
            evidence_report=model.evidence_report,
            classified_evidence=model.classified_evidence,
            correlated_evidence=model.correlated_evidence,
            ignored_evidence=model.ignored_evidence,
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
            metadata=model.metadata,
            
            threat_intelligence_summary=model.threat_intelligence_summary,
            ioc_consensus=model.ioc_consensus
        )
