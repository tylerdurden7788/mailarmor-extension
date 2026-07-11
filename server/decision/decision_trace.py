from models.decision_model import DecisionModel

class DecisionTrace:
    @staticmethod
    def generate(model: DecisionModel) -> DecisionModel:
        """
        Finalizes the structured decision trace list.
        """
        trace = list(model.decision_trace)
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
            metadata=model.metadata
        )
