from models.decision_model import DecisionModel

class ExecutiveSummaryBuilder:
    def build_executive_summary(self, model: DecisionModel) -> str:
        """
        Generates a high-level executive report for management with rule citations.
        """
        evidence_list = model.correlated_evidence or []
        if not evidence_list:
            return "No operational risks or brand abuse detected for corporate assets."

        rule_citations = " ".join([f"[{ev.triggered_rule}]" for ev in evidence_list])
        
        return (
            f"Security Incident Briefing. A corporate email message was classified as '{model.verdict}' "
            f"with an overall risk rating of '{model.risk_level}'. "
            f"This threat is supported by indicators matching rule citations {rule_citations}. "
            "Primary Impact Area: Social engineering and unauthorized brand simulation attempt targeting internal user assets."
        )

# Global executive summary builder instance
executive_summary_builder = ExecutiveSummaryBuilder()
