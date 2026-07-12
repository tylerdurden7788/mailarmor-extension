from typing import List
from models.decision_model import DecisionModel

class AnalystReportBuilder:
    def build_analyst_report(self, model: DecisionModel) -> str:
        """
        Generates a high-fidelity technical report for SOC analysts with rule citations.
        """
        evidence_list = model.correlated_evidence or []
        if not evidence_list:
            return "No malicious indicators detected. Auth passes and local checks remain clean."

        rule_citations = ", ".join([f"[{ev.triggered_rule}]" for ev in evidence_list])
        
        report = (
            f"Incident Analysis Report (Verdict: {model.verdict}). "
            f"MailArmour local engines detected a risk level of '{model.risk_level}' supported by rule citations: {rule_citations}. "
            "Evidence Breakdown:\n"
        )
        
        for ev in evidence_list:
            report += f"- Rule [{ev.triggered_rule}] ({ev.category} by {ev.analyzer_name}): {ev.explanation} (Confidence: {ev.confidence:.2f})\n"
            
        if model.ioc_consensus:
            report += "\nThreat Intelligence Consensus:\n"
            for target, stats in model.ioc_consensus.items():
                report += (
                    f"- Target '{target}': Providers count = {stats.get('provider_count', 0)}, "
                    f"Agreement Score = {stats.get('agreement_score', 0.0):.2f}, Severity = {stats.get('severity')}\n"
                )
                
        return report

# Global analyst report builder instance
analyst_report_builder = AnalystReportBuilder()
