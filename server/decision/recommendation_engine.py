from typing import List
from models.decision_model import DecisionModel

class RecommendationEngine:
    @staticmethod
    def generate(model: DecisionModel) -> DecisionModel:
        """
        Determines contextual user recommendations based on attack classifications and threat intelligence.
        """
        recs = []
        attacks = model.attack_types
        verdict = model.verdict
        
        # Check consensus findings for specific threat scenarios
        has_malware_threat = False
        has_phishing_threat = False
        has_unknown_ioc = False
        
        for target, stats in model.ioc_consensus.items():
            sev = stats.get("severity", "INFO")
            if sev in ["HIGH", "CRITICAL"]:
                has_phishing_threat = True
            if "Malware Delivery" in stats.get("campaign_tags", []):
                has_malware_threat = True
            if stats.get("agreement_score", 0.0) == 0.0:
                has_unknown_ioc = True

        if verdict in ["DANGEROUS", "SUSPICIOUS"]:
            if "Credential Harvesting" in attacks or "Account Takeover" in attacks or "MFA Harvesting" in attacks or has_phishing_threat:
                recs.append("Do not enter your credentials or password on any linked form or login page.")
                recs.append("If you already entered your password, reset it immediately on the official provider website.")
            if "Invoice Fraud" in attacks or "Wire Transfer Fraud" in attacks or "CEO Fraud" in attacks or "Payroll Fraud" in attacks:
                recs.append("Verify this request directly with the sender or vendor using a verified, out-of-band channel.")
                recs.append("Do not use any contact details or payment info provided within this email.")
            if "Malware Delivery" in attacks or "Executable Delivery" in attacks or has_malware_threat:
                recs.append("Do not download, open, or extract any attachments from this message.")
                recs.append("Report this message to your security team immediately.")
            if "Romance Scam" in attacks or "Investment Scam" in attacks or "Lottery Scam" in attacks:
                recs.append("Do not transfer funds, purchase gift cards, or share sensitive personal details.")
            if has_unknown_ioc and not recs:
                recs.append("Verify unknown indicators independently before interacting with this message.")
            if not recs:
                recs.append("Exercise extreme caution before clicking links or replying to this sender.")
        else:
            recs.append("No action required. The message is categorized as safe.")
            
        trace = list(model.decision_trace)
        trace.append("RECOMMENDATIONS_GENERATED: Contextual user safety tips populated with threat warnings.")
        
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
            recommendations=recs,
            verdict=model.verdict,
            technical_explanation=model.technical_explanation,
            user_explanation=model.user_explanation,
            decision_trace=trace,
            metadata=model.metadata,
            
            threat_intelligence_summary=model.threat_intelligence_summary,
            ioc_consensus=model.ioc_consensus
        )
