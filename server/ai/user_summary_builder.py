from models.decision_model import DecisionModel

class UserSummaryBuilder:
    def build_user_summary(self, model: DecisionModel) -> str:
        """
        Generates simplified end-user safety advice citing rule rules.
        """
        evidence_list = model.correlated_evidence or []
        if not evidence_list:
            return "This email appears safe to read. No security flags were triggered."

        # Map rules to basic user summaries
        reasons = []
        rule_citations = []
        
        for ev in evidence_list:
            rule_citations.append(f"[{ev.triggered_rule}]")
            desc = ev.explanation.lower()
            if "spoof" in desc or "brand" in desc or "domain" in desc:
                reasons.append("tries to pretend to be a brand you trust")
            elif "harvest" in desc or "form" in desc or "login" in desc:
                reasons.append("attempts to trick you into entering credentials on a fake website")
            elif "urgent" in desc or "action" in desc:
                reasons.append("uses urgent language to force quick action")
            elif "attachment" in desc or "payload" in desc:
                reasons.append("contains a suspicious file attachment")

        citations_str = " ".join(rule_citations)

        if reasons:
            reasons_str = " and ".join(list(set(reasons)))
            return f"Caution: This email {reasons_str}. Safety flags triggered: {citations_str}."
        else:
            return f"Caution: This email contains suspicious indicators. Safety flags triggered: {citations_str}."

# Global user summary builder instance
user_summary_builder = UserSummaryBuilder()
