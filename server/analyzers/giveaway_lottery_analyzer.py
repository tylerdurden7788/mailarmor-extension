from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.semantic_model import SemanticContext
from scanner.evidence import create_evidence

class GiveawayLotteryAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, SemanticContext):
            return evidence_list
            
        has_reward = any(f.value == "reward_incentive" for f in context.features if f.category == "scam_rewards")
        has_greed = "Greed" in context.soc_eng_techniques
        
        if has_reward and has_greed:
            evidence_list.append(create_evidence(
                analyzer_name="GiveawayLotteryAnalyzer",
                rule_id="SEM_024",
                technical_details={
                    "technique_detected": "Winnings / Lottery / Giveaway Scam",
                    "objective_inferred": "Lottery Collection / Info Harvesting",
                    "victim_action_identified": "Claim prize or submit details",
                    "explainability_summary": "Detected unsolicited notice claiming user won lottery or gift prize."
                },
                confidence=0.85
            ))
        return evidence_list
