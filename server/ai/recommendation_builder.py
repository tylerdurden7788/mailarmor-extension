from typing import List
from models.decision_model import DecisionModel

class RecommendationBuilder:
    def build_recommendations(self, model: DecisionModel) -> List[str]:
        """
        Generates actionable security recommendations mapped directly to the verdict and severity.
        """
        recs = []
        verdict = model.verdict
        evidence_list = model.correlated_evidence or []

        if verdict in ["DANGEROUS", "SUSPICIOUS"]:
            recs.append("Do not click links or enter credentials on linked sites.")
            recs.append("Verify the sender's identity through a secondary, out-of-band channel.")
            recs.append("Report this message immediately using your mail application's report tool.")
            
            # Map categories to recommendations
            for ev in evidence_list:
                cat = ev.category.upper()
                if cat in ["ATTACHMENT", "MALWARE"]:
                    recs.append("Do not open, download, or execute the file attachment.")
                if cat in ["AUTHENTICATION", "SENDER"]:
                    recs.append("Sender authorization (SPF/DKIM/DMARC) failed. Treat sender field as spoofed.")
        else:
            recs.append("Review sender and content before interacting.")

        # Ensure recommendation limit is respected
        from config.explanation_config import RECOMMENDATION_LIMIT
        # De-duplicate while maintaining order
        seen = set()
        unique_recs = [r for r in recs if not (r in seen or seen.add(r))]
        return unique_recs[:RECOMMENDATION_LIMIT]

# Global recommendation builder instance
recommendation_builder = RecommendationBuilder()
