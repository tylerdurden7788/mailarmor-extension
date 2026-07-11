from typing import List
from models.decision_model import DecisionModel
from models.evidence_model import Evidence
from config.decision_rules import RULE_PRIORITY_MAP, ANALYZER_RELIABILITY

class EvidenceClassifier:
    @staticmethod
    def classify(model: DecisionModel) -> DecisionModel:
        """
        Assigns priority, reliability, and quality categories to every evidence object.
        """
        classified = []
        
        for ev in model.evidence_report.evidence_list:
            rule_id = ev.triggered_rule
            analyzer = ev.analyzer_name
            
            # Settle priority from config
            priority = RULE_PRIORITY_MAP.get(rule_id, "Informational")
            reliability = ANALYZER_RELIABILITY.get(analyzer, 0.70)
            
            # Calculate quality
            quality = "Unknown"
            if priority == "Critical" and reliability >= 0.90:
                quality = "Verified"
            elif priority in ["Critical", "High"] and reliability >= 0.80:
                quality = "Strong"
            elif priority == "Medium" and reliability >= 0.70:
                quality = "Moderate"
            elif priority == "Low":
                quality = "Weak"
            elif priority == "Informational":
                quality = "Informational"
            else:
                quality = "Weak"
                
            # Create a clone of technical_details and insert tags to avoid mutation
            new_details = dict(ev.technical_details) if ev.technical_details else {}
            new_details["priority"] = priority
            new_details["reliability"] = reliability
            new_details["quality"] = quality
            
            # Create classified copy of Evidence object
            ev_copy = Evidence(
                evidence_id=ev.evidence_id,
                analyzer_name=ev.analyzer_name,
                category=ev.category,
                severity=ev.severity,
                triggered_rule=ev.triggered_rule,
                technical_details=new_details,
                confidence=ev.confidence,
                risk_contribution=ev.risk_contribution,
                explanation=ev.explanation,
                recommendation=ev.recommendation,
                timestamp=ev.timestamp
            )
            classified.append(ev_copy)
            
        trace = list(model.decision_trace)
        trace.append("CLASSIFIED: Priority and quality mapped for all evidence.")
        
        # Increment execution counts
        meta = dict(model.metadata)
        meta["classified_count"] = len(classified)
        
        return DecisionModel(
            evidence_report=model.evidence_report,
            classified_evidence=classified,
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
            metadata=meta
        )
