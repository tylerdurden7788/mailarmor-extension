import time
import logging
from typing import Dict, Any, Optional
from models.evidence_model import EvidenceReport
from models.decision_model import DecisionModel
from decision.evidence_classifier import EvidenceClassifier
from decision.correlation_engine import CorrelationEngine
from decision.conflict_resolver import ConflictResolver
from decision.confidence_engine import ConfidenceEngine
from decision.risk_engine import RiskEngine
from decision.claude_context_builder import ClaudeContextBuilder
from decision.claude_prompt_builder import ClaudePromptBuilder
from decision.verdict_fusion import VerdictFusion
from decision.explainability_engine import ExplainabilityEngine
from decision.recommendation_engine import RecommendationEngine
from decision.decision_trace import DecisionTrace

logger = logging.getLogger("DecisionEngine")

class DecisionEngine:
    @staticmethod
    async def process_report(report: EvidenceReport, anthropic_client: Optional[Any] = None) -> DecisionModel:
        """
        Executes the full Decision state machine transitions over the evidence report.
        """
        start_time = time.perf_counter()
        
        # 1. INITIAL state Ingestion
        model = DecisionModel(
            evidence_report=report,
            decision_trace=["INITIAL: Ingested raw EvidenceReport."],
            metadata={"start_time_perf": start_time}
        )
        
        # 2. CLASSIFIED state transition
        model = EvidenceClassifier.classify(model)
        
        # 3. CORRELATED state transition
        model = CorrelationEngine.correlate(model)
        
        # 4. CONFLICT_RESOLVED state transition
        model = ConflictResolver.resolve(model)
        
        # 5. CONFIDENCE_CALCULATED state transition
        model = ConfidenceEngine.calculate(model)
        
        # 6. RISK_ASSESSED state transition
        model = RiskEngine.assess(model)
        
        # 7. CLAUDE_ANALYZED (Context build & invoke via central orchestrator)
        from ai.orchestrator import AIOrchestrator
        orchestrator = AIOrchestrator(anthropic_client)
        ai_response, ai_traces = await orchestrator.analyze_decision_model(model)
        
        model = model.model_copy(update={
            "decision_trace": model.decision_trace + ai_traces
        })
        claude_response = ai_response.parsed_json
            
        # 8. VERDICT_FUSED state transition
        model = VerdictFusion.fuse(model, claude_response)
        
        # 9. EXPLANATION_GENERATED & RECOMMENDATIONS_GENERATED state transitions (via ExplainabilityOrchestrator)
        from ai.explainability_orchestrator import ExplainabilityOrchestrator
        explainability_orchestrator = ExplainabilityOrchestrator(anthropic_client)
        exp_response, exp_traces = await explainability_orchestrator.generate_explanations(model)
        
        meta = dict(model.metadata)
        meta["attack_chain"] = exp_response.attack_chain
        meta["confidence_reasoning"] = exp_response.confidence_reasoning
        meta["executive_summary"] = exp_response.executive_summary
        
        model = model.model_copy(update={
            "user_explanation": exp_response.user_summary,
            "technical_explanation": exp_response.technical_summary,
            "recommendations": exp_response.recommendations,
            "decision_trace": model.decision_trace + exp_traces,
            "metadata": meta
        })
        
        # 11. TRACE_GENERATED state transition
        model = DecisionTrace.generate(model)
        
        # Appends processing telemetry
        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000.0
        
        meta = dict(model.metadata)
        meta["processing_time_ms"] = duration_ms
        meta["rules_version"] = "2.0.0"
        meta["classifier_version"] = "2.0.0"
        
        # Construct structured decision trace metadata for Phase 1 Explainability
        executed_analyzers = []
        for name, stats in report.analyzer_statistics.items():
            executed_analyzers.append({
                "analyzer_name": name,
                "status": stats.get("status", "UNKNOWN"),
                "execution_time_ms": stats.get("execution_time_ms", 0.0),
                "evidence_count": stats.get("evidence_count", 0),
                "error": stats.get("error", "")
            })
            
        triggered_rules_details = []
        for ev in model.correlated_evidence:
            details = ev.technical_details or {}
            triggered_rules_details.append({
                "rule_id": ev.triggered_rule,
                "analyzer_name": ev.analyzer_name,
                "category": ev.category,
                "severity": ev.severity,
                "priority": details.get("priority", "Informational"),
                "confidence_contribution": ev.confidence,
                "risk_contribution": ev.risk_contribution,
                "explanation": ev.explanation
            })
            
        decision_traces_structured = {
            "executed_analyzers": executed_analyzers,
            "triggered_rules": triggered_rules_details,
            "final_normalized_score": int(model.confidence * 100),
            "final_verdict": model.verdict,
            "final_risk_level": model.risk_level,
            "claude_reasoning_summary": meta.get("confidence_reasoning", "") or model.technical_explanation
        }
        meta["decision_traces_structured"] = decision_traces_structured
        
        return model.model_copy(update={"metadata": meta})
