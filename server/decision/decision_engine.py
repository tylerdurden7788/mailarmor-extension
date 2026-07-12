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
        
        # 9. EXPLANATION_GENERATED state transition
        model = ExplainabilityEngine.generate(model)
        
        # 10. RECOMMENDATIONS_GENERATED state transition
        model = RecommendationEngine.generate(model)
        
        # 11. TRACE_GENERATED state transition
        model = DecisionTrace.generate(model)
        
        # Appends processing telemetry
        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000.0
        
        meta = dict(model.metadata)
        meta["processing_time_ms"] = duration_ms
        meta["rules_version"] = "2.0.0"
        meta["classifier_version"] = "2.0.0"
        
        return model.model_copy(update={"metadata": meta})
