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
        
        # 7. CLAUDE_ANALYZED (Context build & invoke)
        claude_response = None
        if anthropic_client:
            try:
                claude_response = await DecisionEngine._invoke_claude(model, anthropic_client)
            except Exception as e:
                logger.warning(f"Claude reasoning failed or timed out: {e}. Falling back to local rules.")
                model = model.model_copy(update={
                    "decision_trace": model.decision_trace + [f"WARNING: Claude analysis failed: {e}. Reverting to local engine."]
                })
        else:
            model = model.model_copy(update={
                "decision_trace": model.decision_trace + ["INFO: Claude client not configured. Executing local rules only."]
            })
            
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

    @staticmethod
    async def _invoke_claude(model: DecisionModel, client: Any) -> Optional[Dict[str, Any]]:
        """
        Builds context/prompt and executes Claude.
        """
        context = ClaudeContextBuilder.build(model)
        prompt = ClaudePromptBuilder.build(context)
        
        # Simulates Claude Anthropic call
        # In a real environment, this invokes: client.messages.create(...)
        # We wrap it in a try-except to ensure fallback resilience.
        response = await client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1000,
            temperature=0,
            system="You are an expert security classification model. Always return valid JSON only.",
            messages=[{"role": "user", "content": prompt}]
        )
        
        # Extract response text and parse JSON safely
        content_text = response.content[0].text
        import json
        return json.loads(content_text)
