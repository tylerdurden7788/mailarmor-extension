import uuid
import logging
from typing import Dict, Any, List, Tuple, Optional
from models.decision_model import DecisionModel
from models.explanation_model import ExplanationResponse
from ai.orchestrator import AIOrchestrator
from ai.explanation_builder import explanation_builder
from ai.attack_chain_builder import attack_chain_builder
from ai.analyst_report_builder import analyst_report_builder
from ai.executive_summary_builder import executive_summary_builder
from ai.user_summary_builder import user_summary_builder
from ai.confidence_explainer import confidence_explainer
from ai.recommendation_builder import recommendation_builder
from ai.report_formatter import report_formatter
from utils.structured_logger import structured_logger
import config.explanation_config as config

logger = logging.getLogger("ExplainabilityOrchestrator")

class ExplainabilityOrchestrator:
    def __init__(self, anthropic_client: Optional[Any] = None):
        self.ai_orchestrator = AIOrchestrator(anthropic_client)

    async def generate_explanations(self, model: DecisionModel) -> Tuple[ExplanationResponse, List[str]]:
        """
        Coordinates the complete AI Explainability pipeline flow:
        INITIAL -> AI_ANALYSIS -> VALIDATED -> COMPLETE
        If any step fails, fails over to: FALLBACK -> COMPLETE
        """
        traces = []
        
        # 1. State: INITIAL
        state = "INITIAL"
        request_id = model.metadata.get("request_id")
        if not request_id:
            request_id = model.evidence_report.processing_metadata.get("request_id")
        if not request_id:
            request_id = str(uuid.uuid4())
            
        traces.append(f"AI_EXPLAINABILITY_STATE: {state} | request_id={request_id}")
        structured_logger.info("AI explainability analysis started", None, {"request_id": request_id, "state": state})

        # 2. State: AI_ANALYSIS (Attempt AI-based explainability generation)
        try:
            state = "AI_ANALYSIS"
            traces.append(f"AI_EXPLAINABILITY_STATE: {state}")
            
            response, parsed_json = await explanation_builder.build_explanation_response(
                orchestrator=self.ai_orchestrator,
                model=model,
                request_id=request_id
            )
            
            state = "VALIDATED"
            traces.append(f"AI_EXPLAINABILITY_STATE: {state}")
            
            exp_response = ExplanationResponse(
                technical_summary=parsed_json.get("technical_summary", ""),
                user_summary=parsed_json.get("user_summary", ""),
                executive_summary=parsed_json.get("executive_summary", ""),
                attack_chain=parsed_json.get("attack_chain", []),
                recommendations=parsed_json.get("recommendations", []),
                confidence_reasoning=parsed_json.get("confidence_reasoning", ""),
                generated_sections=list(parsed_json.keys()),
                schema_version=config.SCHEMA_VERSION
            )
            
            traces.append("AI_EXPLAINABILITY_STATE: COMPLETE")
            structured_logger.info("AI explainability analysis completed successfully", None, {"request_id": request_id, "state": "COMPLETE"})
            return exp_response, traces

        except Exception as e:
            # 3. State: FALLBACK (Fallback to local builders)
            state = "FALLBACK"
            error_msg = str(e)
            traces.append(f"AI_EXPLAINABILITY_STATE: {state} | error={error_msg}")
            traces.append(f"WARNING: AI explainability generation failed: {error_msg}. Falling back to local builders.")
            structured_logger.warning("AI explainability analysis failing over to local fallback", None, {"request_id": request_id, "error": error_msg, "state": state})
            
            # Generate deterministic fallback outputs from local builders
            loc_attack_chain = attack_chain_builder.build_attack_chain(model)
            loc_analyst_report = analyst_report_builder.build_analyst_report(model)
            loc_exec_summary = executive_summary_builder.build_executive_summary(model)
            loc_user_summary = user_summary_builder.build_user_summary(model)
            loc_conf_explanation = confidence_explainer.explain_confidence(model)
            loc_recs = recommendation_builder.build_recommendations(model)
            
            fallback_response = ExplanationResponse(
                technical_summary=loc_analyst_report,
                user_summary=loc_user_summary,
                executive_summary=loc_exec_summary,
                attack_chain=loc_attack_chain,
                recommendations=loc_recs,
                confidence_reasoning=loc_conf_explanation,
                generated_sections=["technical_summary", "user_summary", "executive_summary", "attack_chain", "recommendations", "confidence_reasoning"],
                schema_version=config.SCHEMA_VERSION
            )
            
            traces.append("AI_EXPLAINABILITY_STATE: COMPLETE")
            return fallback_response, traces
