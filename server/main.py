import os
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Import refactored modules
from models.response_model import EmailAnalysisResponse, CheckResult
from models.evidence_model import Evidence
from scanner.email_parser import EmailParser
from scanner.rule_engine import RuleEngine
from decision.decision_engine import DecisionEngine as NewDecisionEngine
from threat_intelligence.http_client import http_client
from utils.metrics import metrics_collector

# Load environment variables
env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path)

def validate_startup():
    """
    Validates configurations, registries, environment variables, directories,
    and optimization components on application startup.
    Critical failures stop the startup, optional component failures raise warnings.
    """
    print("=== MailArmour Startup Validation ===")
    
    # 1. Environment variables check
    # ANTHROPIC_API_KEY is optional because the engine gracefully falls back to local rules if missing
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    if not anthropic_key:
        print("[WARNING] ANTHROPIC_API_KEY environment variable is not set. Central AI Orchestration will fall back to local rules.")
    else:
        print("[SUCCESS] ANTHROPIC_API_KEY is configured.")
        
    # 2. Required directories existence
    logs_dir = Path(__file__).parent / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    print(f"[SUCCESS] Logs directory verified at {logs_dir}")

    # 3. Prompt Registry schemas validation
    try:
        from ai.prompt_registry import prompt_registry
        # Check that the prompt registry has loaded schemas
        if not prompt_registry._prompts:
            raise RuntimeError("Prompt registry prompts dictionary is empty")
        # Check that email_threat_analysis version 1.0.0 is present
        meta = prompt_registry.get_prompt("email_threat_analysis", "1.0.0")
        if not meta:
            raise RuntimeError("Required prompt 'email_threat_analysis' version '1.0.0' not found in prompt registry")
        print("[SUCCESS] AI prompt registry validated successfully.")
    except Exception as e:
        raise RuntimeError(f"Startup validation failed on Prompt Registry: {e}")

    # 4. Threat Intelligence registry validation
    try:
        from scanner.rule_engine import global_threat_registry
        # Validate that the registry is clean and valid
        global_threat_registry.validate()
        registered_providers = global_threat_registry._providers
        print(f"[SUCCESS] Threat Intelligence provider registry validated. Registered providers: {list(registered_providers.keys())}")
    except Exception as e:
        raise RuntimeError(f"Startup validation failed on Threat Intelligence Registry: {e}")

    # 5. Security Policy and Optimizations
    try:
        from ai.ai_cache import ai_cache
        from ai.cost_manager import cost_manager
        from ai.ai_circuit_breaker import ai_circuit_breaker
        
        # Verify circuit breaker is healthy at startup
        if ai_circuit_breaker.state != "HEALTHY":
            print(f"[WARNING] AI Circuit Breaker is not in HEALTHY state: {ai_circuit_breaker.state}")
        else:
            print("[SUCCESS] AI Circuit Breaker is initialized and HEALTHY.")
            
        # Verify cost tracking is active
        from config import ai_operations_config
        daily_limit = ai_operations_config.DAILY_COST_LIMIT
        print(f"[SUCCESS] AI Cost limits initialized. Daily budget: ${daily_limit}, Monthly budget: ${ai_operations_config.MONTHLY_COST_LIMIT}")
    except Exception as e:
        raise RuntimeError(f"Startup validation failed on Optimization / Security: {e}")
        
    print("=== Startup Validation Passed Successfully ===")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Run validation checks
    validate_startup()
    # Startup: Initialize shared HTTP connection pools
    await http_client.start()
    yield
    # Shutdown: Clean up HTTP connection pools
    await http_client.close()

# Initialize FastAPI application
app = FastAPI(
    title="MailArmour Hybrid Security Engine",
    description="Refactored modular pipeline for deterministic and AI-based email security",
    version="2.0.0",
    lifespan=lifespan
)

# Configure CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration settings
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
LEMONSQUEEZY_API_KEY = os.getenv("LEMONSQUEEZY_API_KEY")

anthropic_client = None
if ANTHROPIC_API_KEY:
    try:
        import anthropic
        anthropic_client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
    except Exception as e:
        print(f"Failed to initialize Anthropic client: {e}")

class EmailAnalysisRequest(BaseModel):
    subject: str
    sender: str
    body: str
    attachments: Optional[List[Dict[str, Any]]] = Field(default=None, description="Optional attachment metadata list")

def map_evidence_to_checks(evidence_list: List[Evidence]) -> Dict[str, CheckResult]:
    # Set default passed values
    sender_passed = True
    sender_detail = "Sender authentication verified."
    
    domain_passed = True
    domain_detail = "Domain registration details verified."
    
    urgency_passed = True
    urgency_detail = "No malicious urgency indicators found."
    
    link_passed = True
    link_detail = "No malicious URLs detected."
    
    content_passed = True
    content_detail = "Email structure and content appear normal."
    
    attachment_passed = True
    attachment_detail = "No attachments or safe files verified."

    # Look for high/critical indicators
    for ev in evidence_list:
        if ev.severity in ["HIGH", "CRITICAL"]:
            # Sender
            if ev.analyzer_name in ["SenderAnalyzer", "AuthenticationAnalyzer"]:
                sender_passed = False
                sender_detail = ev.explanation
            # Domain
            elif ev.analyzer_name in ["DomainAnalyzer", "ASN", "WHOIS", "Certificate", "Spamhaus"]:
                domain_passed = False
                domain_detail = ev.explanation
            # Urgency
            elif ev.analyzer_name in ["IntentAnalyzer", "SocialEngineeringAnalyzer"]:
                urgency_passed = False
                urgency_detail = ev.explanation
            # Link
            elif ev.analyzer_name in ["UrlAnalyzer", "BrandAnalyzer", "ReputationAnalyzer", "GoogleSafeBrowsing", "PhishTank", "OpenPhish", "URLHaus", "VirusTotal", "AlienvaultOTX", "CiscoTalos"]:
                link_passed = False
                link_detail = ev.explanation
            # Content
            elif ev.analyzer_name in ["ContentAnalyzer", "HtmlAnalyzer", "UnicodeAnalyzer", "DOMAnalyzer", "FormAnalyzer", "CSSAnalyzer", "JavaScriptAnalyzer", "IframeAnalyzer", "MetaAnalyzer", "ResourceAnalyzer", "UIDeceptionAnalyzer"]:
                content_passed = False
                content_detail = ev.explanation
            # Attachment
            elif ev.analyzer_name in ["AttachmentAnalyzer", "MIMEAnalyzer", "FileSignatureAnalyzer", "ExtensionAnalyzer", "ArchiveAnalyzer", "OfficeDocumentAnalyzer", "PDFAnalyzer", "ExecutableAnalyzer", "ScriptAnalyzer", "EmbeddedContentAnalyzer", "ImageAnalyzer", "OCRAnalyzer", "MalwareProviderAnalyzer", "SandboxProviderAnalyzer"]:
                attachment_passed = False
                attachment_detail = ev.explanation

    return {
        "sender_check": CheckResult(passed=sender_passed, detail=sender_detail),
        "domain_check": CheckResult(passed=domain_passed, detail=domain_detail),
        "urgency_check": CheckResult(passed=urgency_passed, detail=urgency_detail),
        "link_check": CheckResult(passed=link_passed, detail=link_detail),
        "content_check": CheckResult(passed=content_passed, detail=content_detail),
        "attachment_check": CheckResult(passed=attachment_passed, detail=attachment_detail)
    }

@app.post("/analyze", response_model=EmailAnalysisResponse)
async def analyze_email(payload: EmailAnalysisRequest):
    """
    Executes the modular email security pipeline:
    1. Parse incoming payload into structured Email object.
    2. Rule Engine executes all registered plugins concurrently.
    3. Decision Engine determines verdict, score, confidence and invokes AI orchestrators.
    """
    start_time = time.perf_counter()
    try:
        # 1. Parse payload to normalized Email object
        raw_payload = {
            "subject": payload.subject,
            "sender": payload.sender,
            "body": payload.body,
            "attachments": payload.attachments or []
        }
        email_obj = EmailParser.parse_api_payload(raw_payload)
        
        # 2. Rule Engine run (asynchronous parallel checks + threat intelligence lookups)
        report = await RuleEngine.run_analysis(email_obj)
        
        # 3. Decision Engine run (classification, correlation, AI Orchestration, Verdict Fusion, explainability)
        dec_start = time.perf_counter()
        decision_model = await NewDecisionEngine.process_report(report, anthropic_client=anthropic_client)
        dec_latency = (time.perf_counter() - dec_start) * 1000.0
        
        # 4. Extract decision outputs
        verdict = decision_model.verdict
        confidence = decision_model.confidence
        risk_level = decision_model.risk_level
        user_explanation = decision_model.user_explanation
        technical_explanation = decision_model.technical_explanation
        recommendations = decision_model.recommendations
        
        # 5. Extract items stored in metadata
        attack_chain = decision_model.metadata.get("attack_chain", [])
        
        # Determine list of rules triggered
        triggered_rules = list(set(ev.triggered_rule for ev in decision_model.correlated_evidence))
        
        # Extract supporting Threat Intelligence providers
        supporting_providers = list(set(
            ev.analyzer_name for ev in decision_model.correlated_evidence 
            if ev.category == "THREAT_INT"
        ))
        
        # Format a Threat Intelligence summary from consensus details
        ti_summary_parts = []
        for target, stats in decision_model.ioc_consensus.items():
            providers_hit = stats.get("supporting_providers", [])
            if providers_hit:
                ti_summary_parts.append(f"{target} flagged by {', '.join(providers_hit)}")
        threat_intelligence_summary = "; ".join(ti_summary_parts) if ti_summary_parts else "No malicious indicators reported by threat intelligence feeds."

        # Map checks dictionary for Chrome Extension UI backward compatibility
        checks_dict = map_evidence_to_checks(decision_model.correlated_evidence)
        
        # Generate compatible legacy values for extension backward-compatibility
        score = int(confidence * 100)
        reason = user_explanation
        
        # Calculate phishing probability
        phishing_probability = 0.0
        if verdict == "DANGEROUS":
            phishing_probability = max(0.85, confidence)
        elif verdict == "SUSPICIOUS":
            phishing_probability = confidence * 0.7
        else:  # SAFE or LIKELY_SAFE
            phishing_probability = confidence * 0.1
        
        # Record metrics
        consensus_count = len(decision_model.ioc_consensus)
        avg_agreement = (
            sum(c.get("agreement_score", 0.0) for c in decision_model.ioc_consensus.values()) / consensus_count 
            if consensus_count > 0 else 0.0
        )
        metrics_collector.record_decision(dec_latency, consensus_count, avg_agreement, decision_model.attack_types)
        
        # Calculate overall latency
        scan_duration_ms = (time.perf_counter() - start_time) * 1000.0
        
        # Collect diagnostics (without logging email body, credentials or API keys)
        diagnostics = {
            "total_pipeline_latency_ms": scan_duration_ms,
            "decision_latency_ms": dec_latency,
            "consensus_count": consensus_count,
            "avg_agreement": avg_agreement,
            "decision_trace": decision_model.decision_trace
        }
        
        return EmailAnalysisResponse(
            report=report,
            verdict=verdict,
            risk_level=risk_level,
            confidence=confidence,
            phishing_probability=phishing_probability,
            triggered_rules=triggered_rules,
            threat_intelligence_summary=threat_intelligence_summary,
            supporting_providers=supporting_providers,
            attack_chain=attack_chain,
            reason=reason,
            user_explanation=user_explanation,
            technical_explanation=technical_explanation,
            recommendations=recommendations,
            score=score,
            scan_duration_ms=scan_duration_ms,
            diagnostics=diagnostics,
            checks=checks_dict
        )
    except Exception as e:
        print(f"[API Error] Unified production analysis pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health_check():
    """Simple health check endpoint."""
    return {"status": "ok", "api_key_configured": bool(ANTHROPIC_API_KEY)}
