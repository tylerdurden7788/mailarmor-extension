import os
import time
from pathlib import Path
from typing import Dict, Any
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

# Import refactored modules
from models.response_model import EmailAnalysisResponse
from scanner.email_parser import EmailParser
from scanner.rule_engine import RuleEngine
from scanner.decision_engine import DecisionEngine
from threat_intelligence.http_client import http_client
from utils.metrics import metrics_collector

# Load environment variables
env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path)

@asynccontextmanager
async def lifespan(app: FastAPI):
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

@app.post("/analyze", response_model=EmailAnalysisResponse)
async def analyze_email(payload: EmailAnalysisRequest):
    """
    Executes the modular email security pipeline:
    1. Parse & Normalize incoming payload into structured Email object.
    2. Rule Engine executes all registered plugins concurrently.
    3. Decision Engine determines the verdict using precedence hierarchies.
    """
    try:
        # 1. Parse payload to normalized Email object
        email_obj = EmailParser.parse_api_payload({
            "subject": payload.subject,
            "sender": payload.sender,
            "body": payload.body
        })
        
        # 2. Rule Engine run (asynchronous parallel checks)
        report = await RuleEngine.run_analysis(email_obj)
        
        # 3. Decision Engine run
        dec_start = time.perf_counter()
        from decision.decision_engine import DecisionEngine as NewDecisionEngine
        decision_model = await NewDecisionEngine.process_report(report, anthropic_client=anthropic_client)
        dec_latency = (time.perf_counter() - dec_start) * 1000.0
        
        verdict = decision_model.verdict
        
        # Generate compatible legacy values for extension backward-compatibility
        score = int(decision_model.confidence * 100)
        reason = decision_model.user_explanation
        
        # Record metrics
        consensus_count = len(decision_model.ioc_consensus)
        avg_agreement = (
            sum(c.get("agreement_score", 0.0) for c in decision_model.ioc_consensus.values()) / consensus_count 
            if consensus_count > 0 else 0.0
        )
        metrics_collector.record_decision(dec_latency, consensus_count, avg_agreement, decision_model.attack_types)
        
        return EmailAnalysisResponse(
            report=report,
            verdict=verdict,
            reason=reason,
            score=score
        )
    except Exception as e:
        print(f"[API Error] Analysis pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health_check():
    """Simple health check endpoint."""
    return {"status": "ok", "api_key_configured": bool(ANTHROPIC_API_KEY)}
