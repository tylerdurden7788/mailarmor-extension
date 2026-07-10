import os
from pathlib import Path
from typing import Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

# Import refactored modules
from models.response_model import EmailAnalysisResponse
from scanner.email_parser import EmailParser
from scanner.rule_engine import RuleEngine
from scanner.decision_engine import DecisionEngine

# Load environment variables
env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path)

# Initialize FastAPI application
app = FastAPI(
    title="MailArmour Hybrid Security Engine",
    description="Refactored modular pipeline for deterministic and AI-based email security",
    version="2.0.0"
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
        
        # 3. Precedence-based decision verification
        verdict = DecisionEngine.reconcile(report)
        
        # Generate compatible legacy values for extension backward-compatibility
        score = 8 if verdict == "SAFE" else (55 if verdict == "SUSPICIOUS" else 92)
        
        reason = (
            "Phishing threat detected by rule engine." if verdict == "DANGEROUS" 
            else ("Anomalous items found." if verdict == "SUSPICIOUS" 
            else "No security threats identified.")
        )
        
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
