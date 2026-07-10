from models.evidence_model import EvidenceReport

class DecisionEngine:
    @staticmethod
    def reconcile(report: EvidenceReport, claude_verdict: str = None) -> str:
        """
        Reconciles rule-based evidence and Claude's reasoning using precedence hierarchies.
        Precedence Hierarchy:
        1. Hard deterministic evidence (CRITICAL / HIGH severity rules) takes precedence.
        2. If CRITICAL / HIGH evidence is found, return DANGEROUS.
        3. If MEDIUM severity rules are triggered, return SUSPICIOUS.
        4. Reconcile with Claude's contextual verdict.
        """
        # Collect categories of severity
        severities = [ev.severity for ev in report.evidence_list]
        
        if "CRITICAL" in severities:
            return "DANGEROUS"
            
        if "HIGH" in severities:
            return "DANGEROUS"
            
        # Reconcile with Claude's response if available
        if claude_verdict:
            verdict_upper = claude_verdict.upper().strip()
            if verdict_upper in ["DANGEROUS", "SUSPICIOUS", "SAFE"]:
                return verdict_upper
                
        if "MEDIUM" in severities:
            return "SUSPICIOUS"
            
        return "SAFE"
