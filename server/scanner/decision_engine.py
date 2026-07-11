from models.evidence_model import EvidenceReport
from decision.decision_engine import DecisionEngine as NewDecisionEngine
import asyncio

class DecisionEngine:
    @staticmethod
    def reconcile(report: EvidenceReport, claude_verdict: str = None) -> str:
        """
        Reconciles evidence report using the new DecisionEngine.
        """
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
        if loop.is_running():
            # If loop is running, execute process_report via run_coroutine_threadsafe
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor() as executor:
                future = executor.submit(lambda: asyncio.run(NewDecisionEngine.process_report(report)))
                model = future.result()
        else:
            model = loop.run_until_complete(NewDecisionEngine.process_report(report))
            
        return model.verdict
