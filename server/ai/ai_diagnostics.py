from typing import Dict, Any, List

class AIDiagnostics:
    def compile_diagnostics(
        self,
        timeline: Dict[str, float],
        cache_hit: bool,
        compression_applied: bool,
        cost: float,
        tokens: int,
        retries: int = 0
    ) -> Dict[str, Any]:
        """
        Compiles structural performance diagnostics.
        """
        return {
            "timeline_latencies_sec": timeline,
            "cache_hit": cache_hit,
            "compression_applied": compression_applied,
            "estimated_cost_usd": cost,
            "total_tokens_consumed": tokens,
            "retries_count": retries
        }

# Global diagnostics collector instance
ai_diagnostics = AIDiagnostics()
