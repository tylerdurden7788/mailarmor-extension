import math
from typing import Dict, Any, List

class AIMetrics:
    def __init__(self):
        self.request_count = 0
        self.success_count = 0
        self.validation_failures = 0
        self.retry_count = 0
        self.timeout_count = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_estimated_cost = 0.0
        self.latencies: List[float] = []

    def record_request(self, request_id: str) -> None:
        self.request_count += 1

    def record_success(self, request_id: str, latency: float, input_tok: int, output_tok: int, cost: float) -> None:
        self.success_count += 1
        self.latencies.append(latency)
        self.total_input_tokens += input_tok
        self.total_output_tokens += output_tok
        self.total_estimated_cost += cost

    def record_validation_failure(self, request_id: str) -> None:
        self.validation_failures += 1

    def record_retry(self, request_id: str) -> None:
        self.retry_count += 1

    def record_timeout(self, request_id: str) -> None:
        self.timeout_count += 1

    def _calculate_p95(self) -> float:
        if not self.latencies:
            return 0.0
        sorted_lats = sorted(self.latencies)
        idx = math.ceil(len(sorted_lats) * 0.95) - 1
        return sorted_lats[max(0, min(idx, len(sorted_lats) - 1))]

    def get_statistics(self) -> Dict[str, Any]:
        avg_lat = sum(self.latencies) / len(self.latencies) if self.latencies else 0.0
        p95_lat = self._calculate_p95()
        
        return {
            "request_count": self.request_count,
            "success_count": self.success_count,
            "validation_failures": self.validation_failures,
            "retry_count": self.retry_count,
            "timeout_count": self.timeout_count,
            "average_latency_sec": avg_lat,
            "p95_latency_sec": p95_lat,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_tokens": self.total_input_tokens + self.total_output_tokens,
            "total_estimated_cost_usd": self.total_estimated_cost
        }

# Global AI metrics instance
ai_metrics = AIMetrics()
