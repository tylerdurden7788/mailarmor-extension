import time
from typing import Dict, Any

class ProviderHealthMonitor:
    def __init__(self, failure_threshold: int = 3, min_calls: int = 3, score_threshold: float = 0.50):
        self._metrics: Dict[str, Dict[str, Any]] = {}
        self.failure_threshold = failure_threshold
        self.min_calls = min_calls
        self.score_threshold = score_threshold
        
    def _init_provider(self, provider_name: str) -> None:
        if provider_name not in self._metrics:
            self._metrics[provider_name] = {
                "successes": 0,
                "failures": 0,
                "consecutive_failures": 0,
                "latency_sum_ms": 0.0,
                "last_success": 0.0,
                "last_failure": 0.0,
                "health_score": 1.0,
                "status": "Healthy"
            }
            
    def record_success(self, provider_name: str, latency_ms: float) -> None:
        """Records a successful lookup and updates latency/health score averages."""
        self._init_provider(provider_name)
        m = self._metrics[provider_name]
        m["successes"] += 1
        m["consecutive_failures"] = 0
        m["latency_sum_ms"] += latency_ms
        m["last_success"] = time.time()
        
        self._update_score(provider_name)
        
    def record_failure(self, provider_name: str) -> None:
        """Records a failed lookup, incrementing failure count and consecutive failures."""
        self._init_provider(provider_name)
        m = self._metrics[provider_name]
        m["failures"] += 1
        m["consecutive_failures"] += 1
        m["last_failure"] = time.time()
        
        self._update_score(provider_name)
        
    def _update_score(self, provider_name: str) -> None:
        m = self._metrics[provider_name]
        total = m["successes"] + m["failures"]
        
        if total > 0:
            m["health_score"] = m["successes"] / total
            
        # Circuit-breaker rules
        if m["consecutive_failures"] >= self.failure_threshold:
            m["status"] = "Unhealthy"
        elif total >= self.min_calls and m["health_score"] < self.score_threshold:
            m["status"] = "Unhealthy"
        else:
            m["status"] = "Healthy"
            
    def get_health_status(self, provider_name: str) -> str:
        """Returns Healthy or Unhealthy."""
        self._init_provider(provider_name)
        return self._metrics[provider_name]["status"]
        
    def get_metrics(self, provider_name: str) -> Dict[str, Any]:
        """Gets all calculated metrics for the provider."""
        self._init_provider(provider_name)
        m = dict(self._metrics[provider_name])
        total = m["successes"] + m["failures"]
        m["average_latency_ms"] = m["latency_sum_ms"] / m["successes"] if m["successes"] > 0 else 0.0
        m["total_calls"] = total
        return m
