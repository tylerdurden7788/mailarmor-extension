import threading
from typing import Dict, Any

class AIHealthMonitor:
    def __init__(self):
        self.total_requests = 0
        self.success_count = 0
        self.failure_count = 0
        self.timeout_count = 0
        self.validation_failures = 0
        self.fallback_triggers = 0
        self.cache_hits = 0
        self.total_latency = 0.0
        self._lock = threading.Lock()

    def record_execution(
        self,
        success: bool,
        latency: float,
        is_timeout: bool = False,
        validation_failed: bool = False,
        fallback_triggered: bool = False,
        cache_hit: bool = False
    ) -> None:
        with self._lock:
            self.total_requests += 1
            if success:
                self.success_count += 1
            else:
                self.failure_count += 1
                
            self.total_latency += latency
            
            if is_timeout:
                self.timeout_count += 1
            if validation_failed:
                self.validation_failures += 1
            if fallback_triggered:
                self.fallback_triggers += 1
            if cache_hit:
                self.cache_hits += 1

    def get_health_summary(self) -> Dict[str, Any]:
        with self._lock:
            total = max(self.total_requests, 1)
            success_rate = (self.success_count / total) * 100.0
            avg_latency = self.total_latency / total
            cache_ratio = (self.cache_hits / total) * 100.0
            
            return {
                "total_requests": self.total_requests,
                "success_rate_percentage": success_rate,
                "average_latency_sec": avg_latency,
                "cache_hit_ratio_percentage": cache_ratio,
                "timeout_count": self.timeout_count,
                "validation_failures_count": self.validation_failures,
                "fallback_frequency": self.fallback_triggers
            }

    def clear(self) -> None:
        with self._lock:
            self.total_requests = 0
            self.success_count = 0
            self.failure_count = 0
            self.timeout_count = 0
            self.validation_failures = 0
            self.fallback_triggers = 0
            self.cache_hits = 0
            self.total_latency = 0.0

# Global health monitor instance
ai_health_monitor = AIHealthMonitor()
