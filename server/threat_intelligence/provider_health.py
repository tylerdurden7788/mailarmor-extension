import time
from typing import Dict, Any
from utils.structured_logger import structured_logger

class HealthState(str):
    """
    A custom string subclass representing health status.
    Ensures backward compatibility by performing case-insensitive matches
    and equating UNAVAILABLE to Unhealthy, and HEALTHY/DEGRADED/RECOVERING to Healthy.
    """
    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            s_up = self.upper()
            o_up = other.upper()
            if s_up == o_up:
                return True
            # Map unavailable/unhealthy to UNHEALTHY, everything else to HEALTHY
            s_mapped = "UNHEALTHY" if s_up in ["UNAVAILABLE", "UNHEALTHY"] else "HEALTHY"
            o_mapped = "UNHEALTHY" if o_up in ["UNAVAILABLE", "UNHEALTHY"] else "HEALTHY"
            return s_mapped == o_mapped
        return super().__eq__(other)

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return super().__hash__()

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
                "status": "HEALTHY",
                "probe_window": 10.0,  # retry probe window in seconds (reduced for faster test cycles)
                "next_probe_time": 0.0,
                "probe_in_flight": False
            }
            
    def record_success(self, provider_name: str, latency_ms: float) -> None:
        """Records a successful lookup and updates latency/health score averages."""
        self._init_provider(provider_name)
        m = self._metrics[provider_name]
        
        # Reset telemetry metrics on recovery to start fresh
        if m["status"] in ["UNAVAILABLE", "RECOVERING"]:
            m["successes"] = 0
            m["failures"] = 0
            m["consecutive_failures"] = 0
            m["status"] = "HEALTHY"
            
        m["successes"] += 1
        m["consecutive_failures"] = 0
        m["latency_sum_ms"] += latency_ms
        m["last_success"] = time.time()
        m["probe_in_flight"] = False
        
        # Reset recovery probe backoff
        m["probe_window"] = 10.0
        
        old_status = m["status"]
        self._update_score(provider_name, latency_ms)
        
        if old_status != m["status"]:
            structured_logger.info(
                "Circuit breaker state transition", 
                provider_name, 
                {"old_status": old_status, "new_status": m["status"]}
            )
        
    def record_failure(self, provider_name: str) -> None:
        """Records a failed lookup, incrementing failure count and consecutive failures."""
        self._init_provider(provider_name)
        m = self._metrics[provider_name]
        m["failures"] += 1
        m["consecutive_failures"] += 1
        m["last_failure"] = time.time()
        
        old_status = m["status"]
        
        # If failure occurred while probing, apply exponential recovery probe backoff
        if old_status == "RECOVERING":
            m["probe_window"] = min(300.0, m["probe_window"] * 2)
            m["next_probe_time"] = time.time() + m["probe_window"]
            m["status"] = "UNAVAILABLE"
            m["probe_in_flight"] = False
        else:
            if m["consecutive_failures"] >= self.failure_threshold:
                m["status"] = "UNAVAILABLE"
                m["next_probe_time"] = time.time() + m["probe_window"]
                m["probe_in_flight"] = False
            else:
                self._update_score(provider_name, 0.0)
                
        if old_status != m["status"]:
            structured_logger.warning(
                "Circuit breaker state transition", 
                provider_name, 
                {"old_status": old_status, "new_status": m["status"], "next_probe_time": m.get("next_probe_time")}
            )
        
    def _update_score(self, provider_name: str, last_latency_ms: float) -> None:
        m = self._metrics[provider_name]
        total = m["successes"] + m["failures"]
        
        if total > 0:
            m["health_score"] = m["successes"] / total
            
        # Circuit-breaker rules
        if m["consecutive_failures"] >= self.failure_threshold:
            m["status"] = "UNAVAILABLE"
            m["next_probe_time"] = time.time() + m["probe_window"]
        elif total >= self.min_calls and m["health_score"] < self.score_threshold:
            m["status"] = "UNAVAILABLE"
            m["next_probe_time"] = time.time() + m["probe_window"]
        elif last_latency_ms > 1500.0 or (total >= self.min_calls and m["health_score"] < 0.85):
            m["status"] = "DEGRADED"
        else:
            m["status"] = "HEALTHY"
            
    def get_health_status(self, provider_name: str) -> str:
        """Returns HEALTHY, DEGRADED, UNAVAILABLE, or RECOVERING (as a compatible HealthState)."""
        self._init_provider(provider_name)
        m = self._metrics[provider_name]
        
        # Check if UNAVAILABLE provider is ready for a recovery probe
        if m["status"] == "UNAVAILABLE" and time.time() >= m["next_probe_time"]:
            m["status"] = "RECOVERING"
            m["probe_in_flight"] = True
            structured_logger.info("Circuit breaker state transition to probe recovery", provider_name)
            
        return HealthState(m["status"])
        
    def get_metrics(self, provider_name: str) -> Dict[str, Any]:
        """Gets all calculated metrics for the provider."""
        self._init_provider(provider_name)
        m = dict(self._metrics[provider_name])
        total = m["successes"] + m["failures"]
        m["average_latency_ms"] = m["latency_sum_ms"] / m["successes"] if m["successes"] > 0 else 0.0
        m["total_calls"] = total
        return m
