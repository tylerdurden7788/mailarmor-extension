import time
import logging
import threading
import config.ai_operations_config as config

logger = logging.getLogger("AICircuitBreaker")

class AICircuitBreaker:
    def __init__(self):
        self.state = "HEALTHY"  # HEALTHY, DEGRADED, OPEN, HALF_OPEN
        self.failure_count = 0
        self.last_failure_time = 0.0
        self._lock = threading.Lock()

    def allow_request(self) -> bool:
        """
        Determines if the circuit allows outgoing queries.
        Handles recovery timeout check for OPEN state.
        """
        with self._lock:
            now = time.time()
            if self.state == "OPEN":
                # Check if recovery timeout has elapsed
                if now - self.last_failure_time > config.CB_RECOVERY_TIMEOUT_SEC:
                    self.state = "HALF_OPEN"
                    logger.info("AICircuitBreaker state transitioned: OPEN -> HALF_OPEN (entering probe phase)")
                    return True
                return False
            return True

    def record_success(self) -> None:
        """
        Resets circuit failures on successful execution.
        """
        with self._lock:
            if self.state in ["DEGRADED", "HALF_OPEN"]:
                logger.info(f"AICircuitBreaker state recovery: {self.state} -> HEALTHY")
            self.state = "HEALTHY"
            self.failure_count = 0

    def record_failure(self) -> None:
        """
        Increments failure count and transitions states.
        """
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.state == "HEALTHY" and self.failure_count >= 3:
                self.state = "DEGRADED"
                logger.warning("AICircuitBreaker state degraded: HEALTHY -> DEGRADED (increased failure count)")
            elif self.failure_count >= config.CB_FAILURE_THRESHOLD:
                self.state = "OPEN"
                logger.error(f"AICircuitBreaker tripped to OPEN! consecutive failures count={self.failure_count}")

# Global circuit breaker instance
ai_circuit_breaker = AICircuitBreaker()
