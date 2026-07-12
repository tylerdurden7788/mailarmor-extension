import threading
import logging
import config.ai_operations_config as config

logger = logging.getLogger("CostManager")

class CostManager:
    def __init__(self):
        self.daily_spend = 0.0
        self.monthly_spend = 0.0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self._lock = threading.Lock()

    def calculate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """
        Calculates the cost based on Anthropic pricing:
        Input tokens: $3.00 / million tokens
        Output tokens: $15.00 / million tokens
        """
        cost = (input_tokens * 3.0 + output_tokens * 15.0) / 1_000_000.0
        return cost

    def record_tokens(self, input_tokens: int, output_tokens: int) -> float:
        """
        Increments spend counters and returns cost for this call.
        """
        cost = self.calculate_cost(input_tokens, output_tokens)
        with self._lock:
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            self.daily_spend += cost
            self.monthly_spend += cost
            
            # Print warnings if budget thresholds are crossed
            if self.monthly_spend >= config.MONTHLY_COST_LIMIT:
                logger.error(f"Monthly AI cost limit reached! spend=${self.monthly_spend:.4f}, budget=${config.MONTHLY_COST_LIMIT:.4f}")
            elif self.monthly_spend >= config.MONTHLY_COST_LIMIT * 0.8:
                logger.warning(f"Monthly AI cost warning (80% of budget reached)! spend=${self.monthly_spend:.4f}")
                
        return cost

    def is_budget_exceeded(self) -> bool:
        """
        If spend exceeds configured monthly limits.
        """
        with self._lock:
            return self.monthly_spend >= config.MONTHLY_COST_LIMIT

    def clear(self) -> None:
        with self._lock:
            self.daily_spend = 0.0
            self.monthly_spend = 0.0
            self.total_input_tokens = 0
            self.total_output_tokens = 0

# Global cost manager instance
cost_manager = CostManager()
