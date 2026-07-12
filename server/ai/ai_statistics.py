import threading
from typing import List, Dict, Any

class AIStatistics:
    def __init__(self):
        self.latencies: List[float] = []
        self.total_cost = 0.0
        self.cache_hits_count = 0
        self.cache_misses_count = 0
        self._lock = threading.Lock()

    def record_stats(self, latency: float, cost: float, cache_hit: bool) -> None:
        with self._lock:
            self.latencies.append(latency)
            self.latencies.sort()
            self.total_cost += cost
            if cache_hit:
                self.cache_hits_count += 1
            else:
                self.cache_misses_count += 1

    def get_statistics(self) -> Dict[str, Any]:
        with self._lock:
            count = len(self.latencies)
            if count == 0:
                return {
                    "avg_latency_sec": 0.0,
                    "p95_latency_sec": 0.0,
                    "total_spend_usd": 0.0,
                    "cache_efficiency_percentage": 0.0
                }
                
            avg_l = sum(self.latencies) / count
            
            # P95 latency calculation
            p95_idx = min(int(count * 0.95), count - 1)
            p95_l = self.latencies[p95_idx]
            
            cache_efficiency = (self.cache_hits_count / (self.cache_hits_count + self.cache_misses_count)) * 100.0 if (self.cache_hits_count + self.cache_misses_count) > 0 else 0.0
            
            return {
                "avg_latency_sec": avg_l,
                "p95_latency_sec": p95_l,
                "total_spend_usd": self.total_cost,
                "cache_efficiency_percentage": cache_efficiency
            }

    def clear(self) -> None:
        with self._lock:
            self.latencies.clear()
            self.total_cost = 0.0
            self.cache_hits_count = 0
            self.cache_misses_count = 0

# Global statistics collector instance
ai_statistics = AIStatistics()
