import time
import math
from typing import Dict, Any, List

class MetricsCollector:
    def __init__(self):
        # Provider metrics: provider_name -> dict
        self._provider_metrics: Dict[str, Dict[str, Any]] = {}
        # Decision metrics
        self._decision_latencies: List[float] = []
        self._ioc_consensus_count = 0
        self._total_agreement_score_sum = 0.0
        self._agreement_score_count = 0
        self._threat_categories: Dict[str, int] = {}

    def _init_provider(self, provider_name: str) -> None:
        if provider_name not in self._provider_metrics:
            self._provider_metrics[provider_name] = {
                "requests": 0,
                "successes": 0,
                "failures": 0,
                "timeouts": 0,
                "latencies": [],
                "cache_hits": 0,
                "cache_misses": 0,
                "evictions": 0,
                "expired_entries": 0
            }

    def record_request(self, provider_name: str) -> None:
        self._init_provider(provider_name)
        self._provider_metrics[provider_name]["requests"] += 1

    def record_success(self, provider_name: str, latency_ms: float) -> None:
        self._init_provider(provider_name)
        m = self._provider_metrics[provider_name]
        m["successes"] += 1
        m["latencies"].append(latency_ms)

    def record_failure(self, provider_name: str) -> None:
        self._init_provider(provider_name)
        self._provider_metrics[provider_name]["failures"] += 1

    def record_timeout(self, provider_name: str) -> None:
        self._init_provider(provider_name)
        self._provider_metrics[provider_name]["timeouts"] += 1

    def record_cache_hit(self, provider_name: str) -> None:
        self._init_provider(provider_name)
        self._provider_metrics[provider_name]["cache_hits"] += 1

    def record_cache_miss(self, provider_name: str) -> None:
        self._init_provider(provider_name)
        self._provider_metrics[provider_name]["cache_misses"] += 1

    def record_cache_eviction(self, provider_name: str) -> None:
        self._init_provider(provider_name)
        self._provider_metrics[provider_name]["evictions"] += 1

    def record_cache_expiry(self, provider_name: str) -> None:
        self._init_provider(provider_name)
        self._provider_metrics[provider_name]["expired_entries"] += 1

    def record_decision(self, latency_ms: float, consensus_count: int, avg_agreement: float, categories: List[str]) -> None:
        self._decision_latencies.append(latency_ms)
        self._ioc_consensus_count += consensus_count
        if avg_agreement > 0.0 or consensus_count > 0:
            self._total_agreement_score_sum += avg_agreement
            self._agreement_score_count += 1
        for cat in categories:
            self._threat_categories[cat] = self._threat_categories.get(cat, 0) + 1

    def _calculate_p95(self, values: List[float]) -> float:
        if not values:
            return 0.0
        sorted_vals = sorted(values)
        idx = math.ceil(len(sorted_vals) * 0.95) - 1
        return sorted_vals[max(0, min(idx, len(sorted_vals) - 1))]

    def get_provider_statistics(self, provider_name: str) -> Dict[str, Any]:
        self._init_provider(provider_name)
        m = self._provider_metrics[provider_name]
        latencies = m["latencies"]
        avg_lat = sum(latencies) / len(latencies) if latencies else 0.0
        p95_lat = self._calculate_p95(latencies)
        
        total_cache = m["cache_hits"] + m["cache_misses"]
        hit_ratio = m["cache_hits"] / total_cache if total_cache > 0 else 0.0
        
        return {
            "requests": m["requests"],
            "successes": m["successes"],
            "failures": m["failures"],
            "timeouts": m["timeouts"],
            "average_latency_ms": avg_lat,
            "p95_latency_ms": p95_lat,
            "cache_hit_ratio": hit_ratio,
            "cache_hits": m["cache_hits"],
            "cache_misses": m["cache_misses"],
            "evictions": m["evictions"],
            "expired_entries": m["expired_entries"]
        }

    def get_decision_statistics(self) -> Dict[str, Any]:
        avg_lat = sum(self._decision_latencies) / len(self._decision_latencies) if self._decision_latencies else 0.0
        p95_lat = self._calculate_p95(self._decision_latencies)
        avg_agreement = self._total_agreement_score_sum / self._agreement_score_count if self._agreement_score_count > 0 else 0.0
        
        return {
            "average_decision_latency_ms": avg_lat,
            "p95_decision_latency_ms": p95_lat,
            "ioc_consensus_count": self._ioc_consensus_count,
            "average_agreement_score": avg_agreement,
            "threat_categories": dict(self._threat_categories)
        }

# Global singleton metrics instance
metrics_collector = MetricsCollector()
