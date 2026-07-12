import time
from typing import Dict, Any

class AIProfiler:
    def __init__(self):
        self._timers: Dict[str, float] = {}
        self._durations: Dict[str, float] = {}

    def start_timer(self, stage: str) -> None:
        self._timers[stage] = time.time()

    def stop_timer(self, stage: str) -> float:
        if stage in self._timers:
            start = self._timers.pop(stage)
            duration = time.time() - start
            self._durations[stage] = duration
            return duration
        return 0.0

    def get_profile_summary(self) -> Dict[str, float]:
        return dict(self._durations)

    def clear(self) -> None:
        self._timers.clear()
        self._durations.clear()
