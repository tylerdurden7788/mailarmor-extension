import math
from collections import Counter

class EntropyStrategy:
    def calculate_entropy(self, text: str) -> float:
        raise NotImplementedError

class ShannonEntropyStrategy(EntropyStrategy):
    def calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        counts = Counter(text)
        length = len(text)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy
