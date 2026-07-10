from utils.unicode_utils import punycode_decode

class SimilarityStrategy:
    def calculate_similarity(self, term1: str, term2: str) -> float:
        raise NotImplementedError

class LevenshteinDistanceStrategy(SimilarityStrategy):
    def calculate_similarity(self, term1: str, term2: str) -> float:
        if term1 == term2:
            return 1.0
        if not term1 or not term2:
            return 0.0
            
        m, n = len(term1), len(term2)
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        
        for i in range(m + 1):
            dp[i][0] = i
        for j in range(n + 1):
            dp[0][j] = j
            
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                cost = 0 if term1[i-1] == term2[j-1] else 1
                dp[i][j] = min(
                    dp[i-1][j] + 1,      # Deletion
                    dp[i][j-1] + 1,      # Insertion
                    dp[i-1][j-1] + cost   # Substitution
                )
                
        distance = dp[m][n]
        max_len = max(m, n)
        return 1.0 - (distance / max_len)

class VisualConfusableStrategy(SimilarityStrategy):
    def calculate_similarity(self, term1: str, term2: str) -> float:
        t1 = punycode_decode(term1).lower()
        t2 = punycode_decode(term2).lower()
        
        if t1 == t2:
            return 1.0
            
        # Map Cyrillic confusable lookalikes back to ASCII
        confusables = {
            '\u0430': 'a', # Cyrillic a
            '\u0441': 'c', # Cyrillic es
            '\u0435': 'e', # Cyrillic ie
            '\u043e': 'o', # Cyrillic o
            '\u0440': 'p', # Cyrillic er
            '\u0443': 'y', # Cyrillic u
            '\u0445': 'x', # Cyrillic ha
            '\u0456': 'i', # Cyrillic i
            '\u0455': 's', # Cyrillic dze
            '\u045b': 'h', # Cyrillic tshe
        }
        
        mapped = "".join(confusables.get(c, c) for c in t1)
        if mapped == t2:
            return 0.99  # Visual match is practically identical
            
        return 0.0

class SubdomainSimilarityStrategy(SimilarityStrategy):
    def calculate_similarity(self, term1: str, term2: str) -> float:
        # Measures overlap of subdomain labels
        labels1 = set(term1.split('.'))
        labels2 = set(term2.split('.'))
        if not labels1 or not labels2:
            return 0.0
        intersection = labels1.intersection(labels2)
        union = labels1.union(labels2)
        return len(intersection) / len(union)

class PathSimilarityStrategy(SimilarityStrategy):
    def calculate_similarity(self, term1: str, term2: str) -> float:
        t1 = term1.strip('/').split('/')
        t2 = term2.strip('/').split('/')
        if not t1 or not t2:
            return 0.0
        # Check path segment overlap
        overlap = sum(1 for s1, s2 in zip(t1, t2) if s1 == s2)
        return overlap / max(len(t1), len(t2))
