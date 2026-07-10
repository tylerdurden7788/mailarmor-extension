from models.email_model import Email
from models.evidence_model import Evidence

class BaseAnalyzer:
    def __init__(self, config: dict = None):
        self.config = config or {}

    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        """
        Runs the analyzer on the normalized Email object and returns a list of collected Evidence.
        """
        raise NotImplementedError("Analyzers must implement the analyze method.")
