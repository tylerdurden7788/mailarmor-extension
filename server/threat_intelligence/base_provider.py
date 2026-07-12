from abc import ABC, abstractmethod
from typing import List
from models.threat_intelligence_model import ThreatObservable, ThreatEvidence

class BaseThreatProvider(ABC):
    @abstractmethod
    def name(self) -> str:
        """Returns the identifier name of this threat provider."""
        pass
        
    @abstractmethod
    def supported_observables(self) -> List[str]:
        """Returns a list of supported ThreatObservable types."""
        pass
        
    @abstractmethod
    async def lookup(self, observable: ThreatObservable) -> List[ThreatEvidence]:
        """Performs lookup against the threat intelligence source."""
        pass
        
    def is_supported(self, observable_type: str) -> bool:
        """Determines if the provider supports the given observable type."""
        return observable_type in self.supported_observables()
