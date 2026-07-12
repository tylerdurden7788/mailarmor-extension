from typing import Dict, Any, List, Optional
from threat_intelligence.base_provider import BaseThreatProvider
from config.provider_config import PROVIDER_CONFIGS

class ProviderRegistry:
    def __init__(self):
        self._providers: Dict[str, BaseThreatProvider] = {}
        self._metadata: Dict[str, Dict[str, Any]] = {}
        
    def register(self, name: str, provider: BaseThreatProvider, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Dynamically registers a provider with optional custom configuration metadata."""
        self._providers[name] = provider
        
        # Merge configuration defaults with custom metadata
        config_meta = dict(PROVIDER_CONFIGS.get(name, {
            "enabled": True,
            "timeout": 2.0,
            "retry_count": 2,
            "cache_ttl": 300,
            "supported_observables": provider.supported_observables()
        }))
        
        if metadata:
            config_meta.update(metadata)
            
        # Add dynamic health status defaults
        if "health_status" not in config_meta:
            config_meta["health_status"] = "Healthy"
            
        self._metadata[name] = config_meta
        
    def unregister(self, name: str) -> None:
        """Removes a registered provider."""
        if name in self._providers:
            del self._providers[name]
        if name in self._metadata:
            del self._metadata[name]
            
    def get_provider(self, name: str) -> Optional[BaseThreatProvider]:
        """Retrieves a provider instance by name."""
        return self._providers.get(name)
        
    def get_all_providers(self) -> List[BaseThreatProvider]:
        """Retrieves all registered providers."""
        return list(self._providers.values())
        
    def get_metadata(self, name: str) -> Optional[Dict[str, Any]]:
        """Retrieves configuration and metadata for a provider."""
        return self._metadata.get(name)
        
    def update_metadata(self, name: str, key: str, value: Any) -> None:
        """Updates specific configuration keys on the provider metadata (e.g. health status)."""
        if name in self._metadata:
            self._metadata[name][key] = value
            
    def get_enabled_providers(self) -> List[str]:
        """Returns names of all enabled providers."""
        return [
            name for name, meta in self._metadata.items()
            if meta.get("enabled", True)
        ]
