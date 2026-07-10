from typing import List, Dict, Type
from analyzers.base_analyzer import BaseAnalyzer

class PluginManager:
    def __init__(self):
        self._registry: Dict[str, BaseAnalyzer] = {}

    def register(self, name: str, analyzer_instance: BaseAnalyzer) -> None:
        """
        Registers an analyzer instance under a unique name.
        """
        self._registry[name] = analyzer_instance
        print(f"[PluginManager] Registered analyzer: {name}")

    def get_analyzers(self) -> List[BaseAnalyzer]:
        """
        Returns a list of all currently registered analyzer instances.
        """
        return list(self._registry.values())

    def get_analyzer_names(self) -> List[str]:
        """
        Returns registered analyzer names.
        """
        return list(self._registry.keys())

# Create a global plugin manager instance
plugin_manager = PluginManager()
