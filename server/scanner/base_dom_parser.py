from models.html_model import HTMLContext

class BaseDOMParser:
    def parse(self, html_content: str) -> HTMLContext:
        """
        Abstract base DOM parser interface.
        Analyzers consume the returned immutable HTMLContext.
        """
        raise NotImplementedError
