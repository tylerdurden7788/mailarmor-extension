import re
import time
import html
import unicodedata
from html.parser import HTMLParser
from typing import List, Dict, Tuple, Any, Optional

from models.html_model import (
    DOMNode, DocumentGraph, HTMLForm, HTMLInput,
    HTMLButton, HTMLScript, HTMLStyle, HTMLIframe, HTMLResource, HTMLContext
)
from models.email_model import Link
from scanner.base_dom_parser import BaseDOMParser
from scanner.html_feature_extractor import HTMLFeatureExtractor

class HTMLCanonicalizer:
    @staticmethod
    def canonicalize(raw_html: str) -> str:
        """
        Entity decoding, character normalization, tag and duplicate attribute cleanup.
        """
        if not raw_html:
            return ""
            
        # 1. HTML entity decoding
        canonical = html.unescape(raw_html)
        
        # 2. Unicode NFC normalization
        canonical = unicodedata.normalize("NFC", canonical)
        
        # 3. Collapse duplicate attributes inside tags using a regex scanner
        def clean_tag_attrs(match):
            tag_open = match.group(1)
            attrs_str = match.group(2)
            tag_close = match.group(3)
            
            # Extract attributes while keeping their casing
            attr_pairs = re.findall(r'([a-zA-Z0-9_-]+)(?:\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]+))?', attrs_str)
            seen_attrs = set()
            cleaned_pieces = []
            
            pos = 0
            for attr in attr_pairs:
                attr_lower = attr.lower()
                pattern = r'\b' + re.escape(attr) + r'(?:\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]+))?'
                found_match = re.search(pattern, attrs_str[pos:])
                if found_match:
                    full_assignment = found_match.group(0)
                    pos += found_match.end()
                    if attr_lower not in seen_attrs:
                        seen_attrs.add(attr_lower)
                        cleaned_pieces.append(full_assignment)
                        
            return f"<{tag_open} {' '.join(cleaned_pieces)}{tag_close}>"
            
        canonical = re.sub(r'<([a-zA-Z0-9:-]+)([^>]*)(/?)>', clean_tag_attrs, canonical)
        return canonical

class HTMLNormalizer:
    @staticmethod
    def normalize(canonical_html: str) -> str:
        """
        Standardizes whitespace, line endings, and case formats.
        """
        if not canonical_html:
            return ""
            
        normalized = canonical_html.replace("\r\n", "\n").replace("\r", "\n")
        normalized = re.sub(r'[ \t]+', ' ', normalized)
        return normalized

class InternalParser(HTMLParser):
    def __init__(self, max_depth: int = 32, max_nodes: int = 1000):
        super().__init__()
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        
        self.node_counter = 0
        self.root_node: Optional[DOMNode] = None
        self.warnings: List[str] = []
        self.recovery_actions: List[str] = []
        self.node_by_id: Dict[str, Dict[str, Any]] = {}
        self.stack: List[Dict[str, Any]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str]]):
        tag_lower = tag.lower()
        if self.node_counter >= self.max_nodes:
            if not self.warnings or "Max node count reached" not in self.warnings[-1]:
                self.warnings.append("Max node count reached during parsing. Truncated remaining nodes.")
            return
            
        current_depth = len(self.stack)
        if current_depth >= self.max_depth:
            self.warnings.append(f"Depth limit exceeded at tag <{tag_lower}>. Ignored nesting.")
            return
            
        self.node_counter += 1
        node_id = f"node_{self.node_counter}"
        
        attrs_dict = {k.lower(): v for k, v in attrs}
        parent_id = self.stack[-1]["node_id"] if self.stack else None
        parent_path = self.stack[-1]["dom_path"] if self.stack else ""
        
        path_selector = tag_lower
        if "id" in attrs_dict:
            path_selector += f"#{attrs_dict['id']}"
        elif "class" in attrs_dict:
            first_cls = attrs_dict["class"].split()[0] if attrs_dict["class"].split() else ""
            if first_cls:
                path_selector += f".{first_cls}"
                
        dom_path = f"{parent_path} > {path_selector}" if parent_path else path_selector
        
        node_builder = {
            "node_id": node_id,
            "tag": tag_lower,
            "attributes": attrs_dict,
            "children": [],
            "parent_id": parent_id,
            "dom_path": dom_path,
            "text_chunks": []
        }
        
        self.node_by_id[node_id] = node_builder
        
        if self.stack:
            self.stack[-1]["children"].append(node_builder)
        else:
            self.root_node_builder = node_builder
            
        self_closing = {
            "img", "input", "br", "hr", "meta", "link", "base", "col", "embed", "param", "source", "track", "wbr"
        }
        if tag_lower not in self_closing:
            self.stack.append(node_builder)

    def handle_endtag(self, tag: str):
        tag_lower = tag.lower()
        matched = False
        for idx in reversed(range(len(self.stack))):
            if self.stack[idx]["tag"] == tag_lower:
                matched = True
                self.stack = self.stack[:idx]
                break
        if not matched:
            self.recovery_actions.append(f"Discarded unmatched closing tag </{tag_lower}>")

    def handle_data(self, data: str):
        if self.stack:
            clean_text = data.strip()
            if clean_text:
                self.stack[-1]["text_chunks"].append(clean_text)

    def finalize(self) -> DOMNode:
        if not hasattr(self, "root_node_builder"):
            return DOMNode(node_id="node_empty", tag="div", dom_path="div")
        return self._finalize_builder(self.root_node_builder)

    def _finalize_builder(self, builder: Dict[str, Any]) -> DOMNode:
        children = [self._finalize_builder(child) for child in builder["children"]]
        inner_text = " ".join(builder["text_chunks"])
        return DOMNode(
            node_id=builder["node_id"],
            tag=builder["tag"],
            attributes=builder["attributes"],
            children=children,
            parent_id=builder["parent_id"],
            dom_path=builder["dom_path"],
            inner_text=inner_text
        )

class StandardHTMLDOMParser(BaseDOMParser):
    def __init__(self, max_depth: int = 32, max_nodes: int = 1000, max_size_bytes: int = 2 * 1024 * 1024):
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.max_size_bytes = max_size_bytes

    def parse(self, html_content: str) -> HTMLContext:
        """
        Canonicalizes, normalizes, parses HTML content, and extracts features under performance limits.
        """
        start_time = time.perf_counter()
        warnings = []
        canonical_warnings = []
        
        if not html_content:
            return HTMLContext()
            
        size_bytes = len(html_content.encode("utf-8", errors="ignore"))
        if size_bytes > self.max_size_bytes:
            warnings.append(f"HTML size exceeds {self.max_size_bytes} bytes. Truncated input.")
            html_content = html_content[:self.max_size_bytes // 2]
            
        # 1. Canonicalization
        canonical = HTMLCanonicalizer.canonicalize(html_content)
        
        # 2. Normalization
        normalized = HTMLNormalizer.normalize(canonical)
        
        # 3. Parsing DOM
        parser = InternalParser(max_depth=self.max_depth, max_nodes=self.max_nodes)
        try:
            parser.feed(normalized)
            root_node = parser.finalize()
            warnings.extend(parser.warnings)
        except Exception as e:
            root_node = DOMNode(node_id="node_error", tag="div", dom_path="div")
            warnings.append(f"Parser exception: {e}")
            
        # 4. Feature Extraction Layer
        features, doc_graph, stats = HTMLFeatureExtractor.extract_features(root_node)
        
        parse_duration_ms = (time.perf_counter() - start_time) * 1000.0
        
        return HTMLContext(
            root_node=root_node,
            forms=features["forms"],
            inputs=features["inputs"],
            buttons=features["buttons"],
            links=features["links"],
            images=features["images"],
            scripts=features["scripts"],
            styles=features["styles"],
            meta_tags=features["meta_tags"],
            base_tags=features["base_tags"],
            iframes=features["iframes"],
            embedded_resources=features["embedded_resources"],
            
            document_graph=doc_graph,
            parser_backend="StandardHTMLDOMParser",
            parser_recovery_actions=parser.recovery_actions,
            extraction_metadata={"features_count": sum(len(v) for v in features.values())},
            canonicalization_warnings=canonical_warnings,
            ignored_nodes=[],
            traversal_cache={},
            dom_statistics=stats,
            
            parser_warnings=warnings,
            normalization_metadata={
                "original_size_bytes": size_bytes,
                "normalized_size_bytes": len(normalized.encode("utf-8", errors="ignore"))
            },
            performance_metadata={
                "parse_duration_ms": parse_duration_ms,
                "total_nodes_parsed": parser.node_counter,
                "traversal_cache_hits": 0
            }
        )
