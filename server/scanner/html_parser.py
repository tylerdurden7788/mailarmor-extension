import re
import time
import html
import unicodedata
from html.parser import HTMLParser
from typing import List, Dict, Tuple, Any, Optional

from models.html_model import (
    DOMNode, DOMRelationshipGraph, HTMLForm, HTMLInput,
    HTMLButton, HTMLScript, HTMLStyle, HTMLIframe, HTMLResource, HTMLContext
)
from models.email_model import Link
from scanner.base_dom_parser import BaseDOMParser

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
        # Tag attributes finder
        def clean_tag_attrs(match):
            tag_open = match.group(1)
            attrs_str = match.group(2)
            tag_close = match.group(3)
            
            # Extract attributes while keeping their casing
            attr_pairs = re.findall(r'([a-zA-Z0-9_-]+)(?:\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]+))?', attrs_str)
            seen_attrs = set()
            cleaned_pieces = []
            
            # Simple attribute scanner to preserve the first occurrence
            pos = 0
            for attr in attr_pairs:
                attr_lower = attr.lower()
                # Find boundaries of this attribute assignment in attrs_str
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
            
        # 1. Normalize line endings
        normalized = canonical_html.replace("\r\n", "\n").replace("\r", "\n")
        
        # 2. Standardize whitespace
        normalized = re.sub(r'[ \t]+', ' ', normalized)
        
        return normalized

class InternalParser(HTMLParser):
    def __init__(self, max_depth: int = 32, max_nodes: int = 1000):
        super().__init__()
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        
        # DOM Builder structures
        self.node_counter = 0
        self.root_node: Optional[DOMNode] = None
        self.warnings: List[str] = []
        self.node_by_id: Dict[str, Dict[str, Any]] = {}
        
        # Stack tracks active node builders
        # Builder dict structure: { "node_id", "tag", "attributes", "children": [], "parent_id", "dom_path", "text_chunks": [] }
        self.stack: List[Dict[str, Any]] = []
        
        # Parsed elements
        self.forms: List[HTMLForm] = []
        self.inputs: List[HTMLInput] = []
        self.buttons: List[HTMLButton] = []
        self.links: List[Link] = []
        self.images: List[HTMLResource] = []
        self.scripts: List[HTMLScript] = []
        self.styles: List[HTMLStyle] = []
        self.meta_tags: List[Dict[str, str]] = []
        self.base_tags: List[Dict[str, str]] = []
        self.iframes: List[HTMLIframe] = []
        self.embedded_resources: List[HTMLResource] = []

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
        
        # Construct path component (tag + id class tags if available)
        path_selector = tag_lower
        if "id" in attrs_dict:
            path_selector += f"#{attrs_dict['id']}"
        elif "class" in attrs_dict:
            # First class label
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
        
        # Keep references of parent-child hierarchy in builder stack
        if self.stack:
            self.stack[-1]["children"].append(node_builder)
        else:
            # Root node
            self.root_node_builder = node_builder
            
        # Elements registration
        self._register_elements(tag_lower, attrs_dict, dom_path)
        
        # Self-closing HTML tags do not push to stack
        self_closing = {
            "img", "input", "br", "hr", "meta", "link", "base", "col", "embed", "param", "source", "track", "wbr"
        }
        if tag_lower not in self_closing:
            self.stack.append(node_builder)

    def handle_endtag(self, tag: str):
        tag_lower = tag.lower()
        # Find matching open tag in stack
        for idx in reversed(range(len(self.stack))):
            if self.stack[idx]["tag"] == tag_lower:
                node_builder = self.stack[idx]
                inner_content = " ".join(node_builder["text_chunks"])
                
                if tag_lower == "script" and self.scripts:
                    last_script = self.scripts[-1]
                    self.scripts[-1] = HTMLScript(
                        src=last_script.src,
                        content=inner_content,
                        dom_path=last_script.dom_path
                    )
                elif tag_lower == "style" and self.styles:
                    last_style = self.styles[-1]
                    self.styles[-1] = HTMLStyle(
                        content=inner_content,
                        media=last_style.media,
                        dom_path=last_style.dom_path
                    )
                
                # Pop up to matched tag
                self.stack = self.stack[:idx]
                break

    def handle_data(self, data: str):
        if self.stack:
            clean_text = data.strip()
            if clean_text:
                self.stack[-1]["text_chunks"].append(clean_text)

    def _register_elements(self, tag: str, attrs: Dict[str, str], dom_path: str):
        # 1. Inputs & Forms
        if tag == "input":
            is_hidden = attrs.get("type", "").lower() == "hidden"
            self.inputs.append(HTMLInput(
                type=attrs.get("type"),
                name=attrs.get("name"),
                id=attrs.get("id"),
                value=attrs.get("value"),
                is_hidden=is_hidden,
                dom_path=dom_path
            ))
        elif tag == "form":
            self.forms.append(HTMLForm(
                action=attrs.get("action"),
                method=attrs.get("method", "post").lower(),
                inputs=[],
                dom_path=dom_path
            ))
            
        # 2. Buttons
        elif tag == "button" or (tag == "input" and attrs.get("type", "").lower() in ["submit", "button"]):
            self.buttons.append(HTMLButton(
                text=attrs.get("value", "") if tag == "input" else "",
                type=attrs.get("type"),
                class_name=attrs.get("class"),
                dom_path=dom_path
            ))
            
        # 3. Links
        elif tag == "a" and "href" in attrs:
            self.links.append(Link(
                actual_url=attrs["href"],
                display_text="", # Will be set during closing/data parsing or defaults
                is_button="btn" in attrs.get("class", "").lower(),
                has_mismatch=False
            ))
            
        # 4. Images & Resources
        elif tag == "img" and "src" in attrs:
            src = attrs["src"]
            res_type = "data_uri" if src.startswith("data:") else "image"
            self.images.append(HTMLResource(src=src, resource_type=res_type, dom_path=dom_path))
            self.embedded_resources.append(HTMLResource(src=src, resource_type=res_type, dom_path=dom_path))
            
        # 5. Scripts
        elif tag == "script":
            self.scripts.append(HTMLScript(
                src=attrs.get("src"),
                content="", # Set in closing tag data
                dom_path=dom_path
            ))
            if attrs.get("src"):
                self.embedded_resources.append(HTMLResource(src=attrs["src"], resource_type="script", dom_path=dom_path))
                
        # 6. Styles
        elif tag == "style":
            self.styles.append(HTMLStyle(
                content="",
                media=attrs.get("media"),
                dom_path=dom_path
            ))
        elif tag == "link" and attrs.get("rel", "").lower() == "stylesheet" and "href" in attrs:
            self.embedded_resources.append(HTMLResource(src=attrs["href"], resource_type="style", dom_path=dom_path))
        elif tag == "link" and "icon" in attrs.get("rel", "").lower() and "href" in attrs:
            self.embedded_resources.append(HTMLResource(src=attrs["href"], resource_type="favicon", dom_path=dom_path))
        elif tag == "link" and attrs.get("rel", "").lower() == "preload" and "href" in attrs:
            res_type = attrs.get("as", "resource")
            self.embedded_resources.append(HTMLResource(src=attrs["href"], resource_type=res_type, dom_path=dom_path))
            
        # 7. Meta & Base URL tags
        elif tag == "meta":
            self.meta_tags.append(attrs)
        elif tag == "base":
            self.base_tags.append(attrs)
            
        # 8. Iframes
        elif tag == "iframe":
            self.iframes.append(HTMLIframe(
                src=attrs.get("src"),
                sandbox=attrs.get("sandbox"),
                width=attrs.get("width"),
                height=attrs.get("height"),
                is_hidden="display:none" in attrs.get("style", "").replace(" ", "").lower(),
                dom_path=dom_path
            ))
            if attrs.get("src"):
                self.embedded_resources.append(HTMLResource(src=attrs["src"], resource_type="iframe", dom_path=dom_path))

    def finalize(self) -> DOMNode:
        """
        Recursively maps builder nodes to finalized frozen DOMNode models.
        """
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
        Canonicalizes, normalizes, and parses HTML content under resource limit controls.
        """
        start_time = time.perf_counter()
        warnings = []
        
        if not html_content:
            return HTMLContext()
            
        # 1. Size control
        size_bytes = len(html_content.encode("utf-8", errors="ignore"))
        if size_bytes > self.max_size_bytes:
            warnings.append(f"HTML size exceeds {self.max_size_bytes} bytes. Truncated input.")
            html_content = html_content[:self.max_size_bytes // 2] # simple safety cut
            
        # 2. Canonicalization
        canonical = HTMLCanonicalizer.canonicalize(html_content)
        
        # 3. Normalization
        normalized = HTMLNormalizer.normalize(canonical)
        
        # 4. Parsing
        parser = InternalParser(max_depth=self.max_depth, max_nodes=self.max_nodes)
        try:
            parser.feed(normalized)
            root_node = parser.finalize()
            warnings.extend(parser.warnings)
        except Exception as e:
            root_node = DOMNode(node_id="node_error", tag="div", dom_path="div")
            warnings.append(f"Parser exception encountered: {e}")
            
        # 5. DOM Relationship Graph Construction
        parent_map = {}
        sibling_map = {}
        by_tag_map = {}
        
        def traverse_graph(node: DOMNode):
            node_id = node.node_id
            tag = node.tag
            
            # Map tag
            if tag not in by_tag_map:
                by_tag_map[tag] = []
            by_tag_map[tag].append(node_id)
            
            # Map children siblings & parents
            child_ids = [child.node_id for child in node.children]
            for child_id in child_ids:
                parent_map[child_id] = node_id
                # Siblings are all other children of the same parent
                sibling_map[child_id] = [cid for cid in child_ids if cid != child_id]
                
            for child in node.children:
                traverse_graph(child)
                
        if root_node:
            traverse_graph(root_node)
            
        relationship_graph = DOMRelationshipGraph(
            parent_map=parent_map,
            sibling_map=sibling_map,
            by_tag_map=by_tag_map
        )
        
        parse_duration_ms = (time.perf_counter() - start_time) * 1000.0
        
        return HTMLContext(
            root_node=root_node,
            forms=parser.forms,
            inputs=parser.inputs,
            buttons=parser.buttons,
            links=parser.links,
            images=parser.images,
            scripts=parser.scripts,
            styles=parser.styles,
            meta_tags=parser.meta_tags,
            base_tags=parser.base_tags,
            iframes=parser.iframes,
            embedded_resources=parser.embedded_resources,
            relationship_graph=relationship_graph,
            parser_warnings=warnings,
            normalization_metadata={
                "original_size_bytes": size_bytes,
                "normalized_size_bytes": len(normalized.encode("utf-8", errors="ignore"))
            },
            performance_metadata={
                "parse_duration_ms": parse_duration_ms,
                "total_nodes_parsed": parser.node_counter,
                "traversal_cache_hits": 0 # Tracked during analyzer execution
            }
        )
