import os
from typing import List, Dict, Any, Tuple
from models.html_model import (
    DOMNode, HTMLForm, HTMLInput, HTMLButton, HTMLScript,
    HTMLStyle, HTMLIframe, HTMLResource, DocumentGraph
)
from models.email_model import Link
from utils.string_utils import normalize_whitespace

class HTMLFeatureExtractor:
    @staticmethod
    def extract_features(root_node: DOMNode) -> Tuple[Dict[str, List[Any]], DocumentGraph, Dict[str, Any]]:
        """
        HTML Feature Extraction Layer.
        Traverses the parsed DOMNode tree to extract structured components, relationships, and stats.
        """
        features = {
            "forms": [],
            "inputs": [],
            "buttons": [],
            "links": [],
            "images": [],
            "scripts": [],
            "styles": [],
            "meta_tags": [],
            "base_tags": [],
            "iframes": [],
            "embedded_resources": []
        }
        
        # Mappings for DocumentGraph
        parent_map = {}
        sibling_map = {}
        by_tag_map = {}
        elements_map = {}
        brand_association_map = {}
        
        # Statistics
        tag_counts = {}
        total_nodes = 0
        max_depth = 0
        
        def traverse(node: DOMNode, depth: int = 1):
            nonlocal total_nodes, max_depth
            if not node:
                return
                
            total_nodes += 1
            max_depth = max(max_depth, depth)
            
            node_id = node.node_id
            tag = node.tag
            attrs = node.attributes
            dom_path = node.dom_path
            
            # Tag count statistics
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
            
            # Add to tag map
            if tag not in by_tag_map:
                by_tag_map[tag] = []
            by_tag_map[tag].append(node_id)
            
            # Elements Map
            elements_map[node_id] = node
            
            # Siblings & Parent mappings
            child_ids = [child.node_id for child in node.children]
            for child_id in child_ids:
                parent_map[child_id] = node_id
                sibling_map[child_id] = [cid for cid in child_ids if cid != child_id]
                
            # Perform element-specific extraction from DOMNode
            # 1. Inputs
            if tag == "input":
                is_hidden = attrs.get("type", "").lower() == "hidden"
                inp_obj = HTMLInput(
                    type=attrs.get("type"),
                    name=attrs.get("name"),
                    id=attrs.get("id"),
                    value=attrs.get("value"),
                    is_hidden=is_hidden,
                    dom_path=dom_path
                )
                features["inputs"].append(inp_obj)
                
            # 2. Forms
            elif tag == "form":
                form_obj = HTMLForm(
                    action=attrs.get("action"),
                    method=attrs.get("method", "post").lower(),
                    inputs=[], # Will be populated during parent/child matching or post-process
                    dom_path=dom_path
                )
                features["forms"].append(form_obj)
                
            # 3. Buttons
            elif tag == "button" or (tag == "input" and attrs.get("type", "").lower() in ["submit", "button"]):
                features["buttons"].append(HTMLButton(
                    text=attrs.get("value", "") if tag == "input" else node.inner_text,
                    type=attrs.get("type"),
                    class_name=attrs.get("class"),
                    dom_path=dom_path
                ))
                
            # 4. Links
            elif tag == "a" and "href" in attrs:
                features["links"].append(Link(
                    actual_url=attrs["href"],
                    display_text=normalize_whitespace(node.inner_text),
                    is_button="btn" in attrs.get("class", "").lower(),
                    has_mismatch=False
                ))
                
            # 5. Images
            elif tag == "img" and "src" in attrs:
                src = attrs["src"]
                res_type = "data_uri" if src.startswith("data:") else "image"
                res_obj = HTMLResource(src=src, resource_type=res_type, dom_path=dom_path)
                features["images"].append(res_obj)
                features["embedded_resources"].append(res_obj)
                
            # 6. Scripts
            elif tag == "script":
                script_obj = HTMLScript(
                    src=attrs.get("src"),
                    content=node.inner_text,
                    dom_path=dom_path
                )
                features["scripts"].append(script_obj)
                if attrs.get("src"):
                    features["embedded_resources"].append(HTMLResource(
                        src=attrs["src"], resource_type="script", dom_path=dom_path
                    ))
                    
            # 7. Styles
            elif tag == "style":
                features["styles"].append(HTMLStyle(
                    content=node.inner_text,
                    media=attrs.get("media"),
                    dom_path=dom_path
                ))
            elif tag == "link" and attrs.get("rel", "").lower() == "stylesheet" and "href" in attrs:
                features["embedded_resources"].append(HTMLResource(
                    src=attrs["href"], resource_type="style", dom_path=dom_path
                ))
            elif tag == "link" and "icon" in attrs.get("rel", "").lower() and "href" in attrs:
                features["embedded_resources"].append(HTMLResource(
                    src=attrs["href"], resource_type="favicon", dom_path=dom_path
                ))
            elif tag == "link" and attrs.get("rel", "").lower() == "preload" and "href" in attrs:
                res_type = attrs.get("as", "resource")
                features["embedded_resources"].append(HTMLResource(
                    src=attrs["href"], resource_type=res_type, dom_path=dom_path
                ))
                
            # 8. Meta & Base URL tags
            elif tag == "meta":
                features["meta_tags"].append(attrs)
            elif tag == "base":
                features["base_tags"].append(attrs)
                
            # 9. Iframes
            elif tag == "iframe":
                features["iframes"].append(HTMLIframe(
                    src=attrs.get("src"),
                    sandbox=attrs.get("sandbox"),
                    width=attrs.get("width"),
                    height=attrs.get("height"),
                    is_hidden="display:none" in attrs.get("style", "").replace(" ", "").lower(),
                    dom_path=dom_path
                ))
                if attrs.get("src"):
                    features["embedded_resources"].append(HTMLResource(
                        src=attrs["src"], resource_type="iframe", dom_path=dom_path
                    ))
                    
            # 10. Additional embedded objects
            elif tag in ["object", "embed"]:
                src = attrs.get("data") or attrs.get("src") or ""
                if src:
                    features["embedded_resources"].append(HTMLResource(
                        src=src, resource_type="object", dom_path=dom_path
                    ))
                    
            for child in node.children:
                traverse(child, depth + 1)
                
        traverse(root_node)
        
        # Post-process: associate inputs with their parent forms
        # We can map input nodes located inside form elements using DOM Paths
        for form in features["forms"]:
            form_inputs = []
            for inp in features["inputs"]:
                if inp.dom_path and form.dom_path and inp.dom_path.startswith(form.dom_path):
                    form_inputs.append(inp)
            # Forms are immutable Pydantic models (frozen), but we can rebuild them
            idx = features["forms"].index(form)
            features["forms"][idx] = HTMLForm(
                action=form.action,
                method=form.method,
                inputs=form_inputs,
                dom_path=form.dom_path
            )
            
        doc_graph = DocumentGraph(
            parent_map=parent_map,
            sibling_map=sibling_map,
            by_tag_map=by_tag_map,
            elements_map=elements_map,
            brand_association_map=brand_association_map
        )
        
        stats = {
            "total_nodes": total_nodes,
            "max_depth": max_depth,
            "tag_counts": tag_counts
        }
        
        return features, doc_graph, stats
