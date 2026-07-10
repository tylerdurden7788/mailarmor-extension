from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.html_model import HTMLContext, DOMNode
from scanner.evidence import create_evidence

class CSSAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        if not context or not isinstance(context, HTMLContext) or not context.root_node:
            return evidence_list
            
        root = context.root_node
        metadata = {
            "analyzer_version": "2.0.0",
            "rule_version": "2.0.0",
            "data_source": "DOM HTML Style Elements & Inline CSS Attributes"
        }
        
        # Recursively inspect all DOM nodes for CSS trickery
        findings = []
        
        def inspect_node(node: DOMNode):
            style = node.attributes.get("style", "").replace(" ", "").lower()
            if style:
                # 1. Hidden properties on container or form elements
                if "display:none" in style or "visibility:hidden" in style or "opacity:0" in style:
                    # Only flag if it hides structural elements or inputs
                    if node.tag in ["form", "input", "a", "button", "iframe"]:
                        findings.append({
                            "type": "hidden_element",
                            "tag": node.tag,
                            "style": node.attributes["style"],
                            "dom_path": node.dom_path
                        })
                        
                # 2. Off-screen absolute positioning
                if "position:absolute" in style or "position:fixed" in style:
                    if any(f in style for f in ["left:-", "top:-", "margin-left:-", "margin-top:-"]):
                        findings.append({
                            "type": "offscreen_element",
                            "tag": node.tag,
                            "style": node.attributes["style"],
                            "dom_path": node.dom_path
                        })
                        
                # 3. Tiny fonts (zero-font tricks)
                font_match = [
                    "font-size:0", "font-size:1px", "font-size:0px", "font-size:0pt", "font-size:1pt"
                ]
                if any(fm in style for fm in font_match):
                    findings.append({
                        "type": "tiny_font",
                        "tag": node.tag,
                        "style": node.attributes["style"],
                        "dom_path": node.dom_path
                    })
                    
                # 4. Refined CSS Visual Deception Techniques
                if "pointer-events:none" in style:
                    findings.append({
                        "type": "pointer_events_none",
                        "tag": node.tag,
                        "style": node.attributes["style"],
                        "dom_path": node.dom_path
                    })
                if "clip-path:" in style:
                    findings.append({
                        "type": "clip_path_mask",
                        "tag": node.tag,
                        "style": node.attributes["style"],
                        "dom_path": node.dom_path
                    })
                if "transform:scale(0)" in style or "transform:translate(-" in style:
                    findings.append({
                        "type": "css_transform_hide",
                        "tag": node.tag,
                        "style": node.attributes["style"],
                        "dom_path": node.dom_path
                    })
                if "filter:opacity(0)" in style or "filter:blur" in style:
                    findings.append({
                        "type": "css_filter_deception",
                        "tag": node.tag,
                        "style": node.attributes["style"],
                        "dom_path": node.dom_path
                    })
                if ("position:fixed" in style or "position:absolute" in style) and ("z-index" in style or "width:100%" in style):
                    findings.append({
                        "type": "overlay_element",
                        "tag": node.tag,
                        "style": node.attributes["style"],
                        "dom_path": node.dom_path
                    })
                if "margin-" in style and "-" in style: # check negative margins
                    findings.append({
                        "type": "negative_margin_overlay",
                        "tag": node.tag,
                        "style": node.attributes["style"],
                        "dom_path": node.dom_path
                    })
                    
            for child in node.children:
                inspect_node(child)
                
        inspect_node(root)
        
        if findings:
            evidence_list.append(create_evidence(
                analyzer_name="CSSAnalyzer",
                rule_id="HTML_003",
                technical_details={
                    "findings": findings,
                    "metadata": metadata
                },
                confidence=0.70
            ))
            
        return evidence_list
