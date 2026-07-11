import re
from typing import List, Dict, Any, Tuple
from models.html_model import DocumentGraph
from models.semantic_model import SemanticFeature, SemanticContext

class SemanticFeatureExtractor:
    @staticmethod
    def extract_features(text: str, html: str) -> SemanticContext:
        """
        Main entry point for semantic extraction from raw text/HTML email bodies.
        """
        # 1. Canonicalization
        canonical_text = SemanticFeatureExtractor._canonicalize(text, html)
        
        # 2. Extract semantic indicators
        features = SemanticFeatureExtractor._extract_indicators(canonical_text)
        
        # 3. Infer Intents, Actions, and Social Engineering techniques
        intents = SemanticFeatureExtractor._infer_intents(features, canonical_text)
        victim_actions = SemanticFeatureExtractor._infer_victim_actions(features, canonical_text)
        soc_eng = SemanticFeatureExtractor._infer_soc_eng(features, canonical_text)
        
        # 4. Integrate into DocumentGraph
        graph = SemanticFeatureExtractor._build_document_graph(
            features, intents, victim_actions, soc_eng
        )
        
        return SemanticContext(
            canonicalized_text=canonical_text,
            features=features,
            intents=intents,
            victim_actions=victim_actions,
            soc_eng_techniques=soc_eng,
            document_graph=graph
        )

    @staticmethod
    def _canonicalize(text: str, html: str) -> str:
        """
        Strips tags, normalizes whitespace, lowercase, splits into readable text.
        """
        # Fallback to HTML tag stripping if text body is empty
        source = text if text else html
        if not source:
            return ""
            
        # Strip simple HTML comments and tags
        clean = re.sub(r'<!--.*?-->', '', source, flags=re.DOTALL)
        clean = re.sub(r'<style.*?>.*?</style>', '', clean, flags=re.DOTALL)
        clean = re.sub(r'<script.*?>.*?</script>', '', clean, flags=re.DOTALL)
        clean = re.sub(r'<.*?>', ' ', clean)
        
        # Replace multiple spaces/newlines
        clean = " ".join(clean.split())
        return clean.strip()

    @staticmethod
    def _extract_indicators(text: str) -> List[SemanticFeature]:
        features = []
        text_lower = text.lower()
        
        # Semantic Pattern Dictionaries
        patterns = {
            "urgency": [
                (r"\b(immediate(ly)?|urgent(ly)?|action required|suspended|deactivated|disabled|lock(ed)?|must resolve|asap)\b", "urgency_indicator"),
                (r"\b(within\s+\d+\s*(hour|day|min)s?|by\s+(tomorrow|today|tonight|due\s+date))\b", "deadline_indicator")
            ],
            "financial": [
                (r"\b(invoice|billing|outstanding|past due|amount due|payment details|routing number|wire transfer|direct deposit|bank account|payroll|salary|direct deposit)\b", "financial_reference"),
                (r"\b(bitcoin|btc|wallet address|cryptocurrency|crypto|gift\s*card)\b", "alternative_payment")
            ],
            "credential": [
                (r"\b(log\s*in|enter credentials|password|passcode|passphrase|mfa|otp|verify account|confirm details|one-time password|verification code)\b", "auth_factor"),
                (r"\b(oauth|grant access|app permissions|request scopes)\b", "oauth_scope")
            ],
            "identity": [
                (r"\b(ceo|cfo|president|founder|director|hr|human resources|helpdesk|support team|admin|administrator|it support)\b", "impersonation_target")
            ],
            "scam_rewards": [
                (r"\b(winner|won|lottery|prize|reward|gift card|bonus|refund|reimbursement|compensation)\b", "reward_incentive"),
                (r"\b(webcam|spyware|compromised|hacked|police|arrest|prosecution|leak your|extortion|blackmail)\b", "coercion_threat")
            ]
        }
        
        for category, list_patterns in patterns.items():
            for regex, sub_value in list_patterns:
                for match in re.finditer(regex, text_lower):
                    start, end = match.span()
                    # Extract 60 characters window context
                    start_ctx = max(0, start - 30)
                    end_ctx = min(len(text), end + 30)
                    snippet = text[start_ctx:end_ctx].strip()
                    
                    features.append(SemanticFeature(
                        category=category,
                        value=sub_value,
                        confidence=0.85,
                        context_snippet=f"... {snippet} ..."
                    ))
                    
        return features

    @staticmethod
    def _infer_intents(features: List[SemanticFeature], text: str) -> List[str]:
        intents = []
        text_lower = text.lower()
        
        # Check credential collection triggers
        has_auth = any(f.value == "auth_factor" for f in features)
        has_oauth = any(f.value == "oauth_scope" for f in features)
        has_fin = any(f.value in ["financial_reference", "alternative_payment"] for f in features)
        has_threat = any(f.value == "coercion_threat" for f in features)
        has_reward = any(f.value == "reward_incentive" for f in features)
        
        if has_auth and ("verify" in text_lower or "confirm" in text_lower or "update" in text_lower):
            intents.append("Credential Collection")
        if has_oauth:
            intents.append("OAuth Consent")
        if has_fin:
            if "update" in text_lower or "change" in text_lower or "routing" in text_lower:
                intents.append("Payment Diversion")
            elif "invoice" in text_lower or "due" in text_lower or "pay" in text_lower:
                intents.append("Invoice Approval")
            else:
                intents.append("Money Transfer")
        if has_threat:
            intents.append("Extortion")
        if has_reward:
            intents.append("Information Collection")
            
        # Default fallback
        if not intents:
            if "help" in text_lower or "support" in text_lower:
                intents.append("Information Collection")
                
        return list(set(intents))

    @staticmethod
    def _infer_victim_actions(features: List[SemanticFeature], text: str) -> List[str]:
        actions = []
        text_lower = text.lower()
        
        # Mapping expected behaviors
        if "log in" in text_lower or "signin" in text_lower or "portal" in text_lower:
            actions.append("Log in")
        if "password" in text_lower or "credentials" in text_lower:
            actions.append("Enter password")
        if any(kw in text_lower for kw in ["otp", "passcode", "one-time", "code"]):
            actions.append("Enter OTP")
        if "mfa" in text_lower or "approve push" in text_lower:
            actions.append("Approve MFA")
        if "grant" in text_lower or "permissions" in text_lower or "oauth" in text_lower:
            actions.append("Approve OAuth")
        if "transfer" in text_lower or "wire" in text_lower or "send money" in text_lower:
            actions.append("Transfer money")
        if "routing" in text_lower or "bank details" in text_lower or "direct deposit" in text_lower:
            actions.append("Update banking information")
        if "qr" in text_lower or "scan" in text_lower:
            actions.append("Scan QR code")
        if "payroll" in text_lower or "salary" in text_lower:
            actions.append("Update payroll")
        if "gift card" in text_lower or "amazon gift" in text_lower:
            actions.append("Purchase gift cards")
            
        return list(set(actions))

    @staticmethod
    def _infer_soc_eng(features: List[SemanticFeature], text: str) -> List[str]:
        techniques = []
        text_lower = text.lower()
        
        # Check Urgency
        if any(f.value == "urgency_indicator" for f in features) or any(f.value == "deadline_indicator" for f in features):
            techniques.append("Urgency")
            
        # Check Authority
        if any(f.value == "impersonation_target" for f in features) or "police" in text_lower or "irs" in text_lower:
            techniques.append("Authority")
            
        # Check Fear/Loss avoidance
        if "suspend" in text_lower or "terminate" in text_lower or "arrest" in text_lower or "leak" in text_lower:
            techniques.append("Fear")
            techniques.append("Loss avoidance")
            
        # Check Greed/Reward
        if "won" in text_lower or "lottery" in text_lower or "cash bonus" in text_lower or "free gift" in text_lower:
            techniques.append("Greed")
            techniques.append("Reward")
            
        # Default fallback
        if len(techniques) > 0:
            techniques.append("Pretexting")
            
        return list(set(techniques))

    @staticmethod
    def _build_document_graph(
        features: List[SemanticFeature],
        intents: List[str],
        victim_actions: List[str],
        soc_eng: List[str]
    ) -> DocumentGraph:
        """
        Creates semantic nodes and links inside the elements_map of a Pydantic DocumentGraph.
        """
        nodes = []
        edges = []
        
        # Create core actors
        nodes.append({"id": "victim_node", "type": "Victim", "label": "Email Recipient"})
        nodes.append({"id": "attacker_node", "type": "Attacker", "label": "External Sender"})
        
        # Add threat techniques
        for idx, intent in enumerate(intents):
            node_id = f"intent_{idx}"
            nodes.append({"id": node_id, "type": "Threat Technique", "label": intent})
            edges.append({"source": "attacker_node", "target": node_id, "relationship": "deploys"})
            edges.append({"source": node_id, "target": "victim_node", "relationship": "targets"})
            
        # Add victim actions
        for idx, action in enumerate(victim_actions):
            node_id = f"action_{idx}"
            nodes.append({"id": node_id, "type": "Victim Action", "label": action})
            edges.append({"source": "victim_node", "target": node_id, "relationship": "requested_to"})
            
        # Add psychological tactics
        for idx, tactic in enumerate(soc_eng):
            node_id = f"tactic_{idx}"
            nodes.append({"id": node_id, "type": "Psychological Technique", "label": tactic})
            # Link tactics to attacker
            edges.append({"source": "attacker_node", "target": node_id, "relationship": "exploits"})
            
        return DocumentGraph(
            parent_map={},
            sibling_map={},
            by_tag_map={},
            elements_map={
                "semantic_nodes": nodes,
                "semantic_edges": edges
            },
            brand_association_map={}
        )
