import re
import json
import enum
from typing import List, Dict, Any, Optional
from pafa.provenance import ProvenanceRecord, is_untrusted

class PolicyTier(str, enum.Enum):
    PERMISSIVE = "permissive"
    BALANCED = "balanced"
    STRICT = "strict"

class PolicyConfig:
    def __init__(self, tier: PolicyTier):
        self.tier = tier
        if tier == PolicyTier.PERMISSIVE:
            self.high_threshold = 0.9
        elif tier == PolicyTier.BALANCED:
            self.high_threshold = 0.7
        else: # STRICT
            self.high_threshold = 0.5
            
        self.allowed_tools: List[str] = [] # By default deny all, configure per task

def extract_tainted_fragments(records: List[ProvenanceRecord]) -> set[str]:
    """
    Distinctive substrings lifted from untrusted parts, for taint matching.
    Ported from taintedFragments in tool-call-policy.ts
    """
    fragments = set()
    for record in records:
        if not record.is_tainted() or not record.text_content:
            continue
            
        text = record.text_content
        # Sentence-ish and token-ish fragments long enough to be distinctive.
        # Split by punctuation
        parts = re.split(r'[\n.!?;]+', text)
        for part in parts:
            part = part.strip().lower()
            if len(part) >= 16:
                fragments.add(part)
                
        # Regex for URLs, emails, special tokens
        tokens = re.findall(r'\b[\w@:/.+-]{12,}\b', text)
        for tok in tokens:
            fragments.add(tok.lower())
            
    return fragments

def check_tool_call(
    tool_name: str, 
    tool_args_raw: str, 
    history_records: List[ProvenanceRecord], 
    policy: PolicyConfig
) -> Dict[str, Any]:
    """
    Validates a requested tool call against the policy.
    Checks if arguments contain text originating in tainted content.
    Returns a dictionary with result and explanation.
    """
    if tool_name not in policy.allowed_tools:
        return {
            "triggered": True,
            "severity": "critical",
            "score": 0.95,
            "explanation": f"Tool '{tool_name}' is not on the allowlist.",
            "labels": ["tool:not-allowlisted"]
        }
        
    fragments = extract_tainted_fragments(history_records)
    args_lower = tool_args_raw.lower()
    
    tainted_matches = [f for f in fragments if len(f) >= 16 and f in args_lower]
    
    if tainted_matches:
        return {
            "triggered": True,
            "severity": "critical",
            "score": 0.9,
            "explanation": f"Tool '{tool_name}' arguments contain {len(tainted_matches)} fragment(s) lifted from untrusted content.",
            "labels": ["tool:tainted-arguments"],
            "tainted_matches": tainted_matches
        }
        
    return {
        "triggered": False,
        "explanation": "Tool call is allowed and free of tainted arguments."
    }
