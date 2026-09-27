import enum
from dataclasses import dataclass, field
from typing import List, Optional

class Trust(enum.Enum):
    SYSTEM = "system"
    USER = "user"
    TOOL = "tool"
    RETRIEVED = "retrieved"

def is_untrusted(trust: Trust) -> bool:
    return trust in (Trust.TOOL, Trust.RETRIEVED)

def most_restrictive_trust(trusts: List[Trust]) -> Trust:
    if not trusts:
        return Trust.SYSTEM
    if any(is_untrusted(t) for t in trusts):
        # Prefer RETRIEVED or TOOL to mark it as untrusted.
        for t in trusts:
            if is_untrusted(t):
                return t
    return Trust.USER if Trust.USER in trusts else Trust.SYSTEM

@dataclass
class ProvenanceRecord:
    source_id: str
    trust: Trust
    agent: str
    step: int
    parent_ids: List[str] = field(default_factory=list)
    text_content: Optional[str] = None # Helpful for extracting fragments

    def is_tainted(self) -> bool:
        return is_untrusted(self.trust)
