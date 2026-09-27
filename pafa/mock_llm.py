"""
Deterministic mock LLM provider from Aegis.
Allows testing the framework offline without API keys.
"""

class MockLLM:
    def __init__(self, predefined_responses=None):
        self.predefined_responses = predefined_responses or {}
        
    def call(self, prompt: str) -> str:
        """Mock LLM generation based on predefined rules."""
        prompt_lower = prompt.lower()
        if "attack" in prompt_lower or "malicious" in prompt_lower:
            return "YES"
        return "NO"
