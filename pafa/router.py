"""
Router module from Aegis.
Two-tier escalation: rules-tier score -> threshold band -> LLM-tier judge only when necessary.
"""

def combine_scores(scores: list[float]) -> float:
    """Noisy-OR combination of probabilistic scores."""
    prob_clean = 1.0
    for s in scores:
        prob_clean *= (1.0 - s)
    return 1.0 - prob_clean

def route_decision(rules_score: float, low_threshold: float, high_threshold: float) -> str:
    """
    Decides whether to allow, block, or escalate to LLM judge based on thresholds.
    """
    if rules_score <= low_threshold:
        return "allow"
    elif rules_score >= high_threshold:
        return "block"
    else:
        return "escalate"
