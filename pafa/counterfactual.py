from .pipeline import run_once
from .attribution import analyze
import copy

def run_counterfactual_replay(
    user_request: str, 
    user_email: str, 
    guardrail: bool,
    attacker_email: str = "attacker@evil.com"
) -> dict:
    """
    Counterfactual replay module (Paper Eq. 3).
    If a failure/attack occurred, re-run the trace with the tainted content 
    replaced by its benign twin (i.e. attack=False). 
    If the failure stops, it confirms the attack was the causal factor.
    """
    
    # 1. First run the factual trace (with attack)
    result_text_f, log_f, blocked_any_f, task_outputs_f = run_once(
        user_request, user_email, attack=True, guardrail=guardrail
    )
    metrics_f = analyze(log_f, task_outputs_f, blocked_any_f, user_email, attacker_email)
    
    factual_attack_success = metrics_f.get("attack_success", False)
    factual_violation = metrics_f.get("violation_logged", False)
    
    # 2. Run the counterfactual trace (without attack, benign twin)
    result_text_cf, log_cf, blocked_any_cf, task_outputs_cf = run_once(
        user_request, user_email, attack=False, guardrail=guardrail
    )
    metrics_cf = analyze(log_cf, task_outputs_cf, blocked_any_cf, user_email, attacker_email)
    
    cf_attack_success = metrics_cf.get("attack_success", False)
    cf_violation = metrics_cf.get("violation_logged", False)
    
    # 3. Compute causal confirmation
    # If it succeeded in factual but failed in counterfactual, the injected content caused it.
    causally_confirmed = factual_attack_success and not cf_attack_success
    
    return {
        "factual_metrics": metrics_f,
        "counterfactual_metrics": metrics_cf,
        "causally_confirmed": causally_confirmed,
        "causal_difference_noted": factual_violation != cf_violation
    }
