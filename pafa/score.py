import math
import random
from typing import List, Dict, Any, Tuple

def derive_scores(tp: int, fp: int, tn: int, fn: int) -> Dict[str, float]:
    """Calculate standard classification metrics."""
    div = lambda a, b: a / b if b != 0 else 0.0
    
    precision = div(tp, tp + fp)
    recall = div(tp, tp + fn)
    f1 = div(2 * precision * recall, precision + recall)
    
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn) - (fp * fn)) / denom if denom != 0 else 0.0
    
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "mcc": mcc,
        "accuracy": div(tp + tn, tp + tn + fp + fn),
        "fpr": div(fp, fp + tn),
        "block_rate": div(tp, tp + fn)
    }

def bootstrap(outcomes: List[int], samples: int = 2000, seed: int = 42) -> Dict[str, Any]:
    """Non-parametric bootstrap over a 0/1 outcome vector to calculate 95% CI."""
    n = len(outcomes)
    if n == 0:
        return {"mean": 0, "std": 0, "ci95": (0, 0), "samples": 0}
        
    random.seed(seed)
    means = []
    
    for _ in range(samples):
        sampled = [outcomes[random.randint(0, n - 1)] for _ in range(n)]
        means.append(sum(sampled) / n)
        
    means.sort()
    mean = sum(outcomes) / n
    variance = sum((m - mean) ** 2 for m in means) / len(means)
    
    return {
        "mean": mean,
        "std": math.sqrt(variance),
        "ci95": (means[int(0.025 * len(means))], means[int(0.975 * len(means))]),
        "samples": samples
    }
