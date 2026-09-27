from pathlib import Path
from typing import List, Dict, Any
from .score import derive_scores

def render_report(run_id: str, results: List[Dict[str, Any]], output_dir: Path) -> None:
    """Renders a reproducible markdown report similar to Aegis report.ts"""
    
    # Calculate global confusion matrix
    tp = fp = tn = fn = 0
    attacks = 0
    attack_successes = 0
    
    for r in results:
        is_attack = r.get("attack", False)
        blocked = r.get("blocked_any", False)
        
        if is_attack:
            attacks += 1
            if blocked:
                tp += 1
            else:
                fn += 1
            if r.get("attack_success", False):
                attack_successes += 1
        else:
            if blocked:
                fp += 1
            else:
                tn += 1

    scores = derive_scores(tp, fp, tn, fn)
    asr = attack_successes / attacks if attacks else 0.0
    
    lines = [
        f"# PAFA Harness Run `{run_id}`",
        "",
        f"Total runs: {len(results)}",
        "",
        "## Headline Metrics",
        "| Metric | Value |",
        "|---|---|",
        f"| **Attack Success Rate (ASR)** | **{asr:.1%}** |",
        f"| **False-Positive Rate (FPR)** | **{scores['fpr']:.1%}** |",
        f"| Block rate (Recall) | {scores['block_rate']:.1%} |",
        f"| Precision | {scores['precision']:.3f} |",
        f"| F1 Score | {scores['f1']:.3f} |",
        f"| MCC | {scores['mcc']:.3f} |",
        "",
        "## Confusion Matrix",
        "| | Guard Blocked | Guard Allowed |",
        "|---|---|---|",
        f"| **Attack** (expect block) | {tp} (TP) | {fn} (FN) |",
        f"| **Benign** (expect allow) | {fp} (FP) | {tn} (TN) |",
    ]
    
    report_path = output_dir / f"report_{run_id}.md"
    report_path.write_text("\n".join(lines))
    print(f"Wrote full reproducible report to {report_path}")
