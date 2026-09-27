"""
Regex/heuristic patterns catching known prompt-injection signs.
Reference from Aegis injection-heuristics.
"""

import re
from typing import List, Dict, Any

ATTACK_PATTERNS = {
    "instruction_override": [
        re.compile(r"(?i)\b(ignore|disregard|forget|discard|override|bypass)\b[^.\n]{0,40}\b(all\s+)?(the\s+)?(above|previous|prior|earlier|preceding|foregoing|initial|original|system)\b[^.\n]{0,30}\b(instruction|prompt|direction|rule|guideline|message|context|constraint)s?\b"),
        re.compile(r"(?i)\b(ignore|disregard|forget)\b\s+(everything|all)\b[^.\n]{0,30}\b(before|above|prior|so\s+far)\b"),
        re.compile(r"(?i)\bnew\s+(instruction|directive|task|system\s+prompt)s?\s*:"),
        re.compile(r"(?i)\byour\s+(previous|prior|earlier|original)\s+instructions?\s+(are|is|were)\s+(now\s+)?(void|invalid|cancelled|canceled|revoked|obsolete|superseded)\b"),
        re.compile(r"(?i)\bthis\s+(message|prompt)\s+(overrides|supersedes|replaces)\b")
    ],
    "role_hijack": [
        re.compile(r"(?i)\byou\s+are\s+now\s+(a|an|the)\b[^.\n]{0,60}"),
        re.compile(r"(?i)\bfrom\s+now\s+on[, ]+you\s+(are|will|must|shall)\b"),
        re.compile(r"(?i)\b(enter|enable|activate|switch\s+to)\s+(developer|debug|god|admin|root|sudo|unrestricted|jailbreak|dan)\s*mode\b"),
        re.compile(r"(?i)\bdeveloper\s+mode\s+(enabled|on|activated)\b"),
        re.compile(r"(?i)\bDAN\b(?=[^a-z]|$)[^.\n]{0,40}\b(mode|prompt|jailbreak|do\s+anything)\b"),
        re.compile(r"(?i)\bdo\s+anything\s+now\b"),
        re.compile(r"(?i)\bpretend\s+(to\s+be|you\s+are|that\s+you\s+are)\b[^.\n]{0,60}\b(no|without|free\s+of|unbound|unrestricted|unfiltered)\b"),
        re.compile(r"(?i)\bact\s+as\s+(if\s+you\s+(have|had)\s+no|an?\s+(unfiltered|unrestricted|uncensored|amoral))\b"),
        re.compile(r"(?i)\byou\s+have\s+no\s+(restrictions|filters|guidelines|rules|limitations|policies)\b"),
        re.compile(r"(?i)\bsimulate\s+(a|an)\s+(unrestricted|uncensored|unfiltered)\b")
    ],
    "prompt_extraction": [
        re.compile(r"(?i)\b(repeat|print|output|show|reveal|display|echo|recite|reproduce|dump)\b[^.\n]{0,40}\b(everything|all\s+text|the\s+text)\b[^.\n]{0,20}\babove\b"),
        re.compile(r"(?i)\b(what|show|print|reveal|tell\s+me|give\s+me|repeat)\b[^.\n]{0,30}\byour\s+(system\s+prompt|initial\s+prompt|original\s+prompt|instructions|directives|system\s+message|configuration|prompt)\b"),
        re.compile(r"(?i)\b(system\s+prompt|initial\s+instructions|original\s+instructions)\b[^.\n]{0,20}\b(verbatim|word\s+for\s+word|exactly|in\s+full)\b"),
        re.compile(r"(?i)\brepeat\s+the\s+words?\s+above\s+starting\s+with\b"),
        re.compile(r"(?i)\boutput\s+(the\s+)?(initialization|initial)\s+(text|prompt|message)\b"),
        re.compile(r"(?i)\bwhat\s+(were|are)\s+you\s+(told|instructed|programmed)\s+(to\s+do|not\s+to)\b"),
        re.compile(r"(?i)\bbegin\s+your\s+(reply|response|answer)\s+with\s+[\"“]?\s*(you\s+are|system)\b")
    ],
    "refusal_suppression": [
        re.compile(r"(?i)\b(do\s+not|don't|never)\s+(refuse|decline|apologize|say\s+(no|you\s+can'?t)|warn|caution|lecture)\b"),
        re.compile(r"(?i)\bnever\s+say\s+(you\s+)?(can'?t|cannot|won'?t|unable)\b"),
        re.compile(r"(?i)\b(without|no)\s+(any\s+)?(warnings?|disclaimers?|caveats?|moralizing|ethical\s+considerations?)\b"),
        re.compile(r"(?i)\bdo\s+not\s+mention\s+(your\s+)?(guidelines|policies|restrictions|rules|training)\b"),
        re.compile(r"(?i)\byou\s+must\s+(comply|obey|answer)\b[^.\n]{0,30}\b(regardless|no\s+matter|whatever)\b"),
        re.compile(r"(?i)\bstart\s+your\s+(response|reply|answer)\s+with\s+[\"“]?(sure|certainly|absolutely|of\s+course)\b")
    ]
}

META_SIGNALS = [
    re.compile(r"(?i)\b(prompt\s+injection|jailbreak(ing)?|adversarial\s+prompt|red[- ]team(ing)?|attack\s+(vector|pattern|technique|surface))\b"),
    re.compile(r"(?i)\b(for\s+example|e\.g\.|such\s+as|an?\s+example\s+of|sample\s+payload|test\s+case|illustrat(es?|ing)|demonstrat(es?|ing))\b"),
    re.compile(r"(?i)\b(how\s+(do|can|would|should)\s+(i|we|you|one)\b|what\s+is\b|why\s+(does|do|is)\b|explain\b|describe\b)"),
    re.compile(r"(?i)\b(defend|defence|defense|mitigat(e|ion)|protect|prevent|detect(ion)?|guard(rail)?s?|filter(ing)?|sanitiz)"),
    re.compile(r"(?i)\b(paper|blog\s+post|article|documentation|research|study|owasp|cwe|cve|benchmark|dataset)\b"),
    re.compile(r"(?i)\b(my\s+(app|application|system|chatbot|agent|service)|our\s+(app|application|system|product))\b")
]

def detect_attack_heuristics(text: str) -> Dict[str, Any]:
    """Returns detected attack families and a dampened score considering meta signals."""
    triggered = []
    
    for family, patterns in ATTACK_PATTERNS.items():
        if any(p.search(text) for p in patterns):
            triggered.append(family)
            
    meta_hits = sum(1 for p in META_SIGNALS if p.search(text))
    
    return {
        "families": triggered,
        "meta_hits": meta_hits,
        "dampened": meta_hits > 0
    }
