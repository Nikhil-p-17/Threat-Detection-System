from dataclasses import dataclass

LEVELS = ((0, "SAFE"), (20, "LOW"), (45, "MEDIUM"), (70, "HIGH"), (90, "CRITICAL"))

@dataclass
class Finding:
    name: str
    detail: str
    weight: int
    status: str = "warning"


def level_for(score: int) -> str:
    label = "SAFE"
    for threshold, name in LEVELS:
        if score >= threshold:
            label = name
    return label


def calculate_score(findings: list[Finding], cap: int = 100) -> int:
    # Weighted indicators are additive, capped at 100.
    return min(cap, max(0, sum(f.weight for f in findings)))
