"""Turn a hazard assessment into a routing decision. Thresholds live here, in code you
can read and tune from labeled examples of your own traffic, not in a system prompt."""

from typing import Any

# A high-probability hazard triggers the product action below.
HAZARD_ACTION = {
    "jailbreak": "block",
    "broke_policy": "block",
    "harmful_request": "block",
    "prompt_injection": "block",
    "secrets_exfiltration": "block",
    "leaked_secrets": "block",
    "malicious_code": "review",
    "provided_exploit": "review",
    "medical_advice": "review",
    "self_harm": "support",
}
PRECEDENCE = ["support", "block", "review", "pass"]  # highest precedence wins

POLICIES: dict[str, dict[str, float]] = {
    "strict": {"review_threshold": 0.35, "action_threshold": 0.70, "severity_block": 2.0},
    "permissive": {"review_threshold": 0.35, "action_threshold": 0.85, "severity_block": 2.0},
}
DEFAULT_POLICY = "strict"


def route(nouls: dict[str, float], severity: float, policy: dict[str, float]) -> str:
    """Turn one message's hazard assessment into one policy-specific action."""
    triggered = []
    for hazard, probability in nouls.items():
        if probability >= policy["action_threshold"]:
            triggered.append(HAZARD_ACTION[hazard])
        elif probability >= policy["review_threshold"]:
            triggered.append("review")
    if severity >= policy["severity_block"]:
        triggered = ["block" if action == "review" else action for action in triggered]
    return next((action for action in PRECEDENCE if action in triggered), "pass")
