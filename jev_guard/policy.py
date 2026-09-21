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
    "exfiltration_setup": "block",
    "exfiltration_channel": "block",
    "hate_harassment": "block",
    "sexual_minors": "block",
    "malicious_url": "block",
    "sensitive_data": "review",
    "malicious_code": "review",
    "provided_exploit": "review",
    "medical_advice": "review",
    "self_harm": "support",
    "staged_attack": "block",
    "context_poisoning": "block",
    "escalation": "review",
}

# Per-hazard thresholds, for the cases where a uniform bar is the wrong call. A
# category whose worst case is catastrophic and whose false positives are cheap to
# absorb should fire on much weaker evidence than one where over-blocking has a real
# cost to the user.
HAZARD_THRESHOLD = {
    "sexual_minors": {"review": 0.05, "action": 0.15},
    "self_harm": {"review": 0.30, "action": 0.50},  # routes to support, not a refusal
    "leaked_secrets": {"review": 0.20, "action": 0.50},
    "exfiltration_channel": {"review": 0.20, "action": 0.50},
}

# Structural detector hits carry their own action, independent of any probability.
# These fire on syntax, so an attacker cannot argue the model out of them — which is
# the point: they cover exactly the obfuscation and exfil-channel cases that evade
# intent classifiers.
STRUCTURAL_ACTION = {
    "invisible_unicode": "block",  # no legitimate message hides text from the reader
    "encoded_payload": "block",  # base64 that decodes to instructions is never incidental
    "exfiltration_channel": "block",
    "homoglyphs": "review",  # occasionally legitimate in multilingual text
    "unicode_variants": "review",
    "sensitive_data": "review",
    "risky_url": "review",  # suspicious shape, not proof — a human should look
}

PRECEDENCE = ["support", "block", "review", "pass"]  # highest precedence wins

POLICIES: dict[str, dict[str, float]] = {
    "strict": {"review_threshold": 0.35, "action_threshold": 0.70, "severity_block": 2.0},
    "permissive": {"review_threshold": 0.35, "action_threshold": 0.85, "severity_block": 2.0},
    # Tuned against 2,378 cached cases. Raising review_threshold is what actually moves
    # the false-positive rate — action_threshold barely matters, because nearly all
    # false positives sit in the review band rather than the action band.
    "low_fp": {"review_threshold": 0.60, "action_threshold": 0.85, "severity_block": 2.5},
}
DEFAULT_POLICY = "low_fp"


def route(
    nouls: dict[str, float],
    severity: float,
    policy: dict[str, float],
    structural: list[dict[str, Any]] | None = None,
) -> str:
    """Turn one message's assessment into one policy-specific action."""
    triggered = []
    for hazard, probability in nouls.items():
        override = HAZARD_THRESHOLD.get(hazard)
        action_at = override["action"] if override else policy["action_threshold"]
        review_at = override["review"] if override else policy["review_threshold"]
        if probability >= action_at:
            triggered.append(HAZARD_ACTION[hazard])
        elif probability >= review_at:
            triggered.append("review")
    if severity >= policy["severity_block"]:
        triggered = ["block" if action == "review" else action for action in triggered]
    # Structural hits are added after the severity rewrite so they keep their own
    # action regardless of how harmless the model judged the message to be.
    for hit in structural or []:
        triggered.append(STRUCTURAL_ACTION.get(hit["name"], "review"))
    return next((action for action in PRECEDENCE if action in triggered), "pass")
