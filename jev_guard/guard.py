"""High-level guard() entry point: screen one message and route it.

Each message goes through two independent passes:

- **Structural** (`detectors.py`): deterministic, catches obfuscation and exfiltration
  channels that read as ordinary text to a classifier. Also de-obfuscates the message
  so the semantic pass scores the real payload rather than the disguised one.
- **Semantic** (Jev): calibrated probabilities for intent-level hazards that no regex
  can express.

Either pass can escalate on its own, so an attack has to evade both.
"""

from typing import Any, Literal

from . import detectors
from .client import JevClient
from .hazards import BATTERIES
from .policy import DEFAULT_POLICY, POLICIES, route

Side = Literal["input", "output"]


def screen(client: JevClient, text: str, side: Side) -> dict[str, Any]:
    """Run both passes over one message and return the raw assessment."""
    normalized, structural = detectors.scan(text)
    battery = BATTERIES[side]
    answers = client.ask(state=normalized, questions=battery)
    return {
        "nouls": {qid: answers[qid]["noul"] for qid in battery if qid != "severity"},
        "severity": answers["severity"]["score"],
        "structural": [{"name": hit.name, "detail": hit.detail} for hit in structural],
        "normalized": normalized if normalized != text else None,
    }


def guard(client: JevClient, text: str, side: Side, policy_name: str = DEFAULT_POLICY) -> dict[str, Any]:
    """Screen a message and route it under a named application policy.

    Returns the action alongside the full assessment, so callers can log why a
    message was treated the way it was.
    """
    result = screen(client, text, side)
    action = route(
        result["nouls"],
        result["severity"],
        POLICIES[policy_name],
        structural=result["structural"],
    )
    return {"action": action, **result}
