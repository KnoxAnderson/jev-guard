"""High-level guard() entry point: screen one message and route it."""

from typing import Any, Literal

from .client import JevClient
from .hazards import BATTERIES
from .policy import DEFAULT_POLICY, POLICIES, route

Side = Literal["input", "output"]


def screen(client: JevClient, text: str, side: Side) -> dict[str, Any]:
    """Send one message and its battery in a single call; return the raw assessment."""
    battery = BATTERIES[side]
    answers = client.ask(state=text, questions=battery)
    return {
        "nouls": {qid: answers[qid]["noul"] for qid in battery if qid != "severity"},
        "severity": answers["severity"]["score"],
    }


def guard(client: JevClient, text: str, side: Side, policy_name: str = DEFAULT_POLICY) -> dict[str, Any]:
    """Screen a message and route it under a named application policy.

    Returns {"action": ..., "nouls": {...}, "severity": ...} so callers can log the
    full assessment alongside the decision.
    """
    result = screen(client, text, side)
    action = route(result["nouls"], result["severity"], POLICIES[policy_name])
    return {"action": action, **result}
