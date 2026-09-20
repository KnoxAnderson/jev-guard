# jev-guard

A safety-and-security guardrail classifier built on TypeSafe's Jev model, called
through OpenRouter's Decisions API (`~typesafe/jev-latest`).

Screens a message with a battery of typed questions in one call:

- **Safety hazards:** jailbreak attempts, requests for help with harm/illegal activity,
  self-harm signals, medical-advice overreach (and, on the output side, whether the
  reply actually broke policy).
- **Security hazards:** prompt injection (hidden instructions aimed at an AI/agent
  rather than a human), secrets/credential exfiltration, requests for malware or
  exploit code without a stated authorization context.
- **Severity:** a `Score` question rating how much harm compliance would do, which can
  escalate a `review` into a `block`.

Your code owns the decision: `jev_guard/policy.py` maps each hazard to an action
(`block` / `review` / `support` / `pass`) and holds the probability thresholds. Nothing
here is enforced by the model — it just hands back calibrated probabilities.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then paste in your OPENROUTER_API_KEY
```

Get a key from your [OpenRouter dashboard](https://openrouter.ai/keys).

## Run it

```bash
python cli.py                      # screen every sample prompt/reply, strict policy
python cli.py --policy permissive  # same messages, looser thresholds
python cli.py --show dan           # full hazard breakdown for one message
```

## Use it in your own code

```python
from jev_guard import JevClient, guard

client = JevClient()
result = guard(client, user_message, side="input")
# result = {"action": "block"|"review"|"support"|"pass", "nouls": {...}, "severity": 1.2}
```

Call `guard(..., side="input")` on the way into your LLM and `guard(..., side="output")`
on the way out — an ordinary-looking prompt can still produce a harmful reply.

## Tuning

Edit `jev_guard/hazards.py` to add/remove hazard questions, and `jev_guard/policy.py`
to change which action each hazard triggers and where the probability thresholds sit.
Tune thresholds against labeled examples of your own traffic, not against this repo's
small sample set.
