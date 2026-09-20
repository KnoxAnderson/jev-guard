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

## Benchmarking against public datasets

`benchmark.py` scores `guard()` against labeled public prompt-injection datasets and
reports precision/recall/F1/false-positive-rate, plus a threshold sweep for tuning.

```bash
python benchmark.py deepset             # direct injection/jailbreak, 30 sampled cases
python benchmark.py bipia --n 60        # indirect injection, 60 sampled cases
python benchmark.py deepset bipia --policy permissive
```

- **`deepset`** — [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections),
  662 labeled direct injection/jailbreak attempts. No extra setup needed.
- **`bipia`** — [MAlmasabi/Indirect-Prompt-Injection-BIPIA-GPT](https://huggingface.co/datasets/MAlmasabi/Indirect-Prompt-Injection-BIPIA-GPT),
  70k examples of indirect injection embedded in external content (a derived
  repackaging of Microsoft's BIPIA benchmark, not the original). This dataset is
  gated behind a self-serve consent click (not manual review): log into a free HF
  account, accept the terms on the dataset page, generate a read-only token at
  [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens), and add
  it as `HF_TOKEN` in `.env`.

`--n` controls how many cases are sampled per dataset — each case costs one Jev call,
so keep it modest while iterating. Results are cached in `bench_cache.json` (gitignored)
keyed by model + input, so re-running after only changing `policy.py` thresholds is free;
delete that file (or edit `hazards.py`) to force fresh calls.

Known gap this benchmark surfaced: Jev is English-primary (per TypeSafe's own docs) and
misses persona/roleplay-framed jailbreaks that don't literally ask the model to "ignore
instructions" — see `hazards.py`'s `jailbreak` criteria if you need to broaden that.
