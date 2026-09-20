# jev-guard

A safety-and-security guardrail classifier built on TypeSafe's Jev model, called
through OpenRouter's Decisions API (`~typesafe/jev-latest`).

## How it works

Every message goes through two independent passes, and either can escalate on its
own — so an attack has to evade both:

1. **Structural** (`jev_guard/detectors.py`) — deterministic, regex/parser-level. It
   de-obfuscates the message *before* the semantic pass (Unicode tag smuggling,
   zero-width characters, Cyrillic/Greek homoglyphs, NFKC variants, base64 payloads
   that decode to instructions) and flags things that are attacker-shaped regardless
   of intent: exfiltration channels, credentials/PII, and risky URLs.
2. **Semantic** (Jev) — calibrated probabilities for intent-level hazards no regex can
   express, evaluated in a single API call.

The split matters because each pass covers the other's blind spot. Character-level
obfuscation evades ML classifiers while the target LLM still reads the payload fine
([arXiv:2504.11168](https://arxiv.org/pdf/2504.11168)); conversely, the dominant
real-world exfiltration vector — a markdown image whose URL carries stolen data in a
query parameter, auto-fetched by the chat UI with no user interaction — is *syntax*,
and an intent classifier reads straight past it.

### Compared to Google Cloud Model Armor

| Capability | Model Armor | jev-guard |
|---|---|---|
| Prompt injection / jailbreak | ML classifier | Semantic + structural, de-obfuscated input |
| Sensitive data | Cloud DLP integration | Regex + Luhn-checked cards, keys, JWTs, SSNs |
| Malicious URLs | Threat-intel lookup | Structural heuristics (punycode, embedded creds, shorteners, high-abuse TLDs) + semantic |
| RAI categories | Built-in filters | `hate_harassment`, `sexual_minors` hazards |
| Exfiltration channels | — | Markdown/HTML image + link URL analysis |
| Obfuscation normalization | — | Unicode tags, zero-width, homoglyphs, base64 |
| Per-hazard thresholds | Per-category confidence | Per-hazard, tunable in `policy.py` |
| Decision logic | Managed service | Yours, in readable code |

Model Armor wins on threat-intel URL reputation (no local heuristic replaces a live
feed) and multimodal screening (Jev is text-only). jev-guard wins on exfiltration-channel
detection, obfuscation normalization, and the fact that every threshold and routing
decision is code you own rather than a managed policy.

Measured on a 20-case sample of `deepset/prompt-injections`: precision 1.00, recall
0.83, F1 0.91, FPR 0.00.

## Hazards

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
