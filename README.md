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
| Multi-turn / staged attacks | Per-message only | Conversation-level battery |
| Per-hazard thresholds | Per-category confidence | Per-hazard, tunable in `policy.py` |
| Decision logic | Managed service | Yours, in readable code |

### Multi-turn screening

Per-message screening structurally cannot see an attack split across turns — a persona
established early and cashed in later, or a fake "system" message planted upstream and
invoked as authorization downstream. `guard_conversation()` passes the turn array to Jev
as structured state and scores the conversation as one object.

On the staged attack in `samples/conversations.json` (a novel-research framing that
turns into a synthesis request only at the last turn), per-message screening of the
final turn returns `review` at jailbreak=0.56 — the attack partially lands.
Conversation-level screening returns `block` at staged_attack=0.82, while a benign
novelist conversation with the same opening scores 0.07 and passes.

```bash
python cli.py --conversations
```

```python
from jev_guard import JevClient, guard_conversation

result = guard_conversation(JevClient(), turns)  # [{"role": ..., "content": ...}, ...]
```

Model Armor wins on threat-intel URL reputation (no local heuristic replaces a live
feed) and multimodal screening (Jev is text-only). jev-guard wins on exfiltration-channel
detection, obfuscation normalization, and the fact that every threshold and routing
decision is code you own rather than a managed policy.

Measured on a 20-case sample of `deepset/prompt-injections`: precision 1.00, recall
0.83, F1 0.91, FPR 0.00.

## Hazards

Screens a message with a battery of typed questions in one call:

- **Safety:** jailbreak (including persona/fictional-frame workarounds), harmful or
  illegal requests, self-harm signals, medical-advice overreach, `hate_harassment`,
  `sexual_minors`.
- **Security:** prompt injection, secrets/credential exfiltration, `exfiltration_setup`
  and `exfiltration_channel` (outbound URLs carrying user data), `malicious_url`,
  `sensitive_data`, unauthorized malware/exploit requests.
- **Cross-turn:** `staged_attack`, `context_poisoning`, `escalation` — only via
  `guard_conversation()`.
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
python cli.py --conversations      # multi-turn staged-attack screening
python ablation.py                 # what de-obfuscation is worth, raw vs normalized
pytest tests/                      # offline detector tests, no API key needed
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

### Known gaps

- **Non-English recall.** Jev is English-primary per TypeSafe's docs, and German-language
  injections were the residual misses in benchmarking. If you expect multilingual
  traffic, measure it before trusting these thresholds.
- **Obfuscation normalization adds less than expected.** `ablation.py` measures it: Jev
  already scores homoglyph and base64 payloads at 0.99 raw, so normalization only moved
  Unicode tag smuggling (+0.09). The detectors earn their place on exfiltration channels
  and secrets, and as a deterministic floor — not by rescuing a weak classifier.
- **No URL reputation.** Structural heuristics only; a freshly-registered malicious
  domain with an ordinary TLD looks clean until the semantic pass catches the context.
- **Benchmarks are a floor, not a ceiling.** Per
  [HiddenLayer's analysis](https://hiddenlayer.com/innovation-hub/evaluating-prompt-injection-datasets/),
  public datasets have noisy benign labels and don't transfer to domain-specific traffic.
