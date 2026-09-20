#!/usr/bin/env python3
"""Measure what de-obfuscating normalization is actually worth.

Sends each evasion sample to Jev twice — once raw, once normalized by detectors.py —
and reports the top hazard probability for each. The gap is the margin a pure-ML
guardrail (which scores the raw, disguised text) gives up to character-level evasion.

    python ablation.py
"""

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from jev_guard import JevClient, detectors
from jev_guard.hazards import BATTERIES

EVASION_SAMPLES = ["unicode_smuggled", "homoglyph_override", "base64_injection"]


def load_messages(path: Path) -> dict[str, str]:
    messages = {}
    for record in path.read_text().split("\n=====\n"):
        record = record.strip("\n")
        if not record:
            continue
        header, _, body = record.partition("\n")
        messages[header.removeprefix("id: ").strip()] = body.strip("\n")
    return messages


def top_score(client: JevClient, text: str) -> tuple[str, float]:
    battery = BATTERIES["input"]
    answers = client.ask(state=text, questions=battery)
    nouls = {qid: answers[qid]["noul"] for qid in battery if qid != "severity"}
    return max(nouls.items(), key=lambda kv: kv[1])


def main() -> None:
    load_dotenv()
    if "OPENROUTER_API_KEY" not in os.environ:
        sys.exit("Set OPENROUTER_API_KEY (see .env.example) before running this.")

    client = JevClient()
    prompts = load_messages(Path(__file__).parent / "samples" / "prompts.txt")

    print(f"{'sample':<22}{'raw':<22}{'normalized':<22}{'delta':>7}")
    print("-" * 73)
    for name in EVASION_SAMPLES:
        text = prompts[name]
        normalized, _ = detectors.normalize(text)
        raw_hazard, raw_p = top_score(client, text)
        norm_hazard, norm_p = top_score(client, normalized)
        print(
            f"{name:<22}{raw_hazard}={raw_p:<15.2f}{norm_hazard}={norm_p:<15.2f}"
            f"{norm_p - raw_p:>+7.2f}"
        )


if __name__ == "__main__":
    main()
