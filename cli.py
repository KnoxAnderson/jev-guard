#!/usr/bin/env python3
"""Run the sample messages through the guard() classifier and print the results.

Usage:
    python cli.py                 # run every sample under the default policy
    python cli.py --policy permissive
    python cli.py --show dan      # print the full hazard breakdown for one message id
    python cli.py --show dosage_request --side output   # disambiguate an id used on both sides
    python cli.py --conversations # screen multi-turn conversations for staged attacks
"""

import argparse
import json
import os
import sys
import textwrap
from pathlib import Path

from dotenv import load_dotenv

from jev_guard import DEFAULT_POLICY, POLICIES, JevClient, guard, guard_conversation, route, screen

ICON = {"pass": "  pass  ", "review": " review ", "block": " BLOCK  ", "support": "support "}


def load_messages(path: Path) -> dict[str, str]:
    messages = {}
    for record in path.read_text().split("\n=====\n"):
        record = record.strip("\n")
        if not record:
            continue
        header, _, body = record.partition("\n")
        messages[header.removeprefix("id: ").strip()] = body.strip("\n")
    return messages


def top_hazard(nouls: dict[str, float]) -> tuple[str, float]:
    return max(nouls.items(), key=lambda kv: kv[1])


def run(client: JevClient, messages: dict[str, str], side: str, policy_name: str) -> None:
    for name, text in messages.items():
        result = guard(client, text, side, policy_name)
        hazard, probability = top_hazard(result["nouls"])
        one_line = " ".join(text.split())
        flags = ",".join(sorted({hit["name"] for hit in result["structural"]}))
        evidence = f"[{flags}] " if flags else ""
        print(
            f"[{ICON[result['action']]}] {name:<20} {hazard}={probability:.2f} "
            f"sev={result['severity']:.1f}  {evidence}{one_line[:52]}"
        )


def show(client: JevClient, messages: dict[str, str], side: str, name: str, policy_name: str) -> None:
    text = messages[name]
    policy = POLICIES[policy_name]
    result = screen(client, text, side)
    action = route(result["nouls"], result["severity"], policy)
    print(f"{name} ({side})  ->  {action.upper()}  [policy={policy_name}]")
    quoted = f'"{" ".join(text.split())}"'
    print(textwrap.fill(quoted, width=88, initial_indent="  ", subsequent_indent="  "))
    print(
        f"  review >= {policy['review_threshold']:.2f}, "
        f"action >= {policy['action_threshold']:.2f}, "
        f"severity blocks at {policy['severity_block']:.2f}"
    )
    for hazard, probability in sorted(result["nouls"].items(), key=lambda kv: -kv[1]):
        bar = "#" * round(probability * 24)
        print(f"    {hazard:<22}{probability:.2f}  {bar}".rstrip())
    print(f"    {'severity':<22}{result['severity']:.2f}  (0-3 scale)")
    if result["structural"]:
        print("  structural detectors:")
        for hit in result["structural"]:
            print(f"    {hit['name']:<22}{hit['detail']}")
    if result["normalized"]:
        print(f"  normalized to: {' '.join(result['normalized'].split())[:200]}")


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", default=DEFAULT_POLICY, choices=POLICIES.keys())
    parser.add_argument("--show", help="print the full breakdown for one message id (prompts or replies)")
    parser.add_argument(
        "--conversations",
        action="store_true",
        help="screen samples/conversations.json for multi-turn attacks instead of single messages",
    )
    parser.add_argument(
        "--side",
        choices=["input", "output"],
        help="disambiguate --show when the id appears in both prompts.txt and replies.txt",
    )
    args = parser.parse_args()

    if "OPENROUTER_API_KEY" not in os.environ:
        sys.exit("Set OPENROUTER_API_KEY (see .env.example) before running this.")

    client = JevClient()
    base = Path(__file__).parent / "samples"

    if args.conversations:
        print(f"POLICY: {args.policy}\n")
        print("CONVERSATIONS (multi-turn)")
        for name, turns in json.loads((base / "conversations.json").read_text()).items():
            result = guard_conversation(client, turns, args.policy)
            hazard, probability = top_hazard(result["nouls"])
            print(
                f"[{ICON[result['action']]}] {name:<24} {hazard}={probability:.2f} "
                f"sev={result['severity']:.1f}  ({len(turns)} turns)"
            )
        return

    prompts = load_messages(base / "prompts.txt")
    replies = load_messages(base / "replies.txt")

    if args.show:
        in_prompts, in_replies = args.show in prompts, args.show in replies
        if in_prompts and in_replies and not args.side:
            sys.exit(f"{args.show!r} is in both prompts.txt and replies.txt — pass --side input or --side output")
        side = args.side or ("input" if in_prompts else "output" if in_replies else None)
        if side == "input" and in_prompts:
            show(client, prompts, "input", args.show, args.policy)
        elif side == "output" and in_replies:
            show(client, replies, "output", args.show, args.policy)
        else:
            sys.exit(f"Unknown message id: {args.show}" + (f" (not found on side={side})" if side else ""))
        return

    print(f"POLICY: {args.policy}\n")
    print("INPUT  (user messages)")
    run(client, prompts, "input", args.policy)
    print("\nOUTPUT (model replies)")
    run(client, replies, "output", args.policy)


if __name__ == "__main__":
    main()
