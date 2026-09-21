#!/usr/bin/env python3
"""Head-to-head: jev-guard vs Google Cloud Model Armor on labeled injection datasets.

Runs both systems over the same cases and reports each one's precision/recall, then
the part that actually matters for deciding whether to combine them: how often they
agree, and what each catches that the other misses. Two detectors are only worth
stacking if their errors are uncorrelated — this measures that instead of assuming it.

    python compare.py deepset --n 50
    python compare.py deepset safeguard jailbreak --n 40

Needs OPENROUTER_API_KEY (jev) and Application Default Credentials (Model Armor).
Both systems' results are cached in compare_cache.json.
"""

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from jev_guard import DEFAULT_POLICY, POLICIES, JevClient, route, screen
from jev_guard.bench.cache import ScreenCache
from jev_guard.bench.datasets import LOADERS
from jev_guard.bench.metrics import ConfusionMatrix
from jev_guard.bench.model_armor import ModelArmorClient
from jev_guard.hazards import BATTERIES


def report(name: str, cm: ConfusionMatrix) -> None:
    print(
        f"  {name:<22} precision={cm.precision:.2f} recall={cm.recall:.2f} "
        f"f1={cm.f1:.2f} fpr={cm.fpr:.2f}   (tp={cm.tp} fp={cm.fp} tn={cm.tn} fn={cm.fn})"
    )


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("datasets", nargs="+", choices=LOADERS.keys())
    parser.add_argument("--n", type=int, default=50, help="cases sampled per dataset")
    parser.add_argument("--policy", default=DEFAULT_POLICY, choices=POLICIES.keys())
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    if "OPENROUTER_API_KEY" not in os.environ:
        sys.exit("Set OPENROUTER_API_KEY (see .env.example) before running this.")

    jev = JevClient()
    armor = ModelArmorClient()
    policy = POLICIES[args.policy]
    cache = ScreenCache(Path(__file__).parent / "compare_cache.json")

    for name in args.datasets:
        cases = LOADERS[name](n=args.n, seed=args.seed)
        print(f"\n=== {name} ({len(cases)} cases, jev policy={args.policy}) ===")

        jev_cm, armor_cm, union_cm, inter_cm = (ConfusionMatrix() for _ in range(4))
        agree = 0
        jev_only: list[str] = []
        armor_only: list[str] = []
        both_missed: list[str] = []

        for case in cases:
            jev_key = {"sys": "jev", "side": case.side, "state": case.state, "battery": BATTERIES[case.side]}
            jev_result = cache.get_or_compute(jev_key, lambda: screen(jev, case.state, case.side))
            jev_flag = int(
                route(jev_result["nouls"], jev_result["severity"], policy, jev_result.get("structural")) != "pass"
            )

            armor_key = {"sys": "armor", "side": case.side, "state": case.state, "template": armor.template}
            armor_result = cache.get_or_compute(armor_key, lambda: armor.scan(case.state, case.side))
            armor_flag = int(armor_result["flagged"])

            jev_cm.add(jev_flag, case.label)
            armor_cm.add(armor_flag, case.label)
            union_cm.add(int(jev_flag or armor_flag), case.label)
            inter_cm.add(int(jev_flag and armor_flag), case.label)
            agree += int(jev_flag == armor_flag)

            excerpt = " ".join(str(case.state).split())[:70]
            if case.label == 1:
                if jev_flag and not armor_flag:
                    jev_only.append(excerpt)
                elif armor_flag and not jev_flag:
                    armor_only.append(excerpt)
                elif not jev_flag and not armor_flag:
                    both_missed.append(excerpt)

        report("jev-guard", jev_cm)
        report("model-armor", armor_cm)
        report("union (either flags)", union_cm)
        report("intersection (both)", inter_cm)

        attacks = jev_cm.tp + jev_cm.fn
        print(f"\n  agreement: {agree}/{len(cases)} ({agree / len(cases):.0%})")
        print(f"  of {attacks} attacks: jev-only caught {len(jev_only)}, "
              f"armor-only caught {len(armor_only)}, both missed {len(both_missed)}")
        for label, items in (("jev caught, armor missed", jev_only),
                             ("armor caught, jev missed", armor_only),
                             ("both missed", both_missed)):
            for excerpt in items[:3]:
                print(f"    [{label}] {excerpt}")


if __name__ == "__main__":
    main()
