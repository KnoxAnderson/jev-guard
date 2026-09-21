#!/usr/bin/env python3
"""Sweep every Model Armor PI template permutation against a dataset.

Answers the question the single-template comparison could not: how much of Model
Armor's measured gap is its configuration rather than its capability.

    python sweep.py deepset --n 50
"""

import argparse
import json
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
from provision_templates import PREFIX, permutations


def main() -> None:
    load_dotenv()
    p = argparse.ArgumentParser()
    p.add_argument("datasets", nargs="+", choices=LOADERS.keys())
    p.add_argument("--n", type=int, default=50)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--json", help="write sweep results here")
    args = p.parse_args()
    if "OPENROUTER_API_KEY" not in os.environ:
        sys.exit("Set OPENROUTER_API_KEY first.")

    jev = JevClient()
    policy = POLICIES[DEFAULT_POLICY]
    cache = ScreenCache(Path(__file__).parent / "compare_cache.json")

    sweep: dict[str, dict] = {}
    for ds in args.datasets:
        cases = LOADERS[ds](n=args.n, seed=args.seed)
        print(f"\n=== {ds} ({len(cases)} cases) ===")

        jev_cm = ConfusionMatrix()
        for case in cases:
            key = {"sys": "jev", "side": case.side, "state": case.state, "battery": BATTERIES[case.side]}
            r = cache.get_or_compute(key, lambda: screen(jev, case.state, case.side))
            jev_cm.add(int(route(r["nouls"], r["severity"], policy, r.get("structural")) != "pass"), case.label)
        print(f"  {'jev-guard (reference)':<26} P={jev_cm.precision:.2f} R={jev_cm.recall:.2f} "
              f"F1={jev_cm.f1:.2f} FPR={jev_cm.fpr:.2f}")
        sweep[ds] = {"n": len(cases), "jev": {"precision": jev_cm.precision, "recall": jev_cm.recall,
                                              "f1": jev_cm.f1, "fpr": jev_cm.fpr}, "armor": {}}

        for name, conf, ml in permutations():
            client = ModelArmorClient(f"projects/ma-claude/locations/us-central1/templates/{name}")
            cm = ConfusionMatrix()
            for case in cases:
                key = {"sys": "armor", "side": case.side, "state": case.for_armor(), "template": name}
                r = cache.get_or_compute(key, lambda: client.scan(case.for_armor(), case.side))
                cm.add(int(r["flagged"]), case.label)
            label = f"{conf.replace('_AND_ABOVE','').lower()}/ml={'on' if ml else 'off'}"
            print(f"  {label:<26} P={cm.precision:.2f} R={cm.recall:.2f} F1={cm.f1:.2f} FPR={cm.fpr:.2f}")
            sweep[ds]["armor"][label] = {"precision": cm.precision, "recall": cm.recall,
                                         "f1": cm.f1, "fpr": cm.fpr, "template": name}


    if args.json:
        Path(args.json).write_text(json.dumps(sweep, indent=2))
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
