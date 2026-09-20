#!/usr/bin/env python3
"""Score jev_guard's guard() classifier against labeled public prompt-injection datasets.

Usage:
    python benchmark.py deepset             # direct injection/jailbreak, 30 sampled cases
    python benchmark.py bipia --n 60        # indirect injection, 60 sampled cases
    python benchmark.py deepset bipia --policy permissive

Results are cached in bench_cache.json so re-running after editing policy.py (thresholds,
hazard-to-action mapping) is free until you delete that file or change hazards.py/model.
"""

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from jev_guard import DEFAULT_POLICY, POLICIES, JevClient, route, screen
from jev_guard.bench.cache import ScreenCache
from jev_guard.bench.datasets import LOADERS
from jev_guard.bench.metrics import ConfusionMatrix, threshold_sweep
from jev_guard.hazards import BATTERIES


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("datasets", nargs="+", choices=LOADERS.keys())
    parser.add_argument("--n", type=int, default=30, help="cases to sample per dataset (controls API cost)")
    parser.add_argument("--policy", default=DEFAULT_POLICY, choices=POLICIES.keys())
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    if "OPENROUTER_API_KEY" not in os.environ:
        sys.exit("Set OPENROUTER_API_KEY (see .env.example) before running this.")

    client = JevClient()
    cache = ScreenCache(Path(__file__).parent / "bench_cache.json")
    policy = POLICIES[args.policy]

    for name in args.datasets:
        cases = LOADERS[name](n=args.n, seed=args.seed)
        print(f"\n=== {name} ({len(cases)} cases, policy={args.policy}) ===")

        cm = ConfusionMatrix()
        scored: list[tuple[float, int]] = []
        for case in cases:
            # Battery is part of the key so editing hazards.py invalidates stale cache
            # entries instead of silently reusing noul scores from the old wording.
            key = {"model": client.model, "side": case.side, "state": case.state, "battery": BATTERIES[case.side]}
            result = cache.get_or_compute(key, lambda case=case: screen(client, case.state, case.side))
            score = max(result["nouls"].values())
            action = route(result["nouls"], result["severity"], policy)
            predicted = 0 if action == "pass" else 1
            cm.add(predicted=predicted, actual=case.label)
            scored.append((score, case.label))

        print(f"tp={cm.tp} fp={cm.fp} tn={cm.tn} fn={cm.fn}")
        print(f"precision={cm.precision:.2f} recall={cm.recall:.2f} f1={cm.f1:.2f} fpr={cm.fpr:.2f}")

        print("\nthreshold sweep (max hazard probability, ignoring policy actions):")
        for row in threshold_sweep(scored, [0.3, 0.5, 0.7, 0.85, 0.95]):
            print(
                f"  t={row['threshold']:.2f}  precision={row['precision']:.2f} "
                f"recall={row['recall']:.2f} f1={row['f1']:.2f} fpr={row['fpr']:.2f}"
            )


if __name__ == "__main__":
    main()
