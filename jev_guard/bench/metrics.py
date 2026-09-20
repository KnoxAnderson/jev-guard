"""Confusion-matrix and threshold-sweep metrics for scoring guard() against labeled data."""

from dataclasses import dataclass


@dataclass
class ConfusionMatrix:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    def add(self, predicted: int, actual: int) -> None:
        if predicted == 1 and actual == 1:
            self.tp += 1
        elif predicted == 1 and actual == 0:
            self.fp += 1
        elif predicted == 0 and actual == 0:
            self.tn += 1
        else:
            self.fn += 1

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else float("nan")

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else float("nan")

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p == p and r == r and (p + r) else float("nan")  # p==p filters nan

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) else float("nan")


def threshold_sweep(scores_labels: list[tuple[float, int]], thresholds: list[float]) -> list[dict]:
    """Recompute the confusion matrix at each threshold against the raw max-hazard-probability
    score, independent of the block/review/support/pass policy actions."""
    rows = []
    for t in thresholds:
        cm = ConfusionMatrix()
        for score, label in scores_labels:
            cm.add(predicted=int(score >= t), actual=label)
        rows.append({"threshold": t, "precision": cm.precision, "recall": cm.recall, "f1": cm.f1, "fpr": cm.fpr})
    return rows
