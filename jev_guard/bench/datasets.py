"""Load public prompt-injection benchmarks into a common shape for scoring against
jev_guard.guard.screen(). Both loaders require the `datasets` package and download
from the Hugging Face Hub on first use.
"""

from dataclasses import dataclass
from typing import Any


@dataclass
class EvalCase:
    state: Any
    side: str  # "input" or "output" battery to screen with
    label: int  # 1 = attack/injection, 0 = benign
    source: str


def _split(dataset_name: str, preferred: str):
    from datasets import load_dataset

    ds_dict = load_dataset(dataset_name)
    split = preferred if preferred in ds_dict else next(iter(ds_dict))
    return ds_dict[split]


def load_deepset(n: int | None = None, seed: int = 0) -> list[EvalCase]:
    """Direct prompt injection / instruction-override attempts in a single user message.
    https://huggingface.co/datasets/deepset/prompt-injections (662 rows total)
    """
    ds = _split("deepset/prompt-injections", preferred="test")
    if n is not None:
        ds = ds.shuffle(seed=seed).select(range(min(n, len(ds))))
    return [EvalCase(state=row["text"], side="input", label=row["label"], source="deepset") for row in ds]


def load_bipia(n: int | None = None, seed: int = 0) -> list[EvalCase]:
    """Indirect prompt injection embedded in external content (email/web/docs/etc), paired
    with the user's legitimate request. A derived repackaging of Microsoft's BIPIA
    benchmark (35k malicious + 35k synthetic-benign), not the original dataset.
    https://huggingface.co/datasets/MAlmasabi/Indirect-Prompt-Injection-BIPIA-GPT
    """
    ds = _split("MAlmasabi/Indirect-Prompt-Injection-BIPIA-GPT", preferred="train")
    if n is not None:
        ds = ds.shuffle(seed=seed).select(range(min(n, len(ds))))
    return [
        EvalCase(
            state={"external_content": row["context"], "user_request": row["user_intent"]},
            side="input",
            label=row["label"],
            source="bipia",
        )
        for row in ds
    ]


LOADERS = {"deepset": load_deepset, "bipia": load_bipia}
