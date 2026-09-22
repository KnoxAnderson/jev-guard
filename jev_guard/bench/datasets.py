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
    # What Model Armor is given, when that differs from Jev's state. Its
    # sanitizeUserPrompt API takes only the user's text, so for system-prompt-aware
    # datasets it cannot see the policy being violated. Defaults to the state.
    armor_text: str | None = None

    def for_armor(self) -> str:
        return self.armor_text if self.armor_text is not None else str(self.state)


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
            # Model Armor takes flat text, so it gets the same content in the shape a
            # real deployment would send rather than a Python dict repr.
            armor_text=f"{row['user_intent']}\n\n{row['context']}",
        )
        for row in ds
    ]




def load_safeguard(n: int | None = None, seed: int = 0) -> list[EvalCase]:
    """Direct prompt injection, larger and more varied than deepset.
    https://huggingface.co/datasets/xTRam1/safe-guard-prompt-injection (2,060 test rows)
    """
    ds = _split("xTRam1/safe-guard-prompt-injection", preferred="test")
    if n is not None:
        ds = ds.shuffle(seed=seed).select(range(min(n, len(ds))))
    return [EvalCase(state=row["text"], side="input", label=row["label"], source="safeguard") for row in ds]


def load_jailbreak(n: int | None = None, seed: int = 0) -> list[EvalCase]:
    """Jailbreak vs benign prompts, labeled by `type` rather than a 0/1 column.
    https://huggingface.co/datasets/jackhhao/jailbreak-classification (262 test rows)
    """
    ds = _split("jackhhao/jailbreak-classification", preferred="test")
    if n is not None:
        ds = ds.shuffle(seed=seed).select(range(min(n, len(ds))))
    return [
        EvalCase(
            state=row["prompt"],
            side="input",
            label=1 if row["type"].strip().lower() == "jailbreak" else 0,
            source="jailbreak",
        )
        for row in ds
    ]


def load_spml(n: int | None = None, seed: int = 0) -> list[EvalCase]:
    """Injection judged against a specific system prompt, not in the abstract.

    Each row pairs the chatbot's system prompt with a user prompt, so the question is
    whether *this* message subverts *that* policy. Jev gets both as structured state;
    Model Armor's API takes only the user text, so it is scored on that.
    https://huggingface.co/datasets/reshabhs/SPML_Chatbot_Prompt_Injection (16k rows)
    """
    ds = _split("reshabhs/SPML_Chatbot_Prompt_Injection", preferred="train")
    if n is not None:
        ds = ds.shuffle(seed=seed).select(range(min(n, len(ds))))
    cases = []
    for row in ds:
        system, user = row["System Prompt"], row["User Prompt"]
        if not system or not user:
            continue
        cases.append(
            EvalCase(
                state={"system_prompt": system, "user_prompt": user},
                side="input",
                label=int(row["Prompt injection"]),
                source="spml",
                armor_text=user,
            )
        )
    return cases


def load_slabs(n: int | None = None, seed: int = 0) -> list[EvalCase]:
    """An independent direct-injection set, for cross-checking deepset's numbers.
    https://huggingface.co/datasets/S-Labs/prompt-injection-dataset (2,101 test rows)
    """
    ds = _split("S-Labs/prompt-injection-dataset", preferred="test")
    if n is not None:
        ds = ds.shuffle(seed=seed).select(range(min(n, len(ds))))
    return [EvalCase(state=row["text"], side="input", label=row["label"], source="slabs") for row in ds]


def load_password(n: int | None = None, seed: int = 0) -> list[EvalCase]:
    """Attempts to extract a secret the system was told to keep — targeted at the
    secrets_exfiltration hazard specifically rather than injection in general.
    https://huggingface.co/datasets/ivanleomk/prompt_injection_password (917 rows)
    """
    ds = _split("ivanleomk/prompt_injection_password", preferred="train")
    if n is not None:
        ds = ds.shuffle(seed=seed).select(range(min(n, len(ds))))
    return [EvalCase(state=row["text"], side="input", label=row["label"], source="password") for row in ds]


def load_mixed(n: int | None = None, seed: int = 0) -> list[EvalCase]:
    """A large mixed corpus whose benign half is ordinary QA/reasoning text, which makes
    it a better false-positive probe than the attack-heavy sets.
    https://huggingface.co/datasets/jayavibhav/prompt-injection (65k test rows)
    """
    ds = _split("jayavibhav/prompt-injection", preferred="test")
    if n is not None:
        ds = ds.shuffle(seed=seed).select(range(min(n, len(ds))))
    return [EvalCase(state=row["text"], side="input", label=row["label"], source="mixed") for row in ds]




def load_jailbreakhub(n: int | None = None, seed: int = 0) -> list[EvalCase]:
    """In-the-wild jailbreak prompts scraped from Discord/Reddit/prompt sites, mixed with
    ordinary ones. The attacks are real rather than synthesized.
    https://huggingface.co/datasets/walledai/JailbreakHub (15,140 rows)
    """
    ds = _split("walledai/JailbreakHub", preferred="train")
    if n is not None:
        ds = ds.shuffle(seed=seed).select(range(min(n, len(ds))))
    return [
        EvalCase(state=row["prompt"], side="input", label=int(bool(row["jailbreak"])), source="jailbreakhub")
        for row in ds
        if row.get("prompt")
    ]


def load_jbb(n: int | None = None, seed: int = 0) -> list[EvalCase]:
    """JailbreakBench behaviors: 100 harmful and 100 benign, deliberately matched so the
    benign half looks superficially similar to the harmful half. A sharp false-positive test.
    https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors (behaviors config)
    """
    from datasets import load_dataset

    cases = []
    for split, label in (("harmful", 1), ("benign", 0)):
        ds = load_dataset("JailbreakBench/JBB-Behaviors", "behaviors", split=split)
        if n is not None:
            ds = ds.shuffle(seed=seed).select(range(min(n // 2, len(ds))))
        cases += [EvalCase(state=row["Goal"], side="input", label=label, source="jbb") for row in ds]
    return cases


def load_gandalf(n: int | None = None, seed: int = 0) -> list[EvalCase]:
    """Real password-extraction attempts submitted to Lakera's Gandalf game. Every row is
    an attack, so this measures recall only — precision is meaningless here.
    https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions (1,000 rows)
    """
    ds = _split("Lakera/gandalf_ignore_instructions", preferred="test")
    if n is not None:
        ds = ds.shuffle(seed=seed).select(range(min(n, len(ds))))
    return [EvalCase(state=row["text"], side="input", label=1, source="gandalf") for row in ds]

LOADERS = {
    "deepset": load_deepset,
    "bipia": load_bipia,
    "safeguard": load_safeguard,
    "jailbreak": load_jailbreak,
    "spml": load_spml,
    "slabs": load_slabs,
    "password": load_password,
    "mixed": load_mixed,
    "jailbreakhub": load_jailbreakhub,
    "jbb": load_jbb,
    "gandalf": load_gandalf,
}
