"""A tiny on-disk cache so re-running a benchmark (e.g. while tuning thresholds in
policy.py) doesn't re-pay for the same Jev call. Keyed on model + side + state."""

import hashlib
import json
from pathlib import Path
from typing import Any, Callable


class ScreenCache:
    def __init__(self, path: Path):
        self.path = path
        self._data: dict[str, Any] = json.loads(path.read_text()) if path.exists() else {}

    def get_or_compute(self, key: Any, compute: Callable[[], dict]) -> dict:
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode()).hexdigest()
        if digest in self._data:
            return self._data[digest]
        value = compute()
        self._data[digest] = value
        self.path.write_text(json.dumps(self._data))
        return value
