"""A tiny on-disk cache so re-running a benchmark (e.g. while tuning thresholds in
policy.py) doesn't re-pay for the same API call. Keyed on model + side + state.

Thread-safe, and flushes periodically rather than on every write — at a few thousand
entries, rewriting the whole file per entry is quadratic and dominates runtime.
"""

import hashlib
import json
import threading
from pathlib import Path
from typing import Any, Callable

FLUSH_EVERY = 50


class ScreenCache:
    def __init__(self, path: Path):
        self.path = path
        self._data: dict[str, Any] = json.loads(path.read_text()) if path.exists() else {}
        self._lock = threading.Lock()
        self._unflushed = 0

    def _digest(self, key: Any) -> str:
        return hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode()).hexdigest()

    def get_or_compute(self, key: Any, compute: Callable[[], dict]) -> dict:
        digest = self._digest(key)
        with self._lock:
            if digest in self._data:
                return self._data[digest]
        # Computed outside the lock so concurrent callers actually run in parallel.
        value = compute()
        with self._lock:
            self._data[digest] = value
            self._unflushed += 1
            if self._unflushed >= FLUSH_EVERY:
                self._write()
        return value

    def _write(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data))
        tmp.replace(self.path)
        self._unflushed = 0

    def flush(self) -> None:
        with self._lock:
            if self._unflushed:
                self._write()
