"""Model Armor REST client, for head-to-head comparison against jev-guard.

Uses Application Default Credentials, so `gcloud auth application-default login`
must already have been run. Only used by compare.py — nothing in the guard itself
depends on this.
"""

from __future__ import annotations

import random
import time

import google.auth
import google.auth.transport.requests
import requests

DEFAULT_TEMPLATE = "projects/ma-claude/locations/us-central1/templates/testing-template"


class ModelArmorClient:
    def __init__(self, template: str = DEFAULT_TEMPLATE, timeout: float = 30.0):
        self.template = template
        self.timeout = timeout
        location = template.split("/")[template.split("/").index("locations") + 1]
        self._base = f"https://modelarmor.{location}.rep.googleapis.com/v1"
        self._creds, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )

    def _token(self) -> str:
        self._creds.refresh(google.auth.transport.requests.Request())
        return self._creds.token

    def scan(self, text: str, side: str = "input") -> dict:
        """Return the filters that matched, plus the raw match state.

        `filters` is the list of filter names that fired, so a comparison can
        separate a prompt-injection match from an unrelated RAI or SDP match.
        """
        endpoint = "sanitizeUserPrompt" if side == "input" else "sanitizeModelResponse"
        body = (
            {"userPromptData": {"text": text}}
            if side == "input"
            else {"modelResponseData": {"text": text}}
        )
        for attempt in range(5):
            try:
                response = requests.post(
                    f"{self._base}/{self.template}:{endpoint}",
                    headers={"Authorization": f"Bearer {self._token()}", "Content-Type": "application/json"},
                    json=body,
                    timeout=self.timeout,
                )
                if response.status_code in (429, 500, 502, 503):
                    raise requests.HTTPError(f"retryable {response.status_code}")
                response.raise_for_status()
                break
            except (requests.Timeout, requests.ConnectionError, requests.HTTPError):
                if attempt == 4:
                    raise
                time.sleep(min(2**attempt, 16) + random.random())
        sr = response.json().get("sanitizationResult", {})

        filters, confidence = [], None
        for name, wrapper in sr.get("filterResults", {}).items():
            inner = next(iter(wrapper.values()), {}) if isinstance(wrapper, dict) else {}
            if inner.get("matchState") == "MATCH_FOUND":
                filters.append(name)
                confidence = confidence or inner.get("confidenceLevel")
            # RAI nests one level deeper, as a map of category -> result.
            for category, result in (inner.get("raiFilterTypeResults") or {}).items():
                if result.get("matchState") == "MATCH_FOUND":
                    filters.append(f"rai:{category}")
        return {
            "flagged": sr.get("filterMatchState") == "MATCH_FOUND",
            "filters": sorted(set(filters)),
            "confidence": confidence,
        }
