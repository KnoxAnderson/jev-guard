"""Thin client for calling Jev through OpenRouter's Decisions API."""

from __future__ import annotations

import os
from typing import Any

import requests

OPENROUTER_DECISIONS_URL = "https://openrouter.ai/api/alpha/decisions"
DEFAULT_MODEL = "~typesafe/jev-latest"


class JevClient:
    def __init__(self, api_key: str | None = None, model: str = DEFAULT_MODEL, timeout: float = 60.0):
        self.api_key = api_key or os.environ["OPENROUTER_API_KEY"]
        self.model = model
        self.timeout = timeout

    def ask(self, state: str | dict | list, questions: dict[str, Any]) -> dict[str, Any]:
        response = requests.post(
            OPENROUTER_DECISIONS_URL,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={"model": self.model, "state": state, "questions": questions},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()["answers"]
