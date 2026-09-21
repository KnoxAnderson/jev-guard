#!/usr/bin/env python3
"""Provision Model Armor templates covering every prompt-injection filter permutation.

Model Armor's PI/jailbreak filter has one tunable axis of its own (confidence level)
plus multi-language detection, which materially affects PI recall on non-English text.
That is 3 x 2 = 6 combinations. Each template isolates the PI filter — RAI, SDP, and
malicious-URI are left off — so a comparison measures prompt-injection detection
rather than "any filter fired".

Every template pins templateMetadata.filterVersionSelector.alias to
FILTER_VERSION_ALIAS_LATEST, so they track the newest filter build rather than STABLE.

    python provision_templates.py create
    python provision_templates.py list
    python provision_templates.py delete     # removes only templates with the PREFIX
"""

import sys

import google.auth
import google.auth.transport.requests
import requests

PROJECT = "ma-claude"
LOCATION = "us-central1"
PREFIX = "pi-eval"
BASE = (
    f"https://modelarmor.{LOCATION}.rep.googleapis.com/v1"
    f"/projects/{PROJECT}/locations/{LOCATION}/templates"
)

CONFIDENCE = {"low": "LOW_AND_ABOVE", "med": "MEDIUM_AND_ABOVE", "high": "HIGH"}
MULTILANG = {"mlon": True, "mloff": False}


def permutations() -> list[tuple[str, str, bool]]:
    return [
        (f"{PREFIX}-{c_key}-{m_key}", c_val, m_val)
        for c_key, c_val in CONFIDENCE.items()
        for m_key, m_val in MULTILANG.items()
    ]


def _headers() -> dict[str, str]:
    creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    creds.refresh(google.auth.transport.requests.Request())
    return {"Authorization": f"Bearer {creds.token}", "Content-Type": "application/json"}


def body(confidence: str, multilang: bool) -> dict:
    return {
        "filterConfig": {
            "piAndJailbreakFilterSettings": {
                "filterEnforcement": "ENABLED",
                "confidenceLevel": confidence,
            }
        },
        "templateMetadata": {
            "logSanitizeOperations": True,
            "logTemplateOperations": True,
            "multiLanguageDetection": {"enableMultiLanguageDetection": multilang},
            # Track the newest filter build rather than STABLE.
            "filterVersionSelector": {"alias": "FILTER_VERSION_ALIAS_LATEST"},
        },
    }


def create() -> None:
    headers = _headers()
    for name, confidence, multilang in permutations():
        response = requests.post(
            f"{BASE}?template_id={name}", headers=headers, json=body(confidence, multilang), timeout=30
        )
        if response.status_code == 200:
            print(f"created  {name:<22} {confidence:<18} multilang={multilang}")
        elif response.status_code == 409:
            # Already there: PATCH so re-running converges rather than failing.
            patch = requests.patch(
                f"{BASE}/{name}?updateMask=filterConfig,templateMetadata",
                headers=headers, json=body(confidence, multilang), timeout=30,
            )
            state = "updated" if patch.status_code == 200 else f"FAILED {patch.status_code}"
            print(f"{state:<8} {name:<22} {confidence:<18} multilang={multilang}")
        else:
            print(f"FAILED   {name:<22} {response.status_code} {response.text[:160]}")


def listing() -> None:
    response = requests.get(BASE, headers=_headers(), timeout=30)
    response.raise_for_status()
    for template in response.json().get("templates", []):
        name = template["name"].split("/")[-1]
        pi = template.get("filterConfig", {}).get("piAndJailbreakFilterSettings", {})
        meta = template.get("templateMetadata", {})
        print(
            f"{name:<24} pi={pi.get('confidenceLevel', '-'):<18} "
            f"version={meta.get('filterVersionSelector', {}).get('alias', '-'):<28} "
            f"multilang={meta.get('multiLanguageDetection', {}).get('enableMultiLanguageDetection', False)}"
        )


def delete() -> None:
    """Delete only templates this script owns — anything without PREFIX is left alone."""
    headers = _headers()
    response = requests.get(BASE, headers=headers, timeout=30)
    response.raise_for_status()
    for template in response.json().get("templates", []):
        name = template["name"].split("/")[-1]
        if not name.startswith(PREFIX):
            print(f"skipped  {name} (not owned by this script)")
            continue
        r = requests.delete(f"{BASE}/{name}", headers=headers, timeout=30)
        print(f"{'deleted' if r.status_code == 200 else f'FAILED {r.status_code}'}  {name}")


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "list"
    {"create": create, "list": listing, "delete": delete}[action]()
