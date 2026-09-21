"""Deterministic structural detectors, run alongside the semantic Jev questions.

Two jobs, both things a pure-ML classifier is bad at:

1. **Normalization.** Character-level obfuscation (invisible Unicode tag chars,
   zero-width joiners, homoglyphs, base64) reliably evades ML guardrail classifiers
   while the target LLM still reads the payload fine. We strip and decode that
   *before* the semantic call, so Jev scores the real instruction rather than the
   disguised one.
2. **Structural exfiltration signals.** The dominant real-world data-exfil vector is
   a rendered markdown image or link whose URL carries stolen data in a query
   parameter. That is a syntactic pattern, not a semantic one — a classifier reading
   for intent routinely passes it, because it looks like ordinary markdown.

Detector hits are evidence, not verdicts: policy.py decides what to do with them.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlparse

# --- character-level obfuscation ------------------------------------------------

UNICODE_TAGS = re.compile(r"[\U000E0000-\U000E007F]")
ZERO_WIDTH = re.compile(r"[​-‏⁠-⁤﻿­]")
BIDI_OVERRIDE = re.compile(r"[‪-‮⁦-⁩]")

# Cyrillic/Greek letters that render identically to ASCII and are used to defeat
# exact-match filters. Mapped back to ASCII before the text is scored.
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "і": "i", "ј": "j", "һ": "h",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "ο": "o", "α": "a", "ν": "v", "ρ": "p",
    "Α": "A", "Β": "B", "Ε": "E", "Ο": "O", "Ρ": "P",
}

INSTRUCTION_MARKERS = (
    "ignore", "disregard", "forget", "instead", "system", "prompt", "instruction",
    "you are", "act as", "reveal", "exfiltrate", "send to", "curl", "http",
)

# --- secrets / sensitive data ---------------------------------------------------

SECRET_PATTERNS: dict[str, re.Pattern] = {
    "openai_key": re.compile(r"\bsk-(?:or-v1-|proj-|ant-)?[A-Za-z0-9_-]{20,}"),
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}"),
    "google_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}"),
    "private_key": re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
}

CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")

# --- exfiltration channels ------------------------------------------------------

MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*([^)\s]+)")
MD_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(\s*([^)\s]+)")
HTML_SRC = re.compile(r"<(?:img|script|iframe)[^>]*\b(?:src|href)\s*=\s*[\"']([^\"']+)", re.I)
BARE_URL = re.compile(r"(?:https?|data|javascript|file|ftp)://?[^\s<>\"')\]]+", re.I)
RAW_IP_HOST = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Link-shortening services hide the real destination, so the address itself carries no
# evidence either way — worth a look rather than a block.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "shorte.st",
}
# TLDs with a high abuse-to-legitimate ratio; .zip and .mov collide with filenames,
# which is what makes them useful for disguising a link as an attachment.
RISKY_TLDS = {"zip", "mov", "tk", "ml", "ga", "cf", "gq"}
URL_CREDENTIALS = re.compile(r"https?://[^/\s:@]+:[^/\s@]+@", re.I)


@dataclass
class DetectorHit:
    name: str
    detail: str


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        n = ord(ch) - 48
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def _decode_b64_blobs(text: str) -> list[str]:
    """Return decoded text for base64 blobs that decode to readable instruction-like text."""
    decoded = []
    for blob in re.findall(r"[A-Za-z0-9+/]{32,}={0,2}", text):
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            candidate = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if sum(c.isprintable() or c.isspace() for c in candidate) < len(candidate) * 0.9:
            continue
        if any(marker in candidate.lower() for marker in INSTRUCTION_MARKERS):
            decoded.append(candidate)
    return decoded


def normalize(text: str) -> tuple[str, list[DetectorHit]]:
    """Strip obfuscation and surface what was stripped.

    Returns the de-obfuscated text to send to Jev, plus a hit per evasion technique
    found. Decoded base64 payloads are appended so the semantic pass scores them too.
    """
    hits: list[DetectorHit] = []

    if tags := UNICODE_TAGS.findall(text):
        smuggled = "".join(chr(ord(c) - 0xE0000) for c in tags if 0xE0020 <= ord(c) <= 0xE007E)
        hits.append(DetectorHit("invisible_unicode", f"{len(tags)} Unicode tag chars: {smuggled[:120]!r}"))
        text = UNICODE_TAGS.sub("", text) + (f"\n[decoded hidden text: {smuggled}]" if smuggled else "")

    if zw := ZERO_WIDTH.findall(text):
        hits.append(DetectorHit("invisible_unicode", f"{len(zw)} zero-width/invisible chars"))
        text = ZERO_WIDTH.sub("", text)

    if BIDI_OVERRIDE.search(text):
        hits.append(DetectorHit("invisible_unicode", "bidirectional text override characters"))
        text = BIDI_OVERRIDE.sub("", text)

    if found := [c for c in text if c in HOMOGLYPHS]:
        hits.append(DetectorHit("homoglyphs", f"{len(found)} Cyrillic/Greek lookalike chars"))
        text = "".join(HOMOGLYPHS.get(c, c) for c in text)

    # NFKC folds fullwidth/styled unicode variants back to plain ASCII forms.
    folded = unicodedata.normalize("NFKC", text)
    if folded != text:
        hits.append(DetectorHit("unicode_variants", "styled/fullwidth Unicode variants folded to ASCII"))
        text = folded

    for payload in _decode_b64_blobs(text):
        hits.append(DetectorHit("encoded_payload", f"base64 decodes to instructions: {payload[:120]!r}"))
        text += f"\n[decoded base64: {payload}]"

    return text, hits


def find_secrets(text: str) -> list[DetectorHit]:
    """Credentials, keys, and regulated identifiers appearing in the text."""
    hits = []
    for name, pattern in SECRET_PATTERNS.items():
        if matches := pattern.findall(text):
            hits.append(DetectorHit("sensitive_data", f"{name} ({len(matches)} match)"))
    for candidate in CARD_CANDIDATE.findall(text):
        digits = re.sub(r"[ -]", "", candidate)
        if 13 <= len(digits) <= 19 and _luhn(digits):
            hits.append(DetectorHit("sensitive_data", "payment card number (Luhn-valid)"))
            break
    return hits


def _url_carries_data(url: str) -> str | None:
    """Whether a URL looks like it is carrying exfiltrated data out."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https", ""):
        return f"non-http scheme {parsed.scheme!r}"
    if RAW_IP_HOST.match(parsed.hostname or ""):
        return f"raw IP host {parsed.hostname}"
    for key, values in parse_qs(parsed.query).items():
        for value in values:
            if len(value) >= 24:
                return f"query param {key!r} carries {len(value)} chars"
            if re.fullmatch(r"[A-Za-z0-9+/=_-]{16,}", value) and not value.isdigit():
                return f"query param {key!r} carries an encoded blob"
    # Data smuggled as a long opaque path segment rather than a query string.
    for segment in parsed.path.split("/"):
        if len(segment) >= 40 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", segment):
            return "long encoded path segment"
    return None


def find_exfiltration_channels(text: str) -> list[DetectorHit]:
    """Rendered images/links that would silently ship data to a third party.

    A markdown image is the highest-value case: most chat UIs auto-fetch it, so the
    data leaves with no user interaction at all.
    """
    hits = []
    for pattern, kind, auto in (
        (MD_IMAGE, "markdown image", True),
        (HTML_SRC, "html tag", True),
        (MD_LINK, "markdown link", False),
    ):
        for url in pattern.findall(text):
            if reason := _url_carries_data(url):
                prefix = "auto-fetched " if auto else ""
                hits.append(
                    DetectorHit(
                        "exfiltration_channel",
                        f"{prefix}{kind} to {urlparse(url).hostname or url[:40]} — {reason}",
                    )
                )
    return hits


def find_risky_urls(text: str) -> list[DetectorHit]:
    """Addresses that are suspicious on their face, independent of surrounding intent.

    This is the structural half of what a threat-intelligence lookup does: no feed can
    tell you a domain is bad before it is reported, but punycode homographs, embedded
    credentials, and filename-colliding TLDs are attacker-shaped regardless of whether
    the domain has been seen before.
    """
    hits = []
    if URL_CREDENTIALS.search(text):
        hits.append(DetectorHit("risky_url", "credentials embedded in URL"))
    for url in BARE_URL.findall(text):
        scheme = url.split(":", 1)[0].lower()
        if scheme in ("data", "javascript", "file"):
            hits.append(DetectorHit("risky_url", f"{scheme}: URI"))
            continue
        host = (urlparse(url).hostname or "").lower()
        if not host:
            continue
        if host.startswith("xn--") or ".xn--" in host:
            hits.append(DetectorHit("risky_url", f"punycode/IDN homograph domain {host}"))
        if host in SHORTENERS:
            hits.append(DetectorHit("risky_url", f"link shortener {host} hides destination"))
        if host.rsplit(".", 1)[-1] in RISKY_TLDS:
            hits.append(DetectorHit("risky_url", f"high-abuse TLD .{host.rsplit('.', 1)[-1]}"))
    return hits


def scan_any(state: Any) -> tuple[Any, list[DetectorHit]]:
    """scan() for state that may be a string, dict, or list.

    Jev takes structured state, so the guard has to as well: every string anywhere in
    the structure gets normalized and scanned, and hits are labeled with the field
    they came from. The shape is preserved so the question still sees the same object.
    """
    hits: list[DetectorHit] = []

    def walk(node: Any, path: str = "") -> Any:
        if isinstance(node, str):
            normalized, node_hits = scan(node)
            hits.extend(
                DetectorHit(hit.name, f"{path}: {hit.detail}" if path else hit.detail)
                for hit in node_hits
            )
            return normalized
        if isinstance(node, dict):
            return {k: walk(v, f"{path}.{k}" if path else str(k)) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v, f"{path}[{i}]") for i, v in enumerate(node)]
        return node

    return walk(state), hits


def scan(text: str) -> tuple[str, list[DetectorHit]]:
    """Normalize `text` and return it alongside every structural hit found.

    Secrets and exfil channels are checked against the normalized text so obfuscated
    payloads are caught after decoding, not before.
    """
    normalized, hits = normalize(text)
    hits += find_secrets(normalized)
    hits += find_exfiltration_channels(normalized)
    hits += find_risky_urls(normalized)
    return normalized, hits
