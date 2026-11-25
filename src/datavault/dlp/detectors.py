"""Content detectors: return Findings with char offsets into the text.

Patterns are ported/adapted from the author's DLP proxy ruleset (secrets, financial,
UZ/RU PII). Cyrillic keyword anchors are written as \\u escapes so this source
file stays ASCII-only (per repo convention) while the compiled regex still
matches Cyrillic text. Detection is conservative (high precision) because
actions may block user traffic; tune reach via policy severity.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass


# --- Cyrillic keyword fragments ---
# Built from Unicode code points so this source file stays ASCII-only (repo
# convention) while the compiled regex still matches the Cyrillic keyword.
def _u(*cps: int) -> str:
    return "".join(map(chr, cps))


_PAROL = _u(0x43f, 0x430, 0x440, 0x43e, 0x43b, 0x44c)           # parol
_PINFL_CYR = _u(0x43f, 0x438, 0x43d, 0x444, 0x43b)              # pinfl
_INN_CYR = _u(0x438, 0x43d, 0x43d)                             # inn
_PASPORT = _u(0x43f, 0x430, 0x441, 0x43f, 0x43e, 0x440, 0x442)  # pasport


@dataclass(frozen=True)
class Finding:
    detector: str          # detector id, e.g. "aws_access_key"
    category: str          # secret | credential | pii | financial | internal
    start: int
    end: int
    value: str
    severity: str          # low | medium | high | critical
    confidence: float      # 0..1


def _luhn_valid(text: str) -> bool:
    nums = [int(d) for d in text if d.isdigit()]
    if not 13 <= len(nums) <= 19:
        return False
    checksum = 0
    parity = len(nums) % 2
    for i, d in enumerate(nums):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# (id, category, severity, compiled_regex, validator)
# validator: optional callable(matched_text) -> bool; None = always accept.
_RULES: list[tuple[str, str, str, re.Pattern[str], object]] = [
    # --- secrets ---
    ("aws_access_key", "secret", "critical", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), None),
    ("aws_secret_key", "secret", "critical",
     re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"), None),
    ("gcp_api_key", "secret", "critical", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), None),
    ("openai_key", "secret", "critical", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), None),
    ("anthropic_key", "secret", "critical", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"), None),
    ("private_key", "secret", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), None),
    ("connection_string", "secret", "critical",
     re.compile(r"(?i)(?:Server|Host|Data Source)=[^;]{5,};.*(?:Password|Pwd)=[^;]+"), None),
    ("github_token", "secret", "high", re.compile(r"\bgh[psour]_[A-Za-z0-9]{36,}\b"), None),
    ("slack_token", "secret", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), None),
    ("jwt", "secret", "high",
     re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"), None),
    ("azure_key", "secret", "high", re.compile(r"\b[A-Za-z0-9/+]{86}==\b"), None),
    ("api_secret", "secret", "high",
     re.compile(r"(?i)(?:api[_\s]?key|api[_\s]?secret|bearer|secret[_\s]?key|"
                r"access[_\s]?key|private[_\s]?key)\s*[:=]\s*[A-Za-z0-9_\-.]{16,}"), None),

    # --- credentials ---
    # keyword may be separated from the value by a few words ("password for the db: ...",
    # "parol ot bazy: ..."). The value must look secret-ish (6+ chars with a digit or
    # symbol) so normal questions mentioning a password are not blocked.
    ("password", "credential", "high",
     re.compile(rf"(?i)(?:password|passwd|pwd|parol|{_PAROL})[^\n:=]{{0,40}}[:=]\s*"
                r"((?=\S*[\d!@#$%^&*_-])\S{6,})"), None),

    # --- financial ---
    ("uz_bank_card", "financial", "high",
     re.compile(r"\b(?:8600|9860)[\s\-.]?\d{4}[\s\-.]?\d{4}[\s\-.]?\d{4}\b"), _luhn_valid),
    ("credit_card", "financial", "high",
     re.compile(r"\b(?:\d[ \-.]?){13,19}\b"), _luhn_valid),
    ("iban", "financial", "medium",
     re.compile(r"\b[A-Z]{2}\d{2}[\s\-]?[\dA-Z]{4}[\s\-]?(?:[\dA-Z]{4}[\s\-]?){1,7}[\dA-Z]{1,4}\b"),
     None),

    # --- PII (UZ / RU) ---
    ("uz_pinfl", "pii", "high",
     re.compile(rf"(?i)(?:pinfl|jshshir|{_PINFL_CYR})\s*[:=No#]{{0,2}}\s*(\d{{14}})\b"), None),
    ("uz_inn", "pii", "medium",
     re.compile(rf"(?i)(?:inn|stir|{_INN_CYR})\s*[:=No#]{{0,2}}\s*(\d{{9}})\b"), None),
    ("uz_passport", "pii", "medium", re.compile(r"\b[A-Z]{2}[\s\-.]?\d{7}\b"), None),
    ("ru_passport", "pii", "high",
     re.compile(rf"(?i)(?:{_PASPORT})\s*[:=No#]{{0,2}}\s*(\d{{2}}[\s\-.]?\d{{2}}[\s\-.]?\d{{6}})\b"),
     None),
    ("ru_snils", "pii", "high",
     re.compile(r"\b\d{3}[\s\-.]\d{3}[\s\-.]\d{3}[\s\-.]?\d{2}\b"), None),
    ("uz_phone", "pii", "low",
     re.compile(r"\+?998[\s\-.]?\(?\d{2}\)?[\s\-.]?\d{3}[\s\-.]?\d{2}[\s\-.]?\d{2}\b"), None),
    ("ru_phone", "pii", "low",
     re.compile(r"(?:\+7|\b8)[\s\-.]?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{2}[\s\-.]?\d{2}\b"), None),
    ("email", "pii", "low",
     re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None),

    # --- internal infra hints ---
    ("ipv4_private", "internal", "low",
     re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"), None),
]

# High-entropy generic secret sniffing on token-like substrings
_TOKEN_RE = re.compile(r"[A-Za-z0-9/+_=-]{24,}")
_ENTROPY_THRESHOLD = 4.0  # bits/char


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _overlaps(start: int, end: int, spans: set[tuple[int, int]]) -> bool:
    return any(s < end and start < e for s, e in spans)


def scan(text: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[int, int]] = set()

    for det_id, category, severity, rx, validator in _RULES:
        for m in rx.finditer(text):
            span = (m.start(), m.end())
            if _overlaps(span[0], span[1], seen):
                continue
            if validator is not None and not validator(m.group(0)):
                continue
            seen.add(span)
            findings.append(Finding(
                detector=det_id, category=category, start=m.start(), end=m.end(),
                value=m.group(0), severity=severity, confidence=0.95,
            ))

    # entropy pass: catch generic API tokens not covered by named patterns
    for m in _TOKEN_RE.finditer(text):
        if _overlaps(m.start(), m.end(), seen):
            continue
        tok = m.group(0)
        ent = _shannon_entropy(tok)
        if ent >= _ENTROPY_THRESHOLD:
            seen.add((m.start(), m.end()))
            findings.append(Finding(
                detector="high_entropy_secret", category="secret",
                start=m.start(), end=m.end(), value=tok,
                severity="medium", confidence=min(0.5 + (ent - _ENTROPY_THRESHOLD) / 4, 0.9),
            ))

    findings.sort(key=lambda f: f.start)
    return findings
