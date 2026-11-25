"""Output guard for labels (file, sheet, column names) exposed to the agent.

P0 scope: labels only. Values are never returned by any P0 tool.
"""
from __future__ import annotations

from .cases import LabelMode
from .dlp.detectors import scan

MAX_LABEL_LEN = 64
REDACTED = "[[REDACTED]]"


def guard_label(text: str, mode: LabelMode, masked_id: str) -> str:
    if mode == "masked":
        return masked_id
    text = " ".join(str(text).split())[:MAX_LABEL_LEN]
    if not text:
        return masked_id
    return REDACTED if scan(text) else text
