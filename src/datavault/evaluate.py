"""Leak evaluation against ground truth: a truth value still present in the
pseudonymized text of its file is a leak."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

from .cases import Case
from .ingest import store_path
from .store import Store


def _digit_runs(s: str) -> str:
    """Digits with formatting removed inside numbers but kept apart between numbers."""
    return re.sub(r"(?<=\d)[\s\-().]+(?=\d)", "", s)


def _norm_text(s: str) -> str:
    return " ".join(s.split()).casefold()


def _present(value: str, typ: str, text: str, text_digits_sep: str) -> bool:
    if typ == "PHONE":
        return re.sub(r"\D", "", value)[-9:] in re.sub(r"\D", "", text_digits_sep)
    if typ == "AMT" and re.fullmatch(r"[\d ]+", value):
        d = re.sub(r"\D", "", value)
        return re.search(rf"(?<!\d){d}(?!\d)", text_digits_sep) is not None
    v = _norm_text(value)
    # word-bounded so "Kim" is not found inside "Kimyo"
    return re.search(rf"(?<!\w){re.escape(v)}(?!\w)", text) is not None


def evaluate(case: Case, truth_path: Path | None = None) -> dict:
    truth = json.loads((truth_path or case.root / "truth.json").read_text())
    st = Store(store_path(case))
    try:
        docs = st.doc_text("pseudo")
        raws = st.doc_text("raw")
        ents = [e for e in st.entities() if not e.alias]
    finally:
        st.close()

    stats: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "leaked": 0})
    leaks, missing = [], 0
    for t in truth:
        raw = raws.get(t["file"])
        if raw is None:
            missing += 1
            continue
        raw_n = _norm_text(raw)
        if not _present(t["value"], t["type"], raw_n, _digit_runs(raw)):
            missing += 1   # value not in parsed text (e.g. xlsx number formatting)
            continue
        key = f"{t['type']}{'' if t['hard'] else '(soft)'}"
        s = stats[key]
        s["total"] += 1
        pseudo = docs.get(t["file"], "")
        if _present(t["value"], t["type"], _norm_text(pseudo), _digit_runs(pseudo)):
            s["leaked"] += 1
            leaks.append(t)

    def recall(keys):
        tot = sum(stats[k]["total"] for k in keys)
        lk = sum(stats[k]["leaked"] for k in keys)
        return round(1 - lk / tot, 4) if tot else None

    # over-redaction: extracted values unrelated to any truth value
    def key(s: str) -> str:
        s = _norm_text(s)
        return re.sub(r"(?<=\d)[\s\-().]+(?=\d)", "", s)

    tvals = [key(t["value"]) for t in truth]
    fp: dict[str, int] = defaultdict(int)
    fp_values = []
    for e in ents:
        v = key(e.value)
        if not any(v in tv or tv in v for tv in tvals):
            fp[e.type] += 1
            fp_values.append({"type": e.type, "value": e.value})

    hard = [k for k in stats if "(soft)" not in k]
    return {
        "recall_hard": recall(hard),
        "recall_all": recall(list(stats)),
        "by_type": {k: {**v, "recall": recall([k])} for k, v in sorted(stats.items())},
        "truth_not_in_text": missing,
        "extracted_values": len(ents),
        "unrelated_values": dict(sorted(fp.items())),
        "leaks": leaks,
        "fp_values": fp_values,
    }
