"""Structural inspection of case sources: shape and types, never values."""
from __future__ import annotations

import datetime as dt
import re
from collections import Counter
from pathlib import Path
from typing import Any

from .cases import Case, CaseError
from .guard import guard_label

SAMPLE_ROWS = 1000
TABULAR_XLSX = {".xlsx", ".xlsm"}

_INT_RE = re.compile(r"^[+-]?\d+$")
_FLOAT_RE = re.compile(r"^[+-]?\d+([.,]\d+)?([eE][+-]?\d+)?$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?$|^\d{2}[./]\d{2}[./]\d{4}$")
_BOOL = {"true", "false", "yes", "no", "0", "1"}


def _value_type(v: Any) -> str:
    if v is None or (isinstance(v, str) and not v.strip()):
        return "empty"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "float"
    if isinstance(v, dt.datetime | dt.date | dt.time):
        return "date"
    s = str(v).strip()
    if _INT_RE.match(s):
        return "int"
    if _FLOAT_RE.match(s):
        return "float"
    if _DATE_RE.match(s):
        return "date"
    if s.lower() in _BOOL:
        return "bool"
    return "text"


def _column_type(values: list[Any]) -> dict:
    counts = Counter(_value_type(v) for v in values)
    empty = counts.pop("empty", 0)
    if not counts:
        kind = "empty"
    elif set(counts) <= {"int", "float"}:
        kind = "float" if "float" in counts else "int"
    elif len(counts) == 1:
        kind = next(iter(counts))
    else:
        kind = "mixed"
    total = len(values) or 1
    return {"type": kind, "null_ratio": round(empty / total, 3)}


def _columns(case: Case, header: list[Any], rows: list[list[Any]], prefix: str) -> list[dict]:
    width = max([len(header)] + [len(r) for r in rows]) if (header or rows) else 0
    cols = []
    for i in range(width):
        name = header[i] if i < len(header) else ""
        col_vals = [r[i] if i < len(r) else None for r in rows]
        cols.append({
            "id": f"{prefix}c{i + 1:02d}",
            "label": guard_label(name or "", case.policy.column_labels, f"{prefix}c{i + 1:02d}"),
            **_column_type(col_vals),
        })
    return cols


def _read_text(path: Path) -> str:
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "cp1251"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1")


def source_entries(case: Case) -> list[tuple[str, Path]]:
    return [(f"f{i:03d}", p) for i, p in enumerate(case.source_files(), start=1)]


def _file_label(case: Case, fid: str, path: Path) -> str:
    rel = path.relative_to(case.data_dir).as_posix()
    if case.policy.file_labels == "masked":
        return fid + path.suffix.lower()
    return guard_label(rel, "dlp", fid + path.suffix.lower())


def list_sources(case: Case) -> list[dict]:
    return [{
        "id": fid,
        "label": _file_label(case, fid, p),
        "ext": p.suffix.lower(),
        "bytes": p.stat().st_size,
    } for fid, p in source_entries(case)]


def inspect_source(case: Case, source_id: str) -> dict:
    match = dict(source_entries(case)).get(source_id)
    if match is None:
        raise CaseError(f"unknown source id: {source_id}")
    ext = match.suffix.lower()
    info = {"id": source_id, "label": _file_label(case, source_id, match), "ext": ext,
            "bytes": match.stat().st_size}
    from .parsers import parse

    parsed = parse(match)
    info["kind"] = parsed.kind
    if parsed.note:
        info["note"] = parsed.note
    if parsed.texts:
        info["text_chunks"] = len(parsed.texts)
        info["chars"] = sum(len(x) for x in parsed.texts)
    if parsed.tables:
        prefix = "s" if ext in TABULAR_XLSX else "t"
        info["tables"] = []
        for n, tb in enumerate(parsed.tables, start=1):
            tid = f"{prefix}{n}"
            sample = tb.rows[:SAMPLE_ROWS]
            info["tables"].append({
                "id": tid,
                "label": guard_label(tb.label, case.policy.column_labels, tid),
                "rows": len(tb.rows),
                "columns": _columns(case, tb.header, sample,
                                    "" if prefix == "t" and n == 1 else f"{tid}."),
            })
    return info
