"""Source parsers: file -> text chunks and/or tables (raw, local only)."""
from __future__ import annotations

import csv
import email
import email.policy
import re
from dataclasses import dataclass, field
from pathlib import Path

from .inspect_src import _read_text

MAX_FILE_BYTES = 8 * 1024 * 1024
CHUNK_CHARS = 1500
TABLE_ROWS_PER_CHUNK = 15

TEXT_EXT = {
    ".txt", ".md", ".log", ".cfg", ".conf", ".ini", ".json", ".yaml", ".yml", ".xml",
    ".env", ".kv", ".sh", ".ps1", ".psm1", ".bat", ".cmd", ".py", ".toml", ".properties",
    ".drawio", ".html", ".htm", ".sql", ".rsc",
}


@dataclass
class Table:
    label: str
    header: list[str]
    rows: list[list[str]]


@dataclass
class Parsed:
    kind: str                       # text | table | email | doc | pdf | skipped
    texts: list[str] = field(default_factory=list)
    tables: list[Table] = field(default_factory=list)
    note: str = ""


def chunk_text(text: str, size: int = CHUNK_CHARS) -> list[str]:
    """Split on line boundaries; a single overlong line is hard-split."""
    out, cur = [], ""
    for line in text.splitlines(keepends=True):
        while len(line) > size:
            if cur:
                out.append(cur)
                cur = ""
            out.append(line[:size])
            line = line[size:]
        if len(cur) + len(line) > size and cur:
            out.append(cur)
            cur = ""
        cur += line
    if cur.strip():
        out.append(cur)
    return [c for c in out if c.strip()]


def table_chunks(t: Table) -> list[str]:
    out = []
    for i in range(0, len(t.rows), TABLE_ROWS_PER_CHUNK):
        lines = []
        for row in t.rows[i:i + TABLE_ROWS_PER_CHUNK]:
            cells = []
            for j, v in enumerate(row):
                if v:
                    h = t.header[j] if j < len(t.header) and t.header[j] else f"col{j + 1}"
                    cells.append(f"{h}: {v}")
            lines.append(" | ".join(cells))
        out.append("\n".join(lines))
    return [c for c in out if c.strip()]


def _cell(v) -> str:
    if v is None:
        return ""
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    return str(v).strip()


def pick_header(rows: list[list[str]], scan: int = 6) -> int:
    """Index of the header row: sheets often start with a title line or a merged caption.
    The header is the first of the top rows that is wide and mostly short non-numeric labels."""
    width = max(sum(1 for c in r if c) for r in rows[:scan + 1])
    for i, r in enumerate(rows[:scan]):
        cells = [c for c in r if c]
        if len(cells) < max(2, width * 0.6):
            continue
        labels = [c for c in cells if not _is_numberish(c) and len(c) <= 60]
        if len(labels) >= 0.8 * len(cells) and len(set(cells)) == len(cells):
            return i
    return 0


def _is_numberish(c: str) -> bool:
    return bool(re.fullmatch(r"[\d\s.,:/%-]+", c))


def _parse_csv(path: Path) -> Parsed:
    text = _read_text(path)
    try:
        dialect = csv.Sniffer().sniff(text[:8192], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel_tab if path.suffix.lower() == ".tsv" else csv.excel
    rows = [[_cell(c) for c in r] for r in csv.reader(text.splitlines(), dialect)]
    if not rows:
        return Parsed("table")
    return Parsed("table", tables=[Table("t1", rows[0], rows[1:])])


def _parse_xlsx(path: Path) -> Parsed:
    from openpyxl import load_workbook

    wb = load_workbook(path, read_only=True, data_only=True)
    tables = []
    try:
        for ws in wb.worksheets:
            rows = [[_cell(c) for c in r] for r in ws.iter_rows(values_only=True)]
            rows = [r for r in rows if any(r)]
            if rows:
                h = pick_header(rows)
                tables.append(Table(ws.title, rows[h], rows[h + 1:]))
    finally:
        wb.close()
    return Parsed("table", tables=tables)


def _parse_docx(path: Path) -> Parsed:
    from docx import Document

    doc = Document(str(path))
    paras = [p.text for p in doc.paragraphs if p.text.strip()]
    tables = []
    for n, t in enumerate(doc.tables, start=1):
        rows = [[c.text.strip() for c in r.cells] for r in t.rows]
        if rows:
            tables.append(Table(f"table{n}", rows[0], rows[1:]))
    return Parsed("doc", texts=chunk_text("\n".join(paras)), tables=tables)


def _parse_pdf(path: Path) -> Parsed:
    from pypdf import PdfReader
    from pypdf.errors import PdfReadError

    try:
        text = "\n".join((p.extract_text() or "") for p in PdfReader(str(path)).pages)
    except PdfReadError as e:
        return Parsed("skipped", note=f"broken pdf: {type(e).__name__}")
    if not text.strip():
        return Parsed("skipped", note="pdf without text layer (OCR not implemented)")
    return Parsed("pdf", texts=chunk_text(text))


def _parse_eml(path: Path) -> Parsed:
    msg = email.message_from_bytes(path.read_bytes(), policy=email.policy.default)
    head = "\n".join(f"{h}: {msg[h]}" for h in ("From", "To", "Cc", "Subject") if msg[h])
    parts = []
    for part in msg.walk():
        if part.get_content_type() == "text/plain" and not part.is_attachment():
            parts.append(part.get_content())
    return Parsed("email", texts=chunk_text(head + "\n\n" + "\n".join(parts)))


def _looks_text(path: Path) -> bool:
    sample = path.read_bytes()[:4096]
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def parse(path: Path) -> Parsed:
    ext = path.suffix.lower()
    if path.stat().st_size > MAX_FILE_BYTES:
        return Parsed("skipped", note="file too large")
    if ext in (".csv", ".tsv"):
        return _parse_csv(path)
    if ext in (".xlsx", ".xlsm"):
        return _parse_xlsx(path)
    if ext == ".docx":
        return _parse_docx(path)
    if ext == ".pdf":
        return _parse_pdf(path)
    if ext == ".eml":
        return _parse_eml(path)
    if ext in TEXT_EXT or _looks_text(path):
        return Parsed("text", texts=chunk_text(_read_text(path)))
    return Parsed("skipped", note=f"unsupported type {ext or '(none)'}")
