"""Local observation UI: what the agent asked, what the vault answered, what the prompt
guard stopped. Loopback only, stdlib only, read-only.

Everything shown is what the agent itself received (handles, [[REDACTED]], [[DV:WARN]])
or counts; raw values never leave the store. The prompt guard feed shows the masked copy
of blocked prompts, never the original.
"""
from __future__ import annotations

import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__
from .cases import list_cases
from .config import vault_home
from .ingest import store_path
from .store import Store

PROMPT_LOG = "promptguard.jsonl"


def _ro(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=1)


def overview() -> dict:
    out = []
    for c in list_cases():
        path = store_path(c)
        row = {"case": c.name, "ingested": path.exists(), "sources": len(c.source_files())}
        if path.exists():
            try:
                st = Store(path, readonly=True, timeout=1)
            except sqlite3.OperationalError:
                row["locked"] = True
                out.append(row)
                continue
            try:
                meta = st.meta()
                row.update({"ingested_at": meta.get("ingested_at"), "handles": st.counts(),
                            "injection_chunks": st.injections(),
                            "chunks": st.db.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]})
                try:
                    row["calls"] = st.db.execute("SELECT COUNT(*) FROM access").fetchone()[0]
                except sqlite3.OperationalError:
                    row["calls"] = 0
            except sqlite3.OperationalError:
                row["locked"] = True
            finally:
                st.close()
        out.append(row)
    return {"version": __version__, "home": str(vault_home()), "cases": out}


def events(limit: int = 200, case: str | None = None) -> list[dict]:
    rows: list[dict] = []
    for c in list_cases():
        if case and c.name != case:
            continue
        path = store_path(c)
        if not path.exists():
            continue
        try:
            db = _ro(path)
        except sqlite3.OperationalError:
            continue
        try:
            cols = {r[1] for r in db.execute("PRAGMA table_info(access)")}
            if not cols:
                continue
            extra = [x for x in ("handles", "redacted", "warnings") if x in cols]
            sel = "rowid, ts, tool, args, out_chars, redactions" + "".join(f", {x}" for x in extra)
            for r in db.execute(f"SELECT {sel} FROM access ORDER BY rowid DESC LIMIT ?",
                                (limit,)):
                d = {"kind": "call", "case": c.name, "id": r[0], "ts": r[1], "tool": r[2],
                     "args": r[3], "out_chars": r[4], "redactions": r[5]}
                for k, v in zip(extra, r[6:], strict=False):
                    d[k] = v
                rows.append(d)
        except sqlite3.OperationalError:
            pass
        finally:
            db.close()
    log = vault_home() / PROMPT_LOG
    if log.is_file():
        lines = log.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
        for i, line in enumerate(lines):
            try:
                d = json.loads(line)
            except ValueError:
                continue
            rows.append({"kind": "prompt", "case": "-", "id": i, **d})
    rows.sort(key=lambda d: d.get("ts", ""), reverse=True)
    return rows[:limit]


def event(case: str, rowid: int) -> dict | None:
    c = next((c for c in list_cases() if c.name == case), None)
    if c is None or not store_path(c).exists():
        return None
    try:
        db = _ro(store_path(c))
        try:
            cols = {r[1] for r in db.execute("PRAGMA table_info(access)")}
            sel = "ts, tool, args, out_chars, redactions" + (", out" if "out" in cols
                                                               else ", NULL")
            r = db.execute(f"SELECT {sel} FROM access WHERE rowid=?", (rowid,)).fetchone()
        finally:
            db.close()
    except sqlite3.OperationalError:
        return {"error": "store is locked (ingest in progress)"}
    if not r:
        return None
    return {"case": case, "id": rowid, "ts": r[0], "tool": r[1], "args": r[2],
            "out_chars": r[3], "redactions": r[4], "out": r[5]}


PAGE = (Path(__file__).with_name("web.html"))


class Handler(BaseHTTPRequestHandler):
    server_version = "datavault-web"

    def log_message(self, *a):  # quiet
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data, code: int = 200):
        self._send(code, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def do_GET(self):  # noqa: N802
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/":
            return self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
        if u.path == "/api/overview":
            return self._json(overview())
        if u.path == "/api/events":
            limit = max(1, min(int(q.get("limit", ["200"])[0]), 1000))
            return self._json(events(limit, q.get("case", [None])[0]))
        if u.path == "/api/event":
            e = event(q.get("case", [""])[0], int(q.get("id", ["0"])[0]))
            return self._json(e or {"error": "not found"}, 200 if e else 404)
        return self._json({"error": "not found"}, 404)


def serve(port: int = 8787, host: str = "127.0.0.1") -> None:
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise ValueError("web UI binds to loopback only")
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"DataVault web UI on http://{host}:{port}/ (read-only, loopback)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
