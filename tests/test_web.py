import http.client
import json
import threading
from http.server import ThreadingHTTPServer

from test_p2 import SECRET, p2case  # noqa: F401

from datavault import query, web


def test_access_log_keeps_what_the_agent_saw(p2case):  # noqa: F811
    s = query.Session(p2case, None)
    try:
        query.search(s, "backup nightly")
        row = s.st.db.execute("SELECT tool, out, handles, redacted FROM access").fetchone()
    finally:
        s.close()
    assert row[0] == "search" and row[2] >= 1 and SECRET not in row[1]
    assert json.loads(row[1])["hits"]


def test_web_api_serves_overview_events_and_detail(p2case, tmp_path):  # noqa: F811
    s = query.Session(p2case, None)
    try:
        query.read(s, next(iter(s.doc_by_sid)), 0)
    finally:
        s.close()
    (tmp_path / "promptguard.jsonl").write_text(json.dumps(
        {"ts": "2026-11-05T10:00:00", "decision": "block", "summary": "DLP: SECRET x1",
         "masked": "pw [SECRET]"}) + "\n")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", srv.server_port, timeout=5)

        def get(path):
            conn.request("GET", path)
            r = conn.getresponse()
            return r.status, r.read().decode()

        st, body = get("/")
        assert st == 200 and "<title>DataVault</title>" in body
        st, body = get("/api/overview")
        ov = json.loads(body)
        assert st == 200 and ov["cases"][0]["calls"] == 1
        st, body = get("/api/events")
        ev = json.loads(body)
        kinds = {e["kind"] for e in ev}
        assert kinds == {"call", "prompt"} and SECRET not in body
        call = next(e for e in ev if e["kind"] == "call")
        st, body = get(f"/api/event?case={call['case']}&id={call['id']}")
        d = json.loads(body)
        assert st == 200 and d["tool"] == "read" and "chunks" in d["out"]
        assert SECRET not in body
    finally:
        srv.shutdown()


def test_readers_do_not_wait_on_a_writer(p2case):  # noqa: F811
    import sqlite3
    import time

    from datavault.ingest import store_path
    from datavault.promptguard import scan
    from datavault.store import Store
    writer = sqlite3.connect(store_path(p2case))
    writer.execute("BEGIN IMMEDIATE")
    writer.execute("INSERT INTO meta VALUES ('x', 'y')")
    try:
        t = time.monotonic()
        st = Store(store_path(p2case), readonly=True, timeout=1)
        assert st.counts()  # WAL: readers see the last committed state
        st.close()
        v = scan("what about srv-sql01.corp.test")
        assert time.monotonic() - t < 5
        ov = web.overview()
        assert ov["cases"] and time.monotonic() - t < 8
        assert v.decision in ("block", "ok")
    finally:
        writer.rollback()
        writer.close()
