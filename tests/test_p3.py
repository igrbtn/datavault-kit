import json

import pytest
import yaml
from test_p2 import SECRET, _sid, p2case  # noqa: F401

from datavault import query, render
from datavault.store import HANDLE_RE


def _handle_for(s, text_query):
    hits = query.search(s, text_query)["hits"]
    for h in hits:
        m = HANDLE_RE.findall(h["text"])
        if m:
            return m
    raise AssertionError("no handles found")


def test_render_resolves_locally_only(p2case):  # noqa: F811
    s = query.Session(p2case, None)
    try:
        hs = _handle_for(s, "backup nightly")
        host = next(h for h in hs if ":HOST:" in h)
        tpl = f"# Report\nBackup target: {host}\nUnknown: [[DV:PER:zzzzzz]]\n"
        out = render.render(s, "report.md", tpl)
        assert out["handles_resolved"] == 1 and out["unresolved"] == ["[[DV:PER:zzzzzz]]"]
        assert "srv-sql01" not in json.dumps(out)
        text = (p2case.out_dir / "report.md").read_text()
        assert "srv-sql01.corp.test" in text and host not in text
        assert oct((p2case.out_dir / "report.md").stat().st_mode)[-3:] == "600"
        assert render.list_out(s)["files"] == [{"file": "report.md", "bytes": out["bytes"]}]
    finally:
        s.close()


def test_render_yaml_escaping(p2case):  # noqa: F811
    s = query.Session(p2case, None)
    try:
        secret_h = s.st.add_entity("ORG", 'Acme: "x# y Ltd', "header")
        tpl = f'nodes:\n  - {{id: a, label: "{secret_h}"}}\n  - {{id: b, label: {secret_h}}}\n'
        render.render(s, "spec.yaml", tpl)
        data = yaml.safe_load((p2case.out_dir / "spec.yaml").read_text())
        assert [n["label"] for n in data["nodes"]] == ['Acme: "x# y Ltd', 'Acme: "x# y Ltd']
    finally:
        s.close()


@pytest.mark.parametrize("name", ["../x.md", "X.md", "a/b.md", "run.sh", ""])
def test_render_rejects_names(p2case, name):  # noqa: F811
    s = query.Session(p2case, None)
    try:
        with pytest.raises(query.QueryError):
            render.render(s, name, "x")
    finally:
        s.close()


def test_exec_allowlist_and_guarded_output(p2case, home):  # noqa: F811
    (home / "tools.yaml").write_text(yaml.safe_dump({"tools": {"echo": {
        "inputs": [".md"],
        "cmd": ["python3", "-c",
                "import sys,pathlib; p=pathlib.Path(sys.argv[1]); t=p.read_text(); "
                "pathlib.Path(p.stem + '.txt').write_text(t.upper()); print(t)",
                "{input}"]}}}))
    s = query.Session(p2case, None)
    try:
        host = "srv-sql01.corp.test"
        h = s.st.resolve_handle(host) if hasattr(s.st, "resolve_handle") else None
        h = h or next(e.handle for e in s.st.entities() if e.value == host)
        render.render(s, "r.md", f"host {h}\n")
        out = render.exec_tool(s, "echo", "r.md")
        assert out["exit_code"] == 0 and any(f["file"] == "r.txt" for f in out["produced"])
        # the tool printed the real host name; the guard turns it back into the handle
        assert host not in json.dumps(out) and h in out["stdout_tail"]
        with pytest.raises(query.QueryError, match="unknown tool"):
            render.exec_tool(s, "bash", "r.md")
        with pytest.raises(query.QueryError, match="not allowed"):
            render.exec_tool(s, "echo", "r.txt")
    finally:
        s.close()


def test_render_withholds_secrets(p2case):  # noqa: F811
    s = query.Session(p2case, None)
    try:
        hs = _handle_for(s, "password")
        sec = next((h for h in hs if ":SECRET:" in h), None)
        if sec is None:
            pytest.skip("no SECRET handle in the fixture")
        out = render.render(s, "s.md", f"pw: {sec}\n")
        assert out["withheld"] == 1 and out["handles_resolved"] == 0
        text = (p2case.out_dir / "s.md").read_text()
        assert "[withheld]" in text and SECRET not in text
    finally:
        s.close()
