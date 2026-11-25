import io
import json

from datavault import fileguard, promptguard, session_mode
from datavault.cases import list_cases
from datavault.fileguard import FilePolicy, decide


def test_vault_command_sets_and_clears_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("DATAVAULT_HOME", str(tmp_path / "home"))
    work = tmp_path / "work"
    work.mkdir()
    out = io.StringIO()
    promptguard.hook_main(io.StringIO(json.dumps(
        {"session_id": "s1", "cwd": str(work), "prompt": "/vault on"})), out)
    d = json.loads(out.getvalue())
    assert "strict mode ON" in d["systemMessage"]
    assert "datavault MCP" in d["hookSpecificOutput"]["additionalContext"]
    st = session_mode.get("s1")
    assert st["mode"] == "strict" and str(work.resolve()) in st["roots"]
    assert session_mode.get("other")["mode"] == "default"
    out = io.StringIO()
    promptguard.hook_main(io.StringIO(json.dumps({"session_id": "s1", "prompt": "vault off"})), out)
    assert session_mode.get("s1")["mode"] == "default"
    assert session_mode.parse_command("vault of this") is None


def test_strict_mode_guards_documents_but_not_code(tmp_path, monkeypatch):
    monkeypatch.setenv("DATAVAULT_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(fileguard, "_start_ingest", lambda case: None)
    work = tmp_path / "proj"
    work.mkdir()
    (work / "notes.md").write_text("customer notes")
    (work / "plan.md").write_text("more notes")
    (work / "tool.py").write_text("print(1)")
    pol = FilePolicy()
    pol.allow = []
    # default mode: markdown passes
    assert decide("Read", {"file_path": str(work / "notes.md")}, str(work), pol, "s2") is None
    session_mode.set_strict("s2", str(work), [])
    d = decide("Read", {"file_path": str(work / "notes.md")}, str(work), pol, "s2")
    assert d["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert decide("Read", {"file_path": str(work / "tool.py")}, str(work), pol, "s2") is None
    # a second file in the same folder joins the same case
    decide("Bash", {"command": f"cat {work / 'plan.md'}"}, str(work), pol, "s2")
    cases = list_cases()
    assert len(cases) == 1 and sorted(cases[0].include) == ["notes.md", "plan.md"]
    # outside the roots the default rules still apply
    other = tmp_path / "elsewhere" / "x.md"
    other.parent.mkdir()
    other.write_text("x")
    assert decide("Read", {"file_path": str(other)}, str(work), pol, "s2") is None


def test_bypass_only_warns(tmp_path, monkeypatch):
    monkeypatch.setenv("DATAVAULT_HOME", str(tmp_path / "home"))
    work = tmp_path / "w"
    work.mkdir()
    f = work / "export.csv"
    f.write_text("a,b\n")
    out = io.StringIO()
    promptguard.hook_main(io.StringIO(json.dumps(
        {"session_id": "s3", "cwd": str(work), "prompt": "/vault bypass"})), out)
    assert "BYPASS" in json.loads(out.getvalue())["systemMessage"]
    pol = FilePolicy()
    pol.allow = []
    d = decide("Read", {"file_path": str(f)}, str(work), pol, "s3")
    assert "hookSpecificOutput" not in d and "bypass" in d["systemMessage"]
    assert list_cases() == []
    out = io.StringIO()
    promptguard.hook_main(io.StringIO(json.dumps(
        {"session_id": "s3", "prompt": "JWT_SECRET=9f8a7b6c5d4e3f2a1b0c"})), out)
    d = json.loads(out.getvalue())
    assert "decision" not in d and "systemMessage" in d
    promptguard.hook_main(io.StringIO(json.dumps({"session_id": "s3", "prompt": "/vault off"})),
                          io.StringIO())
    assert decide("Read", {"file_path": str(f)}, str(work), pol, "s3")["hookSpecificOutput"]
