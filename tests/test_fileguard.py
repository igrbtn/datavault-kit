import io
import json

from datavault import fileguard
from datavault.cases import list_cases
from datavault.fileguard import FilePolicy, candidate_paths, decide


def _policy(tmp_path):
    p = FilePolicy()
    p.allow = [__import__("re").compile(str(tmp_path / "ok") + "/")]
    return p


def test_bash_paths_are_extracted(tmp_path):
    cmd = ("python -c \"import pandas as pd; pd.read_excel('data/RVTools_x.xlsx')\" && "
           "head -2 ./report.csv; cat notes.txt")
    got = [p.name for p in candidate_paths("Bash", {"command": cmd}, str(tmp_path))]
    assert got == ["RVTools_x.xlsx", "report.csv", "notes.txt"]  # guarded() filters by mode


def test_data_file_outside_allowed_dirs_is_denied_and_cased(tmp_path, monkeypatch):
    monkeypatch.setenv("DATAVAULT_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(fileguard, "_start_ingest", lambda case: None)
    f = tmp_path / "inbox" / "Customer_Export.xlsx"
    f.parent.mkdir()
    f.write_bytes(b"x")
    d = decide("Read", {"file_path": str(f)}, str(tmp_path), _policy(tmp_path))
    assert d["hookSpecificOutput"]["permissionDecision"] == "deny"
    cases = list_cases()
    assert len(cases) == 1 and cases[0].name.startswith("auto-")
    assert "Customer_Export" not in cases[0].name and cases[0].include == [f.name]
    # the same file again reuses the case instead of creating another
    d2 = decide("Bash", {"command": f"head {f}"}, str(tmp_path), _policy(tmp_path))
    assert d2 is not None and len(list_cases()) == 1


def test_allowed_dirs_code_files_and_missing_files_pass(tmp_path, monkeypatch):
    monkeypatch.setenv("DATAVAULT_HOME", str(tmp_path / "home"))
    ok = tmp_path / "ok"
    ok.mkdir()
    (ok / "fixture.csv").write_text("a,b\n")
    pol = _policy(tmp_path)
    assert decide("Read", {"file_path": str(ok / "fixture.csv")}, str(tmp_path), pol) is None
    assert decide("Read", {"file_path": str(tmp_path / "main.py")}, str(tmp_path), pol) is None
    assert decide("Bash", {"command": "ls missing.xlsx"}, str(tmp_path), pol) is None


def test_hook_contract_fails_open(tmp_path, monkeypatch):
    monkeypatch.setenv("DATAVAULT_HOME", str(tmp_path / "home"))
    out = io.StringIO()
    assert fileguard.hook_main(io.StringIO("garbage"), out) == 0 and out.getvalue() == ""
    out = io.StringIO()
    rc = fileguard.hook_main(io.StringIO(json.dumps(
        {"tool_name": "Read", "tool_input": {"file_path": str(tmp_path / "x.py")}})), out)
    assert rc == 0 and out.getvalue() == ""
