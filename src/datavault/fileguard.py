"""File guard: a PreToolUse hook for Read and Bash.

The agent must not open a data file (xlsx, csv, docx, pdf, eml, ...) outside the allowed
folders: such a file goes into an auto-created case, an ingest starts in the background and
the tool call is denied with a pointer to the datavault MCP tools. The hook sees only
paths, never content; it fails open on its own errors.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import session_mode
from .cases import Case, CaseError, add_include, init_case, list_cases, load_case
from .config import vault_home

DATA_EXT = {".xlsx", ".xls", ".xlsm", ".csv", ".tsv", ".docx", ".doc", ".pdf", ".eml", ".msg"}
# in strict mode these are still read directly: the agent has to see code and config to work
CODE_EXT = {".py", ".ps1", ".sh", ".js", ".ts", ".cs", ".go", ".rs", ".java", ".yaml", ".yml",
            ".toml", ".ini", ".json", ".cfg", ".conf", ".gitignore", ".lock", ".html", ".css"}
# any file-looking token; guarded() decides by mode and extension
_PATH_TOKEN = re.compile(
    r"""(?:^|[\s"'=(,:])((?:~|\.{0,2}/)?[^\s"'<>|;&()]+?\.[A-Za-z0-9]{1,6})(?=$|[\s"'),;:])""")


@dataclass
class FilePolicy:
    mode: str = "block"  # block | warn | off
    extensions: set[str] = field(default_factory=lambda: set(DATA_EXT))
    allow: list[re.Pattern[str]] = field(default_factory=list)  # paths that stay readable

    @classmethod
    def load(cls, path: Path | None = None) -> FilePolicy:
        path = path or vault_home() / "promptguard.yaml"
        p = cls()
        # the vault's own repo fixtures and its home are never customer data to guard
        p.allow = [re.compile(re.escape(str(vault_home())) + "/"),
                   re.compile(r"/(?:DataVault|datavault-kit)/tests/fixtures/")]
        if not path.is_file():
            return p
        raw = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("file_guard") or {}
        p.mode = raw.get("mode", "block")
        if "extensions" in raw:
            p.extensions = {e if e.startswith(".") else "." + e for e in raw["extensions"]}
        p.allow += [re.compile(x) for x in raw.get("allow", [])]
        return p


def candidate_paths(tool: str, tool_input: dict, cwd: str) -> list[Path]:
    if tool == "Read":
        raw = [str(tool_input.get("file_path", ""))]
    elif tool == "Bash":
        raw = [m.group(1) for m in _PATH_TOKEN.finditer(str(tool_input.get("command", "")))]
    else:
        raw = []
    out = []
    for r in raw:
        if not r:
            continue
        p = Path(os.path.expanduser(r))
        if not p.is_absolute():
            p = Path(cwd) / p
        out.append(p)
    return out


def guarded(p: Path, policy: FilePolicy, roots: list[str] | None = None) -> bool:
    if not p.is_file():
        return False
    s = str(p.resolve())
    if any(rx.search(s) for rx in policy.allow):
        return False
    if roots and any(s.startswith(r.rstrip("/") + "/") for r in roots):
        return p.suffix.lower() not in CODE_EXT  # strict: everything but code
    return p.suffix.lower() in policy.extensions


def _case_for(p: Path) -> tuple[Case | None, bool]:
    """(case covering this file's folder, whether the file is already in it)."""
    for c in list_cases():
        if c.source_dir and Path(c.source_dir).resolve() == p.parent.resolve():
            return c, bool(c.include) and p.name in c.include
    return None, False


def _new_case(p: Path) -> Case:
    # the case id is visible to the agent: never derive it from the file name
    base = time.strftime("auto-%Y%m%d-%H%M")
    name, n = base, 1
    while True:
        try:
            return init_case(name, title=f"auto: {p.suffix.lower()} attachment",
                             description="auto-created by the file guard",
                             source_dir=str(p.parent), include=[p.name])
        except CaseError:
            n += 1
            name = f"{base}-{n}"


def _start_ingest(case: Case) -> None:
    log = case.root / "ingest.log"
    with log.open("ab") as fh:
        subprocess.Popen([sys.executable, "-m", "datavault.cli", "ingest", case.name],
                         stdout=fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                         start_new_session=True, env={**os.environ, "PYTHONPATH": ""})
    log.chmod(0o600)


def decide(tool: str, tool_input: dict, cwd: str, policy: FilePolicy | None = None,
           session_id: str | None = None) -> dict | None:
    """None = let the call through; else a PreToolUse decision dict."""
    policy = policy or FilePolicy.load()
    if policy.mode == "off":
        return None
    state = session_mode.get(session_id or "")
    roots = state.get("roots") if state.get("mode") == "strict" else None
    bypass = state.get("mode") == "bypass"
    hits = [p for p in candidate_paths(tool, tool_input, cwd) if guarded(p, policy, roots)]
    if not hits:
        return None
    if bypass:
        return {"systemMessage": "DataVault file guard (bypass): reading data file(s) directly: "
                + ", ".join(p.name for p in hits)}
    notes = []
    for p in hits:
        case, covered = _case_for(p)
        started = False
        if case is None:
            case = _new_case(p)
            _start_ingest(case)
            started = True
        elif not covered:
            add_include(case.name, p.name)
            case = load_case(case.name)
            _start_ingest(case)
            started = True
        elif not (case.root / "store.db").exists() and not (case.root / "ingest.log").exists():
            _start_ingest(case)
            started = True
        notes.append(f"{p.name} -> case {case.name}" + (" (ingest started)" if started
                                                         else " (already ingested)"))
    reason = ("DataVault file guard: data files are not read directly. " + "; ".join(notes) +
              ". Work through the datavault MCP tools: status(case) until ingested, then "
              "schema(case, 'all'), aggregate, rows, search, extract; write with handles.")
    if policy.mode == "warn":
        return {"systemMessage": reason}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": reason},
            "systemMessage": reason}


def _log(line: str) -> None:
    try:
        home = vault_home()
        home.mkdir(parents=True, exist_ok=True)
        p = home / "promptguard.jsonl"
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "decision": "block",
                                 "summary": line, "verdicts": {"file_guard": "block"},
                                 "masked": None}, ensure_ascii=False) + "\n")
        p.chmod(0o600)
    except OSError:
        pass


def hook_main(stdin=None, stdout=None) -> int:
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    try:
        data = json.load(stdin)
        d = decide(data.get("tool_name", ""), data.get("tool_input") or {},
                   data.get("cwd") or os.getcwd(), session_id=data.get("session_id"))
    except Exception as e:  # noqa: BLE001 - never lock the user out
        try:
            (vault_home() / "promptguard.log").open("a").write(
                time.strftime("%Y-%m-%d %H:%M:%S ") + f"file guard error {type(e).__name__}\n")
        except OSError:
            pass
        return 0
    if d is None:
        return 0
    _log(d.get("systemMessage", ""))
    json.dump(d, stdout, ensure_ascii=False)
    return 0
