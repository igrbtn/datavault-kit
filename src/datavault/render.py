"""P3: re-identification happens only here, on the local side.

The agent sends a template with handles; real values are written into <case>/out/ and
never returned. exec runs allow-listed local tools (diagram generators, pandoc) on those
files; their console output goes back through the output guard.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

import yaml

from .config import vault_home
from .query import QueryError, Session
from .store import HANDLE_RE

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,79}$")
TEXT_FORMATS = {".md", ".txt", ".yaml", ".yml", ".csv", ".xml", ".drawio", ".json", ".html"}
MAX_TEMPLATE = 2_000_000
EXEC_TIMEOUT = 300
NEVER_RENDER = {"SECRET"}
BUNDLED_TOOLS = Path(__file__).with_name("tools.yaml")


def _out_dir(s: Session) -> Path:
    out = s.case.out_dir
    out.mkdir(parents=True, exist_ok=True)
    out.chmod(0o700)
    return out


def _check_name(name: str, allowed: set[str] | None = None) -> str:
    if not NAME_RE.match(name or "") or ".." in name:
        raise QueryError("file name: lowercase [a-z0-9._-], no paths")
    ext = Path(name).suffix.lower()
    if allowed is not None and ext not in allowed:
        raise QueryError(f"extension {ext or '(none)'} not allowed: {sorted(allowed)}")
    return name


def _inside_double_quotes(text: str, pos: int) -> bool:
    line_start = text.rfind("\n", 0, pos) + 1
    seg = text[line_start:pos]
    return (seg.count('"') - seg.count('\\"')) % 2 == 1


def _yaml_value(value: str, quoted: bool) -> str:
    if quoted:
        return json.dumps(value, ensure_ascii=False)[1:-1]
    dumped = yaml.safe_dump(value, allow_unicode=True, default_style=None).strip()
    return dumped.removesuffix("\n...").removesuffix("...").strip()


def _escape_for(ext: str, text: str, pos: int, value: str) -> str:
    if ext in (".yaml", ".yml"):
        return _yaml_value(value, _inside_double_quotes(text, pos))
    if ext in (".xml", ".drawio", ".html"):
        return xml_escape(value, {'"': "&quot;"})
    if ext == ".json":
        return json.dumps(value, ensure_ascii=False)[1:-1]
    if ext == ".csv" and any(c in value for c in ',;"\n'):
        return '"' + value.replace('"', '""') + '"'
    return value


def render(s: Session, name: str, content: str) -> dict:
    name = _check_name(name, TEXT_FORMATS)
    if len(content) > MAX_TEMPLATE:
        raise QueryError("template too large")
    ext = Path(name).suffix.lower()
    cache: dict[str, str | None] = {}
    unresolved: list[str] = []
    withheld = 0
    resolved = 0
    parts, last = [], 0
    for m in HANDLE_RE.finditer(content):
        h = m.group(0)
        parts.append(content[last:m.start()])
        if h.split(":")[1] in NEVER_RENDER:
            # a password belongs in nobody's report; the human looks it up in the source
            withheld += 1
            parts.append("[withheld]")
            last = m.end()
            continue
        if h not in cache:
            cache[h] = s.st.resolve(h)
        value = cache[h]
        if value is None:
            unresolved.append(h)
            parts.append(h)
        else:
            parts.append(_escape_for(ext, content, m.start(), value))
            resolved += 1
        last = m.end()
    parts.append(content[last:])
    data = "".join(parts).encode("utf-8")
    path = _out_dir(s) / name
    path.write_bytes(data)
    path.chmod(0o600)
    out = {"file": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()[:16],
           "handles_resolved": resolved, "distinct_handles": len(cache),
           "unresolved": sorted(set(unresolved)), "withheld": withheld,
           "redacted_markers": content.count("[[REDACTED]]")}
    s.log("render", {"name": name, "template_chars": len(content)}, out, None)
    return out


def list_out(s: Session) -> dict:
    out_dir = _out_dir(s)
    files = []
    for p in sorted(out_dir.rglob("*")):
        if p.is_file():
            files.append({"file": p.relative_to(out_dir).as_posix(), "bytes": p.stat().st_size})
    return {"files": files[:500]}


def load_tools() -> dict:
    local = vault_home() / "tools.yaml"
    path = local if local.is_file() else BUNDLED_TOOLS
    return (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("tools", {})


def exec_tool(s: Session, tool: str, input_name: str) -> dict:
    tools = load_tools()
    if tool not in tools:
        raise QueryError(f"unknown tool {tool!r}; available: {sorted(tools)}")
    spec = tools[tool]
    allowed = {e.lower() for e in spec.get("inputs", [])}
    name = _check_name(input_name, allowed or None)
    out_dir = _out_dir(s)
    if not (out_dir / name).is_file():
        raise QueryError(f"{name} not found in out/ (render it first)")
    stem = Path(name).stem
    subst = {"{input}": name, "{stem}": stem, "{outdir}": str(out_dir)}
    cmd = []
    for arg in spec["cmd"]:
        for k, v in subst.items():
            arg = arg.replace(k, v)
        cmd.append(os.path.expanduser(arg))
    before = {p: p.stat().st_mtime for p in out_dir.rglob("*") if p.is_file()}
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin:/opt/homebrew/bin"),
           "HOME": os.environ.get("HOME", ""), "LANG": "en_US.UTF-8"}
    try:
        proc = subprocess.run(cmd, cwd=out_dir, capture_output=True, text=True,
                              timeout=EXEC_TIMEOUT, env=env, check=False)
        code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        code, stdout, stderr = -1, "", f"timeout after {EXEC_TIMEOUT}s"
    except FileNotFoundError as e:
        raise QueryError(f"tool binary not found: {e.filename}") from e
    produced = []
    for p in sorted(out_dir.rglob("*")):
        if p.is_file() and (p not in before or p.stat().st_mtime != before[p]):
            p.chmod(0o600)
            produced.append({"file": p.relative_to(out_dir).as_posix(),
                             "bytes": p.stat().st_size})
    g = s.guard(" ".join([tool, name]))
    out = {"tool": tool, "input": name, "exit_code": code, "produced": produced,
           "stdout_tail": g.text(stdout[-1500:]), "stderr_tail": g.text(stderr[-1500:])}
    s.log("exec", {"tool": tool, "input": name}, out, g)
    return out
