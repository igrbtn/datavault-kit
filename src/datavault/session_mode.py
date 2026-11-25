"""Per-session vault mode, shared by the prompt guard and the file guard through a small
marker file keyed by the Claude Code session id.

default: the guards as they are (secrets and case values in prompts, data files on disk).
strict:  every file under the session's roots is read through the vault; the file guard turns
         each folder it touches into a case.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from .config import vault_home

_SID = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
_CMD = re.compile(r"^\s*/?vault\s+(on|strict|off|status|bypass)\b(.*)$",
                  re.IGNORECASE | re.DOTALL)


def default_roots() -> list[str]:
    """Folders that strict mode always covers besides cwd (DATAVAULT_STRICT_ROOTS, os.pathsep)."""
    return [r for r in os.environ.get("DATAVAULT_STRICT_ROOTS", "").split(os.pathsep) if r.strip()]


def _path(session_id: str) -> Path | None:
    if not session_id or not _SID.match(session_id):
        return None
    d = vault_home() / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{session_id}.json"


def get(session_id: str) -> dict:
    p = _path(session_id)
    if p is None or not p.is_file():
        return {"mode": "default"}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"mode": "default"}


def set_strict(session_id: str, cwd: str, extra_roots: list[str]) -> dict:
    roots = []
    for r in [cwd, *default_roots(), *extra_roots]:
        rp = str(Path(os.path.expanduser(r)).resolve())
        if rp not in roots and os.path.isdir(rp):
            roots.append(rp)
    state = {"mode": "strict", "roots": roots, "since": time.strftime("%Y-%m-%dT%H:%M:%S")}
    p = _path(session_id)
    if p is not None:
        p.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
        p.chmod(0o600)
    return state


def set_bypass(session_id: str) -> dict:
    """Guards only warn in this session: the human has decided this data may go to the cloud."""
    state = {"mode": "bypass", "since": time.strftime("%Y-%m-%dT%H:%M:%S")}
    p = _path(session_id)
    if p is not None:
        p.write_text(json.dumps(state), encoding="utf-8")
        p.chmod(0o600)
    return state


def clear(session_id: str) -> None:
    p = _path(session_id)
    if p is not None and p.is_file():
        p.unlink()


def parse_command(prompt: str) -> tuple[str, list[str]] | None:
    """'/vault on [path ...]' | '/vault off' | '/vault status' -> (verb, paths)."""
    m = _CMD.match(prompt or "")
    if not m:
        return None
    verb = m.group(1).lower()
    return ("strict" if verb == "on" else verb), m.group(2).split()


STRICT_CONTEXT = (
    "DataVault strict mode is ON for this session. Every document under the session roots "
    "is customer data: do not Read, cat, grep or parse files there; the file guard will refuse "
    "and create a case instead. Work through the datavault MCP tools (cases, status, schema, "
    "search, read, rows, aggregate, extract, describe), write reports with handles and produce "
    "files with render/exec. Roots: {roots}"
)
