"""P4: the vault is where every customer's data ends up, so it is the asset to protect.

`report()` tells what the host does for it (FileVault, permissions, hooks) and what still
leaks around it (LM Studio prompt logs). SQLite itself is not encrypted on purpose: the
sweeper needs plaintext values to find them in text, so at-rest protection is the disk's
(FileVault) plus 700/600 permissions, and the report says whether both hold.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

from .config import vault_home

LMSTUDIO_LOGS = Path.home() / ".lmstudio" / "server-logs"
CLAUDE_SETTINGS = Path.home() / ".claude" / "settings.json"


def _mode(p: Path) -> str:
    try:
        return oct(stat.S_IMODE(p.stat().st_mode))
    except OSError:
        return "missing"


def _filevault() -> str:
    try:
        out = subprocess.run(["fdesetup", "status"], capture_output=True, text=True,
                             timeout=5).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    return "on" if "FileVault is On" in out else ("off" if out else "unknown")


def _hooks() -> dict:
    try:
        cfg = json.loads(CLAUDE_SETTINGS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"prompt_guard": False, "file_guard": False}
    blob = json.dumps(cfg.get("hooks", {}))
    return {"prompt_guard": "hook-prompt" in blob, "file_guard": "hook-file" in blob}


def _dir_size(p: Path) -> int:
    return sum(f.stat().st_size for f in p.rglob("*") if f.is_file()) if p.is_dir() else 0


def report() -> dict:
    home = vault_home()
    loose = []
    if home.is_dir():
        for p in home.rglob("*"):
            m = stat.S_IMODE(p.stat().st_mode) if p.exists() else 0
            if m & 0o077:  # group/other bits set
                loose.append(str(p.relative_to(home)))
    return {
        "home": str(home),
        "home_mode": _mode(home),
        "loose_permissions": loose[:20],
        "filevault": _filevault(),
        "hooks": _hooks(),
        "lmstudio_logs": {"path": str(LMSTUDIO_LOGS), "present": LMSTUDIO_LOGS.is_dir(),
                          "bytes": _dir_size(LMSTUDIO_LOGS)},
    }


def tighten() -> dict:
    """chmod the vault home to 700 dirs / 600 files; returns what changed."""
    home = vault_home()
    changed = 0
    if home.is_dir():
        os.chmod(home, 0o700)
        for p in home.rglob("*"):
            want = 0o700 if p.is_dir() else 0o600
            if stat.S_IMODE(p.stat().st_mode) != want:
                os.chmod(p, want)
                changed += 1
    return {"changed": changed}


def clean_lmstudio_logs() -> dict:
    """LM Studio writes every prompt (raw chunks at NER/extract) to its server logs."""
    if not LMSTUDIO_LOGS.is_dir():
        return {"removed_bytes": 0}
    size = _dir_size(LMSTUDIO_LOGS)
    for p in LMSTUDIO_LOGS.iterdir():
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink()
    return {"removed_bytes": size}
