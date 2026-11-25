"""Prompt guard: the same DLP for what the human types.

A Claude Code UserPromptSubmit hook runs this before the prompt leaves the machine. Two
checks: regex DLP (secrets, cards, ids, mail, phones, addresses) and known values of every
ingested case (the sweeper). A blocked prompt is shown back with secrets cut out and case
values replaced by their handles, so the human can paste that version instead.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import injection, session_mode
from .cases import list_cases
from .config import vault_home
from .detect import _secret_like, is_dict_word, regex_detect
from .ingest import store_path
from .store import HANDLE_RE, Store, Sweeper

# regex findings: what blocks and what only warns
BLOCK_TYPES = {"SECRET", "BANK", "ID"}
WARN_TYPES = {"EMAIL", "PHONE", "IP"}
MAX_PROMPT = 400_000
# harness-generated turns (task and monitor notifications, session events) are not typed by a
# human; blocking them silently starves the agent of its own background results
HARNESS_TAGS = ("<task-notification>", "<side-sessions-event>", "<system-reminder",
                "<agent-message", "<ci-monitor-event>", "<local-command-")
# ids the harness prints that look like secrets to an entropy detector
_HARNESS_IDS = [re.compile(r"^toolu_[A-Za-z0-9]{8,}$"), re.compile(r"^msg_[A-Za-z0-9]{8,}$"),
                re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")]
# a prompt is one paragraph: KEY=value pairs sit mid-line, unlike in a config file
_INLINE_KV = re.compile(r"(?i)(?<![\w-])[A-Z0-9_]*(?:PASS|PASSWORD|PASSWD|SECRET|TOKEN|KEY|PWD|"
                        r"CREDENTIAL)[A-Z0-9_]*\s*[=:]\s*['\"]?([^'\"\s#,;]{6,})")
# user:password@host inside a URL
_PLACEHOLDER = re.compile(r"^\[[A-Z][A-Z_]*(?:_\d+)?\]$")  # [SECRET], [URL_PASSWORD_2]
_KEY_NAME = re.compile(r"(?i)([A-Z0-9_]*(?:PASS|PASSWORD|PASSWD|SECRET|TOKEN|KEY|PWD|CREDENTIAL)"
                       r"[A-Z0-9_]*)\s*[=:]\s*['\"]?$")


def _label_for_key(prefix: str) -> str:
    """AWS_SECRET_ACCESS_KEY=... -> AWS_SECRET_ACCESS_KEY; a bare "password:" -> PASSWORD."""
    m = _KEY_NAME.search(prefix[-80:])
    name = (m.group(1) if m else "SECRET").upper().strip("_")
    return re.sub(r"[^A-Z0-9_]", "_", name)[:32] or "SECRET"
_URL_CRED = re.compile(r"\b[a-z][a-z0-9+.-]*://[^:/\s@]*:([^@\s]{4,})@")  # redis://:pw@ too


@dataclass
class Policy:
    mode: str = "block"  # block | warn | off
    block_types: set[str] = field(default_factory=lambda: set(BLOCK_TYPES))
    warn_types: set[str] = field(default_factory=lambda: set(WARN_TYPES))
    cases: list[str] | None = None  # None = every case
    allow: list[re.Pattern[str]] = field(default_factory=list)
    injection: str = "warn"  # warn | block | off

    @classmethod
    def load(cls, path: Path | None = None) -> Policy:
        path = path or vault_home() / "promptguard.yaml"
        if not path.is_file():
            return cls()
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        p = cls(mode=raw.get("mode", "block"))
        if "block_types" in raw:
            p.block_types = set(raw["block_types"])
        if "warn_types" in raw:
            p.warn_types = set(raw["warn_types"])
        if raw.get("cases"):
            p.cases = list(raw["cases"])
        p.allow = [re.compile(x) for x in raw.get("allow", [])]
        p.injection = raw.get("injection", "warn")
        return p


@dataclass
class Verdict:
    decision: str  # block | warn | ok
    regex: Counter = field(default_factory=Counter)
    cases: dict[str, Counter] = field(default_factory=dict)
    masked: str = ""
    seconds: float = 0.0
    injection: dict | None = None
    verdicts: dict = field(default_factory=dict)

    def summary(self) -> str:
        parts = []
        if self.injection:
            label = "injection" if self.injection["level"] == "injection" else "possible injection"
            parts.append(f"{label}: " + ", ".join(self.injection["rules"]))
        if self.regex:
            parts.append("DLP: " + ", ".join(f"{t} x{n}" for t, n in sorted(self.regex.items())))
        for case, c in self.cases.items():
            parts.append(f"{case}: " + ", ".join(f"{t} x{n}" for t, n in sorted(c.items())))
        return "; ".join(parts)


def _weak(e) -> bool:
    """Entities that are too common to block a prompt on (a dictionary word typed as a login)."""
    if e.alias or len(e.value) < 5:
        return True
    return e.type in ("ACC", "PER", "ORG") and len(e.value.split()) == 1 and is_dict_word(e.value)


def _case_sweepers(policy: Policy) -> list[tuple[str, Sweeper]]:
    out = []
    for c in list_cases():
        if policy.cases is not None and c.name not in policy.cases:
            continue
        path = store_path(c)
        if not path.exists():
            continue
        try:
            st = Store(path, readonly=True, timeout=1)
        except sqlite3.OperationalError:
            continue  # being ingested right now: a prompt must not wait on it
        try:
            ents = [e for e in st.entities() if not _weak(e)]
        except sqlite3.OperationalError:
            continue
        finally:
            st.close()
        if ents:
            out.append((c.name, Sweeper(ents)))
    return out


def scan(text: str, policy: Policy | None = None) -> Verdict:
    policy = policy or Policy.load()
    t0 = time.monotonic()
    if policy.mode == "off" or not text.strip() or text.lstrip().startswith(HARNESS_TAGS):
        return Verdict("ok", masked=text)
    text = text[:MAX_PROMPT]
    allowed = lambda v: any(p.search(v) for p in policy.allow + _HARNESS_IDS)  # noqa: E731

    # 1. known case values -> handles
    v = Verdict("ok")
    masked = text
    for name, sw in _case_sweepers(policy):
        prev = Counter(HANDLE_RE.findall(masked))
        swept = sw.apply(masked)
        new = Counter(HANDLE_RE.findall(swept)) - prev
        hits = Counter(h.split(":")[1] for h in new.elements())
        if hits:
            v.cases[name] = hits
            masked = swept
    # 2. regex DLP on what is left
    # key=value and URL passwords first, so a later whole-token hit keeps the key name
    found: dict[str, tuple[str, str]] = {}  # value -> (type, label)
    for rx in (_INLINE_KV, _URL_CRED):
        for m in rx.finditer(masked):
            val = m.group(1)
            if _PLACEHOLDER.match(val) or allowed(val):
                continue  # the masked copy pasted back must pass
            if rx is _URL_CRED:
                found.setdefault(val, ("SECRET", "URL_PASSWORD"))
            elif _secret_like(val):
                found.setdefault(val, ("SECRET", _label_for_key(masked[:m.start(1)])))
    counters: Counter = Counter()
    masked, n = _replace(masked, found, counters)
    if n:
        v.regex["SECRET"] += n
    found = {}
    for d in regex_detect(masked):
        if (d.type in policy.block_types | policy.warn_types and not allowed(d.value)
                and not _PLACEHOLDER.match(d.value)):
            det = d.source.split("/", 1)[-1]
            label = d.type if re.fullmatch(r"[a-z]+\d+", det) else det.upper()
            found.setdefault(d.value, (d.type, label))
    for typ, _ in found.values():
        v.regex[typ] += 1
    # warn-only types (an IP in a ping) stay readable in the suggested copy
    masked, _ = _replace(masked, {k: tl for k, tl in found.items()
                                  if tl[0] in policy.block_types}, counters)
    v.masked = masked
    inj = injection.scan(text)
    if policy.injection != "off" and inj.level != "clean":
        v.injection = inj.as_dict()
    v.verdicts = {
        "secrets": "block" if any(t in policy.block_types and n for t, n in v.regex.items())
        else "ok",
        "sensitive": "warn" if any(t in policy.warn_types and n for t, n in v.regex.items())
        else "ok",
        "case_values": "block" if v.cases else "ok",
        "injection": "ok" if v.injection is None else (
            "block" if policy.injection == "block" and inj.level == "injection" else "warn"),
    }
    block = bool(v.cases) or any(t in policy.block_types for t in v.regex) or (
        v.injection is not None and policy.injection == "block" and inj.level == "injection")
    warn = any(t in policy.warn_types for t in v.regex) or v.injection is not None
    if policy.mode == "warn":
        v.decision = "warn" if (block or warn) else "ok"
    else:
        v.decision = "block" if block else ("warn" if warn else "ok")
    v.seconds = round(time.monotonic() - t0, 3)
    return v


def _replace(text: str, found: dict[str, tuple[str, str]], counters: Counter) -> tuple[str, int]:
    """Distinct values get numbered, typed placeholders: [URL_PASSWORD_1], [AWS_KEY_2]."""
    n = 0
    for value, (_typ, label) in sorted(found.items(), key=lambda kv: -len(kv[0])):
        if value in text:
            counters[label] += 1
            text = text.replace(value, f"[{label}_{counters[label]}]")
            n += 1
    return text, n


def _log(line: str, event: dict | None = None) -> None:
    try:
        home = vault_home()
        home.mkdir(parents=True, exist_ok=True)
        p = home / "promptguard.log"
        with p.open("a", encoding="utf-8") as fh:
            fh.write(time.strftime("%Y-%m-%d %H:%M:%S ") + line + "\n")
        p.chmod(0o600)
        if event:
            j = home / "promptguard.jsonl"
            with j.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), **event},
                                    ensure_ascii=False) + "\n")
            j.chmod(0o600)
    except OSError:
        pass


def _mode_command(cmd: tuple[str, list[str]], data: dict, stdout) -> int:
    verb, paths = cmd
    sid = data.get("session_id") or ""
    if verb == "strict":
        state = session_mode.set_strict(sid, data.get("cwd") or os.getcwd(), paths)
        msg = "DataVault: strict mode ON for this session; roots: " + ", ".join(state["roots"])
        ctx = session_mode.STRICT_CONTEXT.format(roots=", ".join(state["roots"]))
    elif verb == "bypass":
        session_mode.set_bypass(sid)
        msg = ("DataVault: BYPASS for this session - guards only warn, files are read directly, "
               "nothing is masked. '/vault off' restores the default guards.")
        ctx = ("DataVault bypass is on for this session: the human decided this data may be "
               "handled directly. Guards still report what they see.")
    elif verb == "off":
        session_mode.clear(sid)
        msg = "DataVault: default mode (strict off, bypass off); default guards on"
        ctx = "DataVault is back to default mode; the default guards apply."
    else:
        state = session_mode.get(sid)
        msg = f"DataVault: mode {state.get('mode')}"
        if state.get("mode") == "strict":
            msg += "; roots: " + ", ".join(state.get("roots", []))
        ctx = msg
    _log(msg, {"decision": "mode", "summary": msg, "verdicts": {}, "masked": None})
    json.dump({"systemMessage": msg,
               "hookSpecificOutput": {"hookEventName": "UserPromptSubmit",
                                      "additionalContext": ctx}}, stdout, ensure_ascii=False)
    return 0


def hook_main(stdin=None, stdout=None) -> int:
    """Claude Code hook entry: UserPromptSubmit JSON in, decision JSON out. Fails open."""
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    try:
        data = json.load(stdin)
        text = data.get("prompt") or ""
        cmd = session_mode.parse_command(text)
        if cmd:
            return _mode_command(cmd, data, stdout)
        policy = Policy.load()
        if session_mode.get(data.get("session_id") or "").get("mode") == "bypass":
            policy.mode = "warn" if policy.mode != "off" else "off"
        v = scan(text, policy)
    except Exception as e:  # noqa: BLE001 - a broken guard must not lock the user out
        _log(f"error {type(e).__name__}: {e}")
        return 0
    if v.decision == "ok":
        return 0
    _log(f"{v.decision} {v.summary()} ({v.seconds}s)",
         {"decision": v.decision, "summary": v.summary(), "seconds": v.seconds,
          "verdicts": v.verdicts, "masked": v.masked if v.decision == "block" else None})
    if v.decision == "block":
        reason = ("DataVault prompt guard: the prompt was not sent. Found " + v.summary() +
                  ".\nSame prompt with secrets removed and case values as handles:\n\n" + v.masked)
        json.dump({"decision": "block", "reason": reason}, stdout, ensure_ascii=False)
    else:
        json.dump({"systemMessage": "DataVault prompt guard: " + v.summary() +
                   " in the prompt (sent as typed)"}, stdout, ensure_ascii=False)
    return 0
