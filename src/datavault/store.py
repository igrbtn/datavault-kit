"""Handle store (SQLite in the case dir) and the sweep that pseudonymizes text.

One row per surface value; several values may share a handle (person name forms).
Docs/chunks are rebuilt on every ingest, entity rows are kept.
"""
from __future__ import annotations

import json
import re
import secrets
import sqlite3
from array import array
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

HANDLE_RE = re.compile(r"\[\[DV:[A-Z]+:[a-z2-7]{6}\]\]")
MIN_SWEEP_LEN = 3  # shorter values would match everywhere
_B32 = "abcdefghijklmnopqrstuvwxyz234567"
_CYR_WORD = re.compile("^[\u0400-\u04ff]+$")
_CYR_ENDING = "[\u0430-\u044f\u0451]{0,3}"
_CYR_VOWELS = "\u0430\u044f\u043e"
_TYPE_PRIORITY = ["SECRET", "BANK", "ID", "EMAIL", "PHONE", "IP", "ACC", "HOST", "PER", "ORG",
                  "ADDR", "AMT"]

# generic values that would wreck readability if swept everywhere
STOP_VALUES = {
    "admin", "administrator", "root", "user", "users", "guest", "test", "default", "public",
    "private", "none", "null", "true", "false", "password", "secret", "localhost", "system",
    "service", "server", "host", "domain", "corp", "local", "support", "operator", "manager",
}
HEADER_TRUSTED = {"SECRET", "ACC", "EMAIL", "PHONE", "ID", "BANK"}

# well-known AD groups and accounts: not personal data, needed to reason about privileges
STOP_VALUES |= {
    "domain admins", "enterprise admins", "schema admins", "administrators", "domain users",
    "domain computers", "domain controllers", "domain guests", "account operators",
    "backup operators", "server operators", "print operators", "remote desktop users",
    "dnsadmins", "dnsupdateproxy", "protected users", "group policy creator owners",
    "cert publishers", "key admins", "enterprise key admins", "read-only domain controllers",
    "enterprise read-only domain controllers", "cloneable domain controllers", "guests",
    "replicator", "network configuration operators", "performance monitor users",
    "distributed com users", "event log readers", "hyper-v administrators",
    "access control assistance operators", "remote management users", "krbtgt",
    "administrator", "guest", "defaultaccount", "wdagutilityaccount", "everyone",
    "authenticated users", "exchange servers", "organization management",
}
# netmasks and loopback carry no information; subnets and ranges DO (addressing plan)
_IP_NOISE = re.compile(r"^(?:255\.\d+\.\d+\.\d+|0\.0\.0\.0(?:/0)?|127\.0\.0\.1)$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS entities (
    norm TEXT PRIMARY KEY, handle TEXT NOT NULL, type TEXT NOT NULL, value TEXT NOT NULL,
    origin TEXT NOT NULL, alias INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS entities_handle ON entities(handle);
CREATE TABLE IF NOT EXISTS docs (
    id INTEGER PRIMARY KEY, source_id TEXT NOT NULL, rel TEXT NOT NULL, kind TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS chunks (
    id INTEGER PRIMARY KEY, doc_id INTEGER NOT NULL REFERENCES docs(id), ord INTEGER NOT NULL,
    raw TEXT NOT NULL, pseudo TEXT, emb BLOB);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def norm(typ: str, value: str) -> str:
    v = " ".join(value.split()).casefold()
    if typ == "PHONE":
        return "phone:" + re.sub(r"\D", "", v)[-9:]
    return v


def is_noise(typ: str, value: str) -> bool:
    v = value.strip().casefold()
    if v in STOP_VALUES or len(v) < 2 or not any(c.isalnum() for c in v):
        return True
    return typ == "IP" and bool(_IP_NOISE.match(v))


# Shape checks per type. Column typing and LLM NER label whole cells/spans; on real
# data that turned "Veeam" into SECRET, "Ispolnitel" into PER, "103" into HOST.
_SURNAME_END = re.compile(
    "(?i)(ov|ova|ev|eva|yev|yeva|iyev|iyeva|in|ina|sky|skiy|skaya|ovich|evich|ovna|evna|"
    "\u043e\u0432|\u043e\u0432\u0430|\u0435\u0432|\u0435\u0432\u0430|\u0438\u043d|"
    "\u0438\u043d\u0430|\u0441\u043a\u0438\u0439|\u0441\u043a\u0430\u044f|"
    "\u043e\u0432\u0438\u0447|\u0435\u0432\u0438\u0447|\u043e\u0432\u043d\u0430|"
    "\u0435\u0432\u043d\u0430)$")
_NAME_TOKEN = re.compile(r"^[^\W\d_](?:[^\W\d_]|['\u2019\u02bb\u02bc`](?=[^\W\d_]))*\.?$|"
                         r"^[^\W\d_]\.$")
_ORG_MARK = re.compile(
    "(?i)[\"\u00ab\u00bb]|\\b(llc|ltd|inc|jsc|gmbh|plc|bank|"
    "\u043e\u043e\u043e|\u0430\u043e|\u043e\u0430\u043e|\u0437\u0430\u043e|\u0447\u043f|"
    "\u0438\u043f|\u0430\u043a\u0431|\u0433\u0443\u043f)\\b")
_IP_SHAPE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}(?:-\d{1,3})?\."
                       r"(?:\d{1,3}(?:-\d{1,3})?|[xX*]|<\w+>|N)(/\d{1,2})?$")
_EMAIL_SHAPE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")
_EN_STOP = {"for", "post", "and", "the", "all", "any", "info", "mail", "temp", "scan",
            "print", "backup", "service", "server", "group", "users", "none", "yes", "no"}


_CAMEL = re.compile(r"^(?:[A-Z]?[a-z]+)+$|^[A-Z]+$|^[a-z]+$")


def random_letters(v: str) -> bool:
    """Letters-only secret like 'usqFMOTQOPQI': mixed case that is not CamelCase words."""
    return len(v) >= 8 and v.isalpha() and v.isascii() and not _CAMEL.match(v)


def name_like(value: str) -> bool:
    """Capitalized letter tokens (1-5), initials allowed: could be a person's name."""
    toks = " ".join(value.split()).split()
    if not toks or len(toks) > 5 or not all(_NAME_TOKEN.match(t) for t in toks):
        return False
    words = [t for t in toks if len(t.rstrip(".")) > 1]
    return bool(words) and all(t[0].isupper() for t in toks) and \
        not any(w.isupper() and len(w) > 1 for w in words)


def surname_shaped(value: str) -> bool:
    return any(_SURNAME_END.search(t.rstrip(".")) and len(t) >= 4 for t in value.split())


_CONFIG_KEY = re.compile(r"^[a-z][a-z0-9_]*(\.[A-Za-z0-9_]+)+$|^[/\\~]|^[A-Za-z]:\\")
_DATE = re.compile(r"^\d{1,4}[./-]\d{1,2}[./-]\d{1,4}$")
_TIME = re.compile(r"^\d{1,2}:\d{2}(:\d{2})?$")


def plausible(typ: str, value: str, origin: str = "") -> bool:
    """Does the value look like an instance of its type at all?
    PER that is name-like but has no surname-shaped token returns False here; the ingest
    gate decides those with corpus statistics."""
    v = " ".join(value.split())
    low = v.casefold()
    digits = sum(c.isdigit() for c in v)
    has_space = " " in v
    if typ == "IP":
        if ":" in v:
            from .detect import ipv6_ok
            return ipv6_ok(v)
        return bool(_IP_SHAPE.match(v))
    if typ == "EMAIL":
        return bool(_EMAIL_SHAPE.match(v))
    if typ == "PHONE":
        return digits >= 9
    if typ in ("ID", "AMT", "BANK") and _DATE.match(v):
        return False  # 5/17/2024 is a date whatever the column guess says
    if typ == "BANK":
        return digits >= 12 or (origin == "header" and digits >= 8)
    if typ == "ID":
        if origin == "header" and len(v) >= 8 and " " not in v:
            return True  # SIDs, GUIDs: alphanumeric ids from a typed column
        return digits >= 1 and len(v) >= 5 and v.count(" ") <= 3
    if typ == "AMT":
        # regex hits are currency-anchored; column/LLM numbers need money-sized values
        # (MTU 1500, "02:00" and years are not amounts)
        if _TIME.match(v):
            return False
        return digits >= 4 if origin == "regex" else digits >= 5
    if typ == "HOST":
        if origin == "header":  # NetBIOS / short names from a hostname column
            return not has_space and len(v) >= 3 and not v.isdigit() and not _IP_SHAPE.match(v)
        return (not has_space and len(v) >= 3 and not v.isdigit()
                and any(c.isdigit() or c in "-._" for c in v) and not _IP_SHAPE.match(v))
    if typ == "ACC":
        if has_space or len(v) < 3 or v.isdigit() or low in _EN_STOP or v.startswith("_"):
            return False
        if origin in ("regex", "header") or origin.endswith(":email"):
            return True
        # an LLM/column guess must look like a login, not a product name (ESXi, vCenter)
        return any(c.isdigit() or c in "._$\\@-" for c in v) or (v.islower() and v.isascii())
    if typ == "SECRET":
        if len(v) < 4 or len(v) > 200 or v.count(" ") > 1 or set(v) <= set("_-*. "):
            return False
        if _CONFIG_KEY.match(v):
            return False  # das.isolationaddress0, /etc/..., C:\... are keys and paths
        if v.isdigit() and len(v) < 8 and origin not in ("regex", "header"):
            return False
        return bool(re.search(r"\d|[^\w\s]", v)) or len(v) >= 16 or random_letters(v)
    if typ == "PER":
        # "Veeam Backup" and "HPE OneView" are name-like too; a surname-shaped token decides
        return name_like(v) and surname_shaped(v)
    if typ == "ORG":
        return len(v) >= 3 and (bool(_ORG_MARK.search(v)) or len(v.split()) >= 2
                                or origin == "header") \
            and not set(v) <= set("_-*. ")
    if typ == "ADDR":
        alpha_words = [w for w in v.split() if sum(c.isalpha() for c in w) >= 3]
        return len(alpha_words) >= 2 and digits >= 1 and len(v) >= 10
    return True


def _new_handle(typ: str) -> str:
    return f"[[DV:{typ}:{''.join(secrets.choice(_B32) for _ in range(6))}]]"


def _retag(handle: str, typ: str) -> str:
    return re.sub(r"^\[\[DV:[A-Z]+:", f"[[DV:{typ}:", handle)


def _name_tokens(value: str) -> list[str]:
    toks = [t.strip(".,;") for t in value.split()]
    return [t for t in toks if len(t) >= MIN_SWEEP_LEN and not t.endswith(".")]


class StoreSchemaError(RuntimeError):
    pass


@dataclass
class Entity:
    handle: str
    type: str
    value: str
    alias: bool = False


class Store:
    def __init__(self, path: Path, readonly: bool = False, timeout: float = 30):
        """readonly: a short-lived reader (prompt guard, web UI) that must never wait on an
        ingest in progress; WAL on the writer side lets such readers through."""
        if readonly:
            self.db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=timeout)
            self.readonly = True
            self._name_idx = None
            return
        self.readonly = False
        self.db = sqlite3.connect(path, timeout=timeout)
        self.db.execute("PRAGMA journal_mode=WAL")
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(entities)")}
        if cols and "alias" not in cols:
            self.db.close()
            raise StoreSchemaError("store has an old schema; re-run ingest with --fresh")
        self.db.executescript(SCHEMA)
        ccols = {r[1] for r in self.db.execute("PRAGMA table_info(chunks)")}
        if "inj" not in ccols:
            self.db.execute("ALTER TABLE chunks ADD COLUMN inj TEXT")
        path.chmod(0o600)
        self._name_idx: dict[str, list[tuple[str, str]]] | None = None

    def close(self):
        self.db.commit()
        self.db.close()

    # --- entities ---
    def add_entity(self, typ: str, value: str, origin: str, trusted: bool = False) -> str | None:
        if is_noise(typ, value):
            return None
        n = norm(typ, value)
        row = self.db.execute("SELECT handle, type, alias FROM entities WHERE norm=?",
                              (n,)).fetchone()
        # a structured column named by an explicit header rule ("Password", "SamAccountName")
        # is trusted: a weak password like "qwerty" must still be hidden. Free-form types
        # (names, hosts, amounts) always need the shape check: role/product words live there.
        trust = trusted or (origin == "header" and typ in HEADER_TRUSTED)
        if not row and not trust and not plausible(typ, value, origin):
            return None
        if row:
            handle, old_type, was_alias = row
            # an existing row (often a name alias) must not be promoted or retyped by a
            # detection that would not pass on its own
            if not (trust or plausible(typ, value, origin)):
                return handle
            if was_alias:
                self.db.execute("UPDATE entities SET alias=0 WHERE norm=?", (n,))
            if _TYPE_PRIORITY.index(typ) < _TYPE_PRIORITY.index(old_type):
                new = _retag(handle, typ)
                self.db.execute("UPDATE entities SET handle=?, type=? WHERE handle=?",
                                (new, typ, handle))
                handle = new
            return handle
        handle = self._link_person(value) if typ == "PER" else None
        if typ == "HOST":
            handle = self._link_host(value)
        handle = handle or _new_handle(typ)
        self.db.execute("INSERT INTO entities VALUES (?,?,?,?,?,0)",
                        (n, handle, typ, value, origin))
        if typ == "PER":
            self._add_person_aliases(handle, value)
            if self._name_idx is not None:
                self._index_name(value, handle)
        if typ == "EMAIL":
            # the local part is usually the login: a.karimov@corp -> a.karimov
            local = value.split("@", 1)[0]
            if len(local) >= MIN_SWEEP_LEN:
                self.add_entity("ACC", local, origin + ":email")
        return handle

    def _link_host(self, value: str) -> str | None:
        """srv01 and srv01.corp.local are one node."""
        v = value.casefold()
        if "." in v and not _IP_SHAPE.match(v):
            row = self.db.execute("SELECT handle FROM entities WHERE norm=? AND type='HOST'",
                                  (v.split(".", 1)[0],)).fetchone()
        else:
            row = self.db.execute(
                "SELECT handle FROM entities WHERE type='HOST' AND norm LIKE ? ESCAPE '\\'",
                (v.replace("\\", "").replace("%", "").replace("_", "\\_") + ".%",)).fetchone()
        return row[0] if row else None

    def _link_person(self, value: str) -> str | None:
        """Reuse the handle of a known person whose surname/name token matches a token here
        (declension-aware), so "Ibragimova R.K." joins "Ibragimov Rustam Kamolovich"."""
        toks = _name_tokens(value)
        if not toks:
            return None
        idx = self._names()
        votes: dict[str, int] = {}
        for t in toks:
            tl = t.lower()
            for k, handle in idx.get(tl[:4], ()):
                if _tokens_match(tl, k):
                    votes[handle] = votes.get(handle, 0) + 1
        if not votes:
            return None
        best = max(votes.items(), key=lambda kv: kv[1])
        # a single shared first name is weak evidence; require the surname-sized token
        return best[0] if best[1] >= 2 or len(toks) == 1 else None

    def _names(self) -> dict[str, list[tuple[str, str]]]:
        """Token index of known person names: first 4 letters -> [(token, handle)].
        Keeps linking O(candidates) instead of O(all persons) per new name."""
        if self._name_idx is None:
            self._name_idx = {}
            for value_k, handle in self.db.execute(
                    "SELECT value, handle FROM entities WHERE type='PER' AND alias=0"):
                self._index_name(value_k, handle)
        return self._name_idx

    def _index_name(self, value: str, handle: str):
        for k in _name_tokens(value):
            kl = k.lower()
            self._name_idx.setdefault(kl[:4], []).append((kl, handle))

    def _add_person_aliases(self, handle: str, value: str):
        tokens = _name_tokens(value)
        if len(tokens) < 2:
            return
        for tok in tokens:
            if is_noise("PER", tok):
                continue
            self.db.execute("INSERT OR IGNORE INTO entities VALUES (?,?,?,?,?,1)",
                            (norm("PER", tok), handle, "PER", tok, "alias"))

    def resolve(self, handle: str) -> str | None:
        """Canonical real value of a handle: a non-alias form, the longest one (full name,
        FQDN). Only render() calls this; nothing it returns goes to the agent."""
        row = self.db.execute(
            "SELECT value FROM entities WHERE handle=? ORDER BY alias ASC, length(value) DESC "
            "LIMIT 1", (handle,)).fetchone()
        return row[0] if row else None

    def entities(self) -> list[Entity]:
        return [Entity(h, t, v, bool(a)) for h, t, v, a in
                self.db.execute("SELECT handle, type, value, alias FROM entities")]

    def counts(self) -> dict[str, int]:
        return dict(self.db.execute(
            "SELECT type, COUNT(DISTINCT handle) FROM entities GROUP BY type"))

    # --- docs/chunks ---
    def reset_docs(self):
        self.db.execute("DELETE FROM chunks")
        self.db.execute("DELETE FROM docs")

    def add_doc(self, source_id: str, rel: str, kind: str, note: str = "") -> int:
        cur = self.db.execute("INSERT INTO docs (source_id, rel, kind, note) VALUES (?,?,?,?)",
                              (source_id, rel, kind, note))
        return cur.lastrowid

    def add_chunk(self, doc_id: int, ord_: int, raw: str, inj: str | None = None) -> int:
        return self.db.execute("INSERT INTO chunks (doc_id, ord, raw, inj) VALUES (?,?,?,?)",
                               (doc_id, ord_, raw, inj)).lastrowid

    def injection(self, chunk_id: int) -> dict | None:
        row = self.db.execute("SELECT inj FROM chunks WHERE id=?", (chunk_id,)).fetchone()
        return json.loads(row[0]) if row and row[0] else None

    def injections(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for (inj,) in self.db.execute("SELECT inj FROM chunks WHERE inj IS NOT NULL"):
            level = json.loads(inj)["level"]
            out[level] = out.get(level, 0) + 1
        return out

    def chunks(self) -> list[tuple[int, str]]:
        return list(self.db.execute("SELECT id, raw FROM chunks ORDER BY id"))

    def set_pseudo(self, chunk_id: int, pseudo: str):
        self.db.execute("UPDATE chunks SET pseudo=? WHERE id=?", (pseudo, chunk_id))

    def set_emb(self, chunk_id: int, vec: list[float]):
        self.db.execute("UPDATE chunks SET emb=? WHERE id=?",
                        (array("f", vec).tobytes(), chunk_id))

    def doc_text(self, column: str) -> dict[str, str]:
        assert column in ("raw", "pseudo")
        out: dict[str, str] = {}
        for rel, text in self.db.execute(
                f"SELECT d.rel, c.{column} FROM chunks c JOIN docs d ON d.id=c.doc_id "
                "ORDER BY c.id"):
            out[rel] = out.get(rel, "") + (text or "") + "\n"
        return out

    def set_meta(self, key: str, value: str):
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, value))

    def meta(self) -> dict[str, str]:
        return dict(self.db.execute("SELECT key, value FROM meta"))

    # --- sweep ---
    def build_sweeper(self) -> Sweeper:
        return Sweeper([e for e in self.entities() if len(e.value) >= MIN_SWEEP_LEN])


@lru_cache(maxsize=65536)
def _tokens_match(a: str, b: str) -> bool:
    """Same name token up to Russian declension (either direction)."""
    if a == b:
        return True
    return bool(_compiled_per(b).fullmatch(a) or _compiled_per(a).fullmatch(b))


@lru_cache(maxsize=65536)
def _compiled_per(token: str) -> re.Pattern[str]:
    return re.compile(_pattern("PER", token), re.IGNORECASE)


def _pattern(typ: str, value: str) -> str:
    if typ == "PHONE":
        d = re.sub(r"\D", "", value)[-9:]
        return r"(?:\+?998[\s\-.]*)?\(?" + r"[\s\-().]*".join(d)
    if typ == "PER" and _CYR_WORD.match(value) and len(value) >= 4:
        # Russian declension: Karimov -> Karimova/Karimovu/Karimovym, Yusupova -> Yusupovoy
        stem = value[:-1] if value[-1].lower() in _CYR_VOWELS else value
        return re.escape(stem) + _CYR_ENDING
    return r"\s+".join(re.escape(w) for w in value.split())


_PHONE_CAND = re.compile(r"(?:\+?998[\s\-.]*)?\(?\d{2}\)?[\s\-.]*\d{3}[\s\-.]*\d{2}"
                         r"[\s\-.]*\d{2}(?!\d)")
_CYR_FIRST = [chr(c) for c in range(0x430, 0x450)] + ["\u0451"]
_CYR_TOKEN = re.compile("[\u0400-\u04ff]+")


class Sweeper:
    """Dictionary sweep: at every token boundary try the known value lengths, longest first.

    Scales to tens of thousands of values (a regex alternation does not). Phones are matched
    by their last 9 digits, Russian surnames by stem plus up to 3 Cyrillic ending letters.
    """

    def __init__(self, entities: list[Entity]):
        self.literal: dict[str, str] = {}
        self.stems: dict[str, str] = {}
        self.phones: dict[str, str] = {}
        lengths: dict[str, set[int]] = {}
        for e in sorted(entities, key=lambda e: e.alias):  # real values win over aliases
            if e.type == "PHONE":
                self.phones.setdefault(re.sub(r"\D", "", e.value)[-9:], e.handle)
                continue
            if e.type == "PER" and _CYR_WORD.match(e.value) and len(e.value) >= 4:
                stem = e.value[:-1] if e.value[-1].lower() in _CYR_VOWELS else e.value
                self.stems.setdefault(stem.lower(), e.handle)
            key = " ".join(e.value.split()).lower()
            if key not in self.literal:
                self.literal[key] = e.handle
                lengths.setdefault(key[0], set()).add(len(key))
        self.lengths = {c: sorted(ls, reverse=True) for c, ls in lengths.items()}

    def _phones(self, text: str) -> str:
        if not self.phones:
            return text

        def repl(m: re.Match) -> str:
            h = self.phones.get(re.sub(r"\D", "", m.group(0))[-9:])
            return h if h else m.group(0)
        return _PHONE_CAND.sub(repl, text)

    def apply(self, text: str) -> str:
        text = self._phones(text)
        out, pos, n = [], 0, len(text)
        lower = text.lower()
        starts = self.lengths.keys() | (set(_CYR_FIRST) if self.stems else set())
        for i in range(n):
            if i < pos or (lower[i] not in starts and text[i] != "["):
                continue
            prev_alpha = i > 0 and text[i - 1].isalpha()
            if i > 0 and (text[i - 1].isdigit() or text[i - 1] in "_@"):
                continue
            if prev_alpha and not text[i].isdigit() and text[i] != "[":
                continue
            # right after a dot only dotted values may start: "corp.local" inside
            # "srv01.corp.local", but never "local" alone inside a domain
            after_dot = i > 0 and text[i - 1] == "."
            if text.startswith("[[DV:", i):
                end = text.find("]]", i)
                if end != -1:
                    out.append(text[pos:end + 2])
                    pos = end + 2
                continue
            best = None
            for L in self.lengths.get(lower[i], ()):
                j = i + L
                if j > n:
                    continue
                if j < n and (text[j].isalnum() or text[j] in "_@"):
                    continue
                key = _squash(lower[i:j])
                if prev_alpha and "." not in key:
                    continue
                if after_dot and "." not in key:
                    continue
                h = self.literal.get(key)
                if h:
                    best = (j, h)
                    break
            tok = None if after_dot else _CYR_TOKEN.match(text, i)
            if tok and self.stems:
                w = tok.group(0).lower()
                for cut in range(0, min(3, len(w) - 3) + 1):
                    h = self.stems.get(w[:len(w) - cut])
                    if h:
                        if not best or tok.end() > best[0]:
                            best = (tok.end(), h)
                        break
            if best:
                out.append(text[pos:i])
                out.append(best[1])
                pos = best[0]
        out.append(text[pos:])
        return "".join(out)


def _squash(s: str) -> str:
    return " ".join(s.split()) if any(c.isspace() for c in s) else s
