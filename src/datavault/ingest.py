"""Ingest a case: parse -> detect -> register handles -> sweep -> embed."""
from __future__ import annotations

import json
import re
import time
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from . import injection
from .cases import Case
from .detect import llm_detect, regex_detect, table_detect
from .gateway import GatewayError, ModelGateway
from .inspect_src import source_entries
from .parsers import parse, table_chunks
from .store import Store, name_like, surname_shaped

EMBED_BATCH = 64


@dataclass
class IngestOptions:
    llm: bool = True            # LLM NER on text chunks
    columns: bool = True        # LLM column typing for tables
    embed: bool = True
    workers: int = 2            # parallel LLM requests


@dataclass
class IngestReport:
    files: int = 0
    skipped: Counter = field(default_factory=Counter)
    chunks: int = 0
    detections: Counter = field(default_factory=Counter)
    entities: dict = field(default_factory=dict)
    embedded: int = 0
    seconds: float = 0.0
    warnings: list[str] = field(default_factory=list)
    deferred: dict = field(default_factory=dict)
    injections: Counter = field(default_factory=Counter)


_WORD = re.compile(r"\w+")


class _Gate:
    """Detections that need corpus statistics before they become entities.

    - a lone capitalized PER token that is not surname-shaped (a first name like "Maksim",
      or a role like "Zakazchik"): accepted only if the word never occurs lowercase in the
      case, i.e. it is not a common noun;
    - an all-letters SECRET/ACC from a header-trusted column ("Veeam" in a password column):
      dropped if it appears in many documents, which is how product names behave.
    """

    def __init__(self, st: Store):
        self.st = st
        self.lower_words: set[str] = set()
        self.word_docs: dict[str, set[int]] = {}
        self.docs: set[int] = set()
        self.names: list = []
        self.vocab: list = []

    def observe(self, raw: str, doc_id: int, prose: bool = True):
        # spread is measured over prose only: a login legitimately sits in many tables
        # (Users, GroupMembers, Computers), a product name sits in many texts
        if prose:
            self.docs.add(doc_id)
        if not prose:
            # a surname in a table is lowercase inside logins and mail (anna.petrova@...),
            # which says nothing about it being an ordinary word
            return
        for m in _WORD.finditer(raw):
            w = m.group(0)
            lw = w.casefold()
            if w[0].islower():
                self.lower_words.add(lw)
            self.word_docs.setdefault(lw, set()).add(doc_id)

    def add(self, d, doc_id):
        v = d.value.strip()
        if d.type == "PER" and name_like(v) and not surname_shaped(v):
            self.names.append(d)
            return
        if d.source in ("header", "column") and d.type in ("SECRET", "ACC") and v.isalpha():
            self.vocab.append(d)
            return
        self.st.add_entity(d.type, d.value, d.source)

    def resolve(self) -> dict:
        kept = {"names": 0, "names_dropped": 0, "vocab": 0, "vocab_dropped": 0}
        limit = max(3, int(0.1 * len(self.docs)))
        for d in self.names:
            v = " ".join(d.value.split())
            words = [w.rstrip(".") for w in v.split() if len(w.rstrip(".")) > 1]
            # a name: none of its words is used as an ordinary lowercase word in the case
            # ... and it is not spread over many documents like a product or a city
            ok = bool(words) and all(len(w) >= 3 and w.casefold() not in self.lower_words
                                     and len(self.word_docs.get(w.casefold(), ())) <= limit
                                     for w in words)
            if ok and self.st.add_entity("PER", v, d.source, trusted=True):
                kept["names"] += 1
            else:
                kept["names_dropped"] += 1
        limit = max(3, int(0.1 * len(self.docs)))
        for d in self.vocab:
            df = len(self.word_docs.get(d.value.strip().casefold(), ()))
            if df > limit:
                kept["vocab_dropped"] += 1
            elif self.st.add_entity(d.type, d.value, d.source, trusted=True):
                kept["vocab"] += 1
            else:
                kept["vocab_noise"] = kept.get("vocab_noise", 0) + 1
        return kept


_FREE_TEXT = re.compile(
    "(?i)(description|desc|info|comment|comments|notes?|remarks?|memo|"
    "\u043f\u0440\u0438\u043c\u0435\u0447\u0430\u043d\\w*|"
    "\u043e\u043f\u0438\u0441\u0430\u043d\\w*|"
    "\u043a\u043e\u043c\u043c\u0435\u043d\u0442\u0430\u0440\\w*|"
    "\u0437\u0430\u043c\u0435\u0447\u0430\u043d\\w*)")


def _free_text_chunks(t, size: int = 1500) -> list[str]:
    """Unique free-text cells of comment-like columns, packed into NER-sized chunks."""
    out, cur, seen = [], "", set()
    for j, h in enumerate(t.header):
        if not h or not _FREE_TEXT.search(h):
            continue
        for r in t.rows:
            v = r[j].strip() if j < len(r) and r[j] else ""
            if len(v) < 8 or v in seen or not any(c.isalpha() for c in v):
                continue
            seen.add(v)
            if len(cur) + len(v) + 1 > size and cur:
                out.append(cur)
                cur = ""
            cur += v + "\n"
    if cur:
        out.append(cur)
    return out


def store_path(case: Case):
    return case.root / "vault.sqlite"


def ingest(case: Case, gw: ModelGateway | None, opts: IngestOptions | None = None,
           progress: Callable[[str], None] | None = None) -> IngestReport:
    opts = opts or IngestOptions()
    say = progress or (lambda _m: None)
    rep = IngestReport()
    t0 = time.monotonic()
    st = Store(store_path(case))
    try:
        st.reset_docs()
        gate = _Gate(st)
        llm_jobs: list[str] = []
        freetext_jobs: list[str] = []
        table_chunk_ids: set[int] = set()
        entries = source_entries(case)
        for n_file, (sid, path) in enumerate(entries, 1):
            rel = path.relative_to(case.data_dir).as_posix()
            try:
                parsed = parse(path)
            except Exception as e:  # noqa: BLE001 - one broken file must not stop the case
                parsed = None
                rep.skipped[f"parse error {type(e).__name__}"] += 1
            if parsed is None or parsed.kind == "skipped":
                if parsed is not None:
                    rep.skipped[parsed.note] += 1
                st.add_doc(sid, rel, "skipped", parsed.note if parsed else "parse error")
                continue
            rep.files += 1
            doc_id = st.add_doc(sid, rel, parsed.kind)
            pieces = list(parsed.texts)
            for t in parsed.tables:
                pieces.extend(table_chunks(t))
                dets = table_detect(gw if opts.columns else None, t, path.name)
                for d in dets:
                    gate.add(d, doc_id)
                rep.detections.update(f"column:{d.type}" for d in dets)
                freetext_jobs.extend(_free_text_chunks(t))
            for i, raw in enumerate(pieces):
                inj = injection.scan(raw)
                if inj.level != "clean":
                    rep.injections[inj.level] += 1
                cid = st.add_chunk(doc_id, i, raw,
                                   json.dumps(inj.as_dict()) if inj.level != "clean" else None)
                gate.observe(raw, doc_id, prose=i < len(parsed.texts))
                if i >= len(parsed.texts):
                    table_chunk_ids.add(cid)
                rep.chunks += 1
                for d in regex_detect(raw):
                    st.add_entity(d.type, d.value, "regex")
                    rep.detections[f"regex:{d.type}"] += 1
            if opts.llm:
                llm_jobs.extend(parsed.texts)
            if n_file % 10 == 0 or n_file == len(entries):
                say(f"parsed {n_file}/{len(entries)} files")

        # free-text table cells (Description, comments) get NER even without full-text NER:
        # they are where people write names and passwords into AD and inventories
        if opts.columns:
            llm_jobs.extend(freetext_jobs)
        # identical chunks (templates repeated across docx/md versions) need one NER pass
        llm_jobs = list(dict.fromkeys(c for c in llm_jobs if c.strip()))
        if (opts.llm or opts.columns) and gw is not None and llm_jobs:
            say(f"llm ner on {len(llm_jobs)} unique chunks")
            with ThreadPoolExecutor(max_workers=opts.workers) as pool:
                for n, dets in enumerate(pool.map(lambda c: llm_detect(gw, c), llm_jobs), 1):
                    for d in dets:
                        gate.add(d, None)
                        rep.detections[f"llm:{d.type}"] += 1
                    if n % 10 == 0:
                        say(f"llm ner {n}/{len(llm_jobs)}")

        rep.deferred = gate.resolve()
        for v in case.policy.always_mask:
            h = st.add_entity(v["type"], v["value"], "policy", trusted=True)
            labels = v["value"].split(".")
            if h and v["type"] == "HOST" and len(labels) >= 2:
                # the same domain inside LDAP DNs: DC=corp,DC=example
                st.add_entity("HOST", ",".join(f"DC={x}" for x in labels), "policy",
                              trusted=True)
        sweeper = st.build_sweeper()
        rows = st.chunks()
        pseudo = []
        for cid, raw in rows:
            p = sweeper.apply(raw)
            st.set_pseudo(cid, p)
            pseudo.append((cid, p))
        say("sweep done")

        # table rows are answered by aggregate/rows; embedding every row of a 10k-line
        # AD export costs ~40 min and adds little to semantic search
        to_embed = [(cid, p) for cid, p in pseudo if cid not in table_chunk_ids]
        if opts.embed and gw is not None and to_embed:
            model = None
            try:
                for i in range(0, len(to_embed), EMBED_BATCH):
                    batch = to_embed[i:i + EMBED_BATCH]
                    vecs, used = gw.embed([p for _, p in batch], only=model)
                    if model is None:
                        model = str(used)
                        st.set_meta("embed_model", model)
                    for (cid, _), v in zip(batch, vecs, strict=True):
                        st.set_emb(cid, v)
                    rep.embedded += len(batch)
            except GatewayError as e:
                rep.warnings.append(f"embeddings skipped: {e}")

        rep.entities = st.counts()
        rep.seconds = round(time.monotonic() - t0, 1)
        st.set_meta("ingested_at", time.strftime("%Y-%m-%dT%H:%M:%S"))
        st.set_meta("files", str(rep.files))
        st.set_meta("chunks", str(rep.chunks))
        st.set_meta("llm", str(opts.llm))
    finally:
        st.close()
    return rep
