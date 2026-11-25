"""Leak audit without ground truth: a stronger local model re-reads a sample of
pseudonymized chunks and reports values that still look sensitive.

Findings (with values) are written to <case>/audit.json for the human; callers that
talk to the agent must expose only the counts.
"""
from __future__ import annotations

import json
import random
import sqlite3
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from .cases import Case
from .detect import NER_SCHEMA, TYPES
from .gateway import GatewayError, ModelGateway
from .ingest import store_path
from .parsers import chunk_text
from .store import HANDLE_RE

PIECE_CHARS = 4000

AUDIT_SYSTEM = """You audit pseudonymized documents. Sensitive values were replaced by tokens
like [[DV:PER:abc123]]. Find sensitive values that were NOT replaced and are still visible:
PER person names/surnames, ACC logins, EMAIL, PHONE, HOST hostnames, IP addresses,
ID personal/tax/passport ids, BANK account numbers, SECRET passwords/keys/tokens,
ADDR street addresses, ORG names of private organizations/customers.
Ignore the tokens themselves, vendor/product names (Microsoft, Veeam, HPE, Cisco...),
generic words, dates, versions, model numbers, ports. Names of AD groups, OUs, GPOs and
service objects are not persons. Copy each value exactly as it appears.
If nothing sensitive remains, return an empty list."""


def audit(case: Case, gw: ModelGateway, sample: int = 60, seed: int = 1,
          task: str = "heavy", workers: int = 1) -> dict:
    db = sqlite3.connect(store_path(case))
    rows = list(db.execute("SELECT c.id, d.rel, c.pseudo FROM chunks c "
                           "JOIN docs d ON d.id=c.doc_id WHERE c.pseudo IS NOT NULL"))
    db.close()
    rnd = random.Random(seed)
    picked = rnd.sample(rows, min(sample, len(rows)))
    t0 = time.monotonic()

    def check(row):
        cid, rel, pseudo = row
        bare = HANDLE_RE.sub(" ", pseudo)
        found, err = [], None
        # table chunks reach 20k chars; the heavy model runs with an 8k context
        for piece in chunk_text(pseudo, PIECE_CHARS):
            try:
                data, _ = gw.complete_json(
                    task, [{"role": "system", "content": AUDIT_SYSTEM},
                           {"role": "user", "content": piece}], NER_SCHEMA, max_tokens=2048)
            except GatewayError as e:
                err = str(e).rsplit(": ", 1)[-1]  # exception class name only
                continue
            for e in data.get("entities", []):
                val, typ = str(e.get("text", "")).strip(), e.get("type")
                if typ in TYPES and len(val) >= 3 and val in bare and not HANDLE_RE.search(val):
                    found.append({"type": typ, "value": val})
        return cid, rel, found, err

    findings = []
    errors: Counter = Counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for cid, rel, found, err in pool.map(check, picked):
            if err:
                errors[err] += 1
            for f in found:
                findings.append({"chunk": cid, "file": rel, **f})
    by_type = Counter(f["type"] for f in findings)
    flagged_chunks = len({f["chunk"] for f in findings})
    report = {
        "sampled_chunks": len(picked),
        "total_chunks": len(rows),
        "chunks_with_findings": flagged_chunks,
        "model_errors": sum(errors.values()),
        "error_kinds": dict(errors),
        "findings_by_type": dict(sorted(by_type.items())),
        "seconds": round(time.monotonic() - t0, 1),
    }
    (case.root / "audit.json").write_text(
        json.dumps({**report, "findings": findings}, ensure_ascii=False, indent=1))
    (case.root / "audit.json").chmod(0o600)
    return report
