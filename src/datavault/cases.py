"""Cases: isolated workspaces of raw data under DATAVAULT_HOME/cases/<name>/.

Layout:
    <name>/case.yaml   metadata + policy (title/description are agent-visible)
    <name>/data/       raw sources (never exposed directly)
    <name>/out/        rendered results with real values (human-only)
"""
from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from datetime import date
from fnmatch import fnmatch
from pathlib import Path
from typing import Literal

import yaml

from .config import vault_home

CASE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")

LabelMode = Literal["masked", "dlp"]


class CaseError(ValueError):
    pass


@dataclass
class Policy:
    # file/dir names often carry data ("ivanov_salary.xlsx"), so masked by default
    file_labels: LabelMode = "masked"
    column_labels: LabelMode = "dlp"
    k_anonymity: int = 5
    # values the operator knows are sensitive (customer name, its domains): always masked
    always_mask: list[dict] = field(default_factory=list)
    # person tables: "handles" returns rows with identifying columns as handles, "deny" drops
    # those columns from rows/read so people cannot be walked one by one
    person_rows: str = "handles"
    # extract: free string fields per call (each is a channel for pulling values bit by bit)
    extract_free_fields: int = 4

    @classmethod
    def from_dict(cls, d: dict | None) -> Policy:
        d = d or {}
        p = cls(
            file_labels=d.get("file_labels", "masked"),
            column_labels=d.get("column_labels", "dlp"),
            k_anonymity=int(d.get("k_anonymity", 5)),
            always_mask=[{"type": str(x["type"]).upper(), "value": str(x["value"])}
                         for x in d.get("always_mask", []) or []],
            person_rows=str(d.get("person_rows", "handles")),
            extract_free_fields=int(d.get("extract_free_fields", 4)),
        )
        if p.person_rows not in ("handles", "deny"):
            raise CaseError(f"unknown person_rows mode: {p.person_rows}")
        for mode in (p.file_labels, p.column_labels):
            if mode not in ("masked", "dlp"):
                raise CaseError(f"unknown label mode: {mode}")
        return p


@dataclass
class Case:
    name: str
    root: Path
    title: str = ""
    description: str = ""
    created: str = ""
    policy: Policy = field(default_factory=Policy)
    source_dir: str = ""   # read sources in place instead of <case>/data
    include: list[str] = field(default_factory=list)  # fnmatch patterns on file names

    @property
    def data_dir(self) -> Path:
        return Path(self.source_dir).expanduser() if self.source_dir else self.root / "data"

    @property
    def out_dir(self) -> Path:
        return self.root / "out"

    def source_files(self) -> list[Path]:
        """Stable order so masked ids (f001, f002, ...) do not shift between calls."""
        if not self.data_dir.is_dir():
            return []
        files = [
            p for p in self.data_dir.rglob("*")
            if p.is_file() and not p.is_symlink() and not p.name.startswith(".")
            and (not self.include or any(fnmatch(p.name, pat) for pat in self.include))
        ]
        return sorted(files, key=lambda p: p.relative_to(self.data_dir).as_posix())


def cases_root(home: Path | None = None) -> Path:
    return (home or vault_home()) / "cases"


def _validate_name(name: str) -> str:
    if not CASE_NAME_RE.match(name):
        raise CaseError("case name must match [a-z0-9][a-z0-9-]{1,62}")
    return name


def load_case(name: str, home: Path | None = None) -> Case:
    root = cases_root(home) / _validate_name(name)
    meta_path = root / "case.yaml"
    if not meta_path.is_file():
        raise CaseError(f"case not found: {name}")
    meta = yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
    return Case(
        name=name,
        root=root,
        title=str(meta.get("title", "")),
        description=str(meta.get("description", "")),
        created=str(meta.get("created", "")),
        policy=Policy.from_dict(meta.get("policy")),
        source_dir=str(meta.get("source_dir", "")),
        include=[str(x) for x in meta.get("include", [])],
    )


def list_cases(home: Path | None = None) -> list[Case]:
    root = cases_root(home)
    if not root.is_dir():
        return []
    out = []
    for d in sorted(root.iterdir()):
        if d.is_dir() and CASE_NAME_RE.match(d.name) and (d / "case.yaml").is_file():
            out.append(load_case(d.name, home))
    return out


def init_case(name: str, title: str = "", description: str = "",
              home: Path | None = None, source_dir: str = "",
              include: list[str] | None = None) -> Case:
    root = cases_root(home) / _validate_name(name)
    if (root / "case.yaml").exists():
        raise CaseError(f"case already exists: {name}")
    (root / "data").mkdir(parents=True, exist_ok=True)
    (root / "out").mkdir(exist_ok=True)
    meta = {
        "title": title or name,
        "description": description,
        "created": date.today().isoformat(),
        "policy": {"file_labels": "masked", "column_labels": "dlp", "k_anonymity": 5},
    }
    if source_dir:
        src = Path(source_dir).expanduser().resolve()
        if not src.is_dir():
            raise CaseError(f"source dir not found: {source_dir}")
        meta["source_dir"] = str(src)
    if include:
        meta["include"] = list(include)
    (root / "case.yaml").write_text(
        yaml.safe_dump(meta, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    root.chmod(0o700)
    return load_case(name, home)


def add_include(name: str, pattern: str, home: Path | None = None) -> list[str]:
    """Add a file name to a case that reads its source dir in place."""
    meta_path = cases_root(home) / _validate_name(name) / "case.yaml"
    meta = yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
    items = meta.get("include") or []
    if pattern not in items:
        items.append(pattern)
    meta["include"] = items
    meta_path.write_text(yaml.safe_dump(meta, allow_unicode=True, sort_keys=False),
                         encoding="utf-8")
    return items


def case_footprint(name: str, home: Path | None = None) -> dict:
    """What deleting a case removes: derived files only, sources read in place stay."""
    c = load_case(name, home)
    files = [p for p in c.root.rglob("*") if p.is_file()]
    inside = c.source_dir == "" or Path(c.source_dir).resolve() == c.data_dir.resolve()
    return {"case": c.name, "root": str(c.root), "files": len(files),
            "bytes": sum(p.stat().st_size for p in files),
            "out_files": len([p for p in files if p.is_relative_to(c.out_dir)]),
            "store_backups": len([p for p in files if ".bak-" in p.name]),
            "copies_of_sources": inside and any(p.is_relative_to(c.data_dir) for p in files),
            "source_dir": c.source_dir}


def delete_case(name: str, home: Path | None = None) -> dict:
    fp = case_footprint(name, home)
    shutil.rmtree(Path(fp["root"]))
    return fp


def set_policy(name: str, key: str, value: str, home: Path | None = None) -> dict:
    """Set one policy key in case.yaml (k_anonymity, person_rows, extract_free_fields, ...)."""
    meta_path = cases_root(home) / _validate_name(name) / "case.yaml"
    meta = yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
    pol = meta.setdefault("policy", {})
    pol[key] = int(value) if value.isdigit() else value
    Policy.from_dict(pol)  # validates
    meta_path.write_text(yaml.safe_dump(meta, allow_unicode=True, sort_keys=False),
                         encoding="utf-8")
    return pol


def add_always_mask(name: str, typ: str, value: str, home: Path | None = None) -> int:
    """Append a value to the case policy's always_mask list; returns the list length."""
    root = cases_root(home) / _validate_name(name)
    meta_path = root / "case.yaml"
    meta = yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
    pol = meta.setdefault("policy", {})
    items = pol.setdefault("always_mask", []) or []
    item = {"type": typ.upper(), "value": value}
    if item not in items:
        items.append(item)
    pol["always_mask"] = items
    meta_path.write_text(yaml.safe_dump(meta, allow_unicode=True, sort_keys=False),
                         encoding="utf-8")
    return len(items)


def rename_case(old: str, new: str, home: Path | None = None) -> Case:
    """Case ids are visible to the agent in every call, so they must not name the customer."""
    src = cases_root(home) / _validate_name(old)
    dst = cases_root(home) / _validate_name(new)
    if not (src / "case.yaml").is_file():
        raise CaseError(f"case not found: {old}")
    if dst.exists():
        raise CaseError(f"case already exists: {new}")
    src.rename(dst)
    return load_case(new, home)
