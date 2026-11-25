"""Generate a synthetic case with ground truth for NER/leak evaluation.

Usage: python scripts/synth/gen_synthetic.py <case-name> [--seed 7]

Writes sources into <DATAVAULT_HOME>/cases/<case>/data/ and the ground truth into
<case>/truth.json (outside data/, so it is never ingested). All values are fake.
Truth entries: {"file": rel path, "type": T, "value": surface form, "hard": bool}.
hard=False marks weak identifiers (first names, amounts) reported separately.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import random
import string
import sys
from email.message import EmailMessage
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from datavault.cases import CaseError, init_case, load_case  # noqa: E402

VOCAB = json.loads((Path(__file__).with_name("vocab.json")).read_text())
FONT = "/System/Library/Fonts/Supplemental/Arial Unicode.ttf"

_CYR = [chr(c) for c in range(0x430, 0x450)]
_LAT = ["a", "b", "v", "g", "d", "e", "zh", "z", "i", "y", "k", "l", "m", "n", "o", "p",
        "r", "s", "t", "u", "f", "kh", "ts", "ch", "sh", "sch", "", "y", "", "e", "yu", "ya"]
_TR = dict(zip(_CYR, _LAT, strict=True)) | {chr(0x451): "yo"}


def translit(s: str) -> str:
    return "".join(_TR.get(ch, ch) for ch in s.lower())


class Person:
    def __init__(self, last, first, middle="", gender="m", cyr=True):
        self.last, self.first, self.middle, self.gender, self.cyr = last, first, middle, gender, cyr
        self.login = f"{translit(first)[0]}.{translit(last)}" if cyr else \
            f"{first[0].lower()}.{last.lower()}"

    @property
    def full(self):
        return " ".join(x for x in (self.last, self.first, self.middle) if x)

    @property
    def short(self):
        return f"{self.first[0]}. {self.last}"

    def dat(self):
        if not self.cyr:
            return self.last
        sx = VOCAB["suffix"]
        if self.gender == "f" and self.last.endswith(sx["dat_f_from"]):
            return self.last[:-1] + sx["dat_f_to"]
        return self.last + sx["dat_m"] if self.gender == "m" and self.last[-1] not in "\u0439" \
            and not self.last.endswith(("\u0438\u043c", "\u043e\u0439")) and len(self.last) > 3 \
            else self.last

    def gen(self):
        if not self.cyr:
            return self.last
        sx = VOCAB["suffix"]
        if self.gender == "f" and self.last.endswith(sx["dat_f_from"]):
            return self.last[:-1] + sx["gen_f_to"]
        if self.gender == "m" and len(self.last) > 3:
            return self.last + sx["gen_m"]
        return self.last


class Gen:
    def __init__(self, seed: int):
        self.r = random.Random(seed)
        self.truth: list[dict] = []
        self.people = [Person(*p, cyr=True) for p in VOCAB["people_ru"]] + \
                      [Person(p[0], p[1], cyr=False) for p in VOCAB["people_uz"]]
        self.r.shuffle(self.people)
        self.domain = "uzenergo-test.uz"
        self.hosts = [f"{p}-{s}{n:02d}.corp.tpp.local" for p, s, n in [
            ("srv", "dc", 1), ("srv", "dc", 2), ("srv", "sql", 1), ("srv", "scada", 3),
            ("sw", "core", 1), ("fw", "edge", 1), ("srv", "backup", 2), ("srv", "file", 1)]]

    # --- fake value factories ---
    def phone(self):
        d = [self.r.randint(0, 9) for _ in range(7)]
        op = self.r.choice(["90", "91", "93", "94", "97", "99"])
        fmt = self.r.choice([
            "+998 {op} {a}{b}{c} {d}{e} {f}{g}", "+998{op}{a}{b}{c}{d}{e}{f}{g}",
            "({op}) {a}{b}{c}-{d}{e}-{f}{g}", "+998-{op}-{a}{b}{c}-{d}{e}-{f}{g}"])
        return fmt.format(op=op, **dict(zip("abcdefg", d, strict=True)))

    def digits(self, n, first="123456789"):
        return self.r.choice(first) + "".join(self.r.choice(string.digits) for _ in range(n - 1))

    def pinfl(self):
        return self.digits(14, "3456")

    def passport(self):
        return self.r.choice(["AA", "AB", "AC", "AD"]) + self.digits(7)

    def inn(self):
        return self.digits(9, "23")

    def account(self):
        return "2020" + self.digits(16)

    def amount(self):
        v = self.r.randint(15, 990) * 100_000
        return f"{v:,}".replace(",", " ")

    def ip(self, public=False):
        if public:
            return f"{self.r.choice([91, 185, 213])}.{self.r.randint(1, 254)}." \
                   f"{self.r.randint(0, 254)}.{self.r.randint(1, 254)}"
        return f"10.{self.r.randint(10, 60)}.{self.r.randint(0, 254)}.{self.r.randint(1, 254)}"

    def password(self):
        if self.r.random() < 0.4:
            return self.r.choice(["Summer", "Tashkent", "Energo", "Welcome"]) + \
                str(self.r.randint(2020, 2026)) + self.r.choice("!#$")
        alphabet = string.ascii_letters + string.digits + "!#$%&*"
        return "".join(self.r.choice(alphabet) for _ in range(12))

    def email(self, p: Person):
        return f"{p.login}@{self.domain}"

    def date(self):
        return f"{self.r.randint(1, 28):02d}.{self.r.randint(1, 12):02d}.2026"

    # --- truth helpers ---
    def t(self, file, typ, value, hard=True):
        self.truth.append({"file": file, "type": typ, "value": value, "hard": hard})
        return value

    def tp(self, file, p: Person, form: str):
        """Register a person mention; returns the surface text."""
        if form == "full":
            self.t(file, "PER", p.last)
            self.t(file, "PER", p.first, hard=False)
            return p.full
        if form == "short":
            self.t(file, "PER", p.last)
            return p.short
        if form == "first":
            return self.t(file, "PER", p.first, hard=False)
        if form == "surname":
            return self.t(file, "PER", p.last)
        if form == "dat":
            return self.t(file, "PER", p.dat())
        if form == "gen":
            self.t(file, "PER", p.gen())
            return f"{p.gen()} {p.first[0]}.{p.middle[:1] + '.' if p.middle else ''}"
        raise ValueError(form)

    def pick(self, n):
        return self.r.sample(self.people, n)


def write_ad_csv(g: Gen, d: Path):
    f = "ad_users.csv"
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["sAMAccountName", "DisplayName", "mail", "telephoneNumber",
                "Department", "Title", "Enabled", "LastLogonDate"])
    for p in g.people:
        w.writerow([g.t(f, "ACC", p.login), g.tp(f, p, "full"), g.t(f, "EMAIL", g.email(p)),
                    g.t(f, "PHONE", g.phone()), g.r.choice(VOCAB["departments"]),
                    g.r.choice(VOCAB["titles"]), g.r.choice(["True", "True", "False"]),
                    g.date()])
    (d / f).write_text(buf.getvalue(), encoding="utf-8")


def write_hr_xlsx(g: Gen, d: Path):
    from openpyxl import Workbook
    f = "hr_staff.xlsx"
    wb = Workbook()
    ws = wb.active
    ws.title = "\u0428\u0442\u0430\u0442"
    ws.append(["\u0424\u0418\u041e", "\u041f\u0418\u041d\u0424\u041b",
               "\u041f\u0430\u0441\u043f\u043e\u0440\u0442", "\u041e\u043a\u043b\u0430\u0434",
               "\u041e\u0442\u0434\u0435\u043b", "\u0422\u0435\u043b\u0435\u0444\u043e\u043d"])
    for p in [p for p in g.people if p.cyr]:
        ws.append([g.tp(f, p, "full"), g.t(f, "ID", g.pinfl()), g.t(f, "ID", g.passport()),
                   int(g.t(f, "AMT", g.amount(), hard=False).replace(" ", "")),
                   g.r.choice(VOCAB["departments"]),
                   g.t(f, "PHONE", g.phone())])
    wb.save(d / f)


def write_emails(g: Gen, d: Path, n=12):
    (d / "mail").mkdir(exist_ok=True)
    for i in range(n):
        f = f"mail/msg_{i + 1:02d}.eml"
        tpl = VOCAB["emails"][i % len(VOCAB["emails"])]
        frm, to, third = g.pick(3)
        org = g.r.choice(VOCAB["orgs"])
        vals = {
            "to_dat": g.tp(f, to, "dat"), "to_first": g.tp(f, to, "first"),
            "to_short": g.tp(f, to, "short"),
            "from_full": g.tp(f, frm, "full"), "from_first": g.tp(f, frm, "first"),
            "from_short": g.tp(f, frm, "short"),
            "from_title": g.r.choice(VOCAB["titles"]),
            "from_dept": g.r.choice(VOCAB["departments"]),
            "third_full": g.tp(f, third, "full"), "third_short": g.tp(f, third, "short"),
            "org": g.t(f, "ORG", org), "amount": g.t(f, "AMT", g.amount(), hard=False),
            "account": g.t(f, "BANK", g.account()), "inn": g.t(f, "ID", g.inn()),
            "phone": g.t(f, "PHONE", g.phone()), "pinfl": g.t(f, "ID", g.pinfl()),
            "passport": g.t(f, "ID", g.passport()),
            "host": g.t(f, "HOST", g.r.choice(g.hosts)),
            "ip": g.t(f, "IP", g.ip(public=g.r.random() < 0.3)),
            "login": g.t(f, "ACC", third.login), "password": g.t(f, "SECRET", g.password()),
            "email": g.t(f, "EMAIL", g.email(third)),
        }
        body = tpl["body"].format(**vals)
        # only placeholders actually used count as truth
        used = {k for k in vals if "{" + k + "}" in tpl["body"]}
        g.truth = [t for t in g.truth if t["file"] != f or t["value"] in body]
        msg = EmailMessage()
        msg["From"] = f"{g.t(f, 'PER', frm.last)} {frm.first} <{g.t(f, 'EMAIL', g.email(frm))}>"
        msg["To"] = f"{g.t(f, 'PER', to.last)} {to.first} <{g.t(f, 'EMAIL', g.email(to))}>"
        msg["Subject"] = tpl["subject"]
        msg["Date"] = "Mon, 02 Nov 2026 10:00:00 +0500"
        msg.set_content(body)
        (d / f).write_bytes(bytes(msg))
        assert used


def write_contracts(g: Gen, d: Path, n=3):
    from docx import Document
    for i in range(n):
        f = f"contract_{i + 1}.docx"
        o1, o2 = g.r.sample(VOCAB["orgs"], 2)
        d1, d2, c = g.pick(3)
        vals = {
            "num": f"{g.r.randint(10, 99)}/{g.r.randint(100, 999)}-26", "date": g.date(),
            "org1": g.t(f, "ORG", o1), "org2": g.t(f, "ORG", o2),
            "inn1": g.t(f, "ID", g.inn()), "inn2": g.t(f, "ID", g.inn()),
            "dir1_gen": g.tp(f, d1, "gen"), "dir2_gen": g.tp(f, d2, "gen"),
            "dir1_short": g.tp(f, d1, "short"), "dir2_short": g.tp(f, d2, "short"),
            "amount": g.t(f, "AMT", g.amount(), hard=False),
            "account": g.t(f, "BANK", g.account()),
            "contact_full": g.tp(f, c, "full"), "phone": g.t(f, "PHONE", g.phone()),
            "email": g.t(f, "EMAIL", g.email(c)),
        }
        doc = Document()
        for line in VOCAB["contract"]:
            doc.add_paragraph(line.format(**vals))
        doc.save(d / f)


def write_notes(g: Gen, d: Path, n=2):
    for i in range(n):
        f = f"notes/meeting_{i + 1}.md"
        (d / "notes").mkdir(exist_ok=True)
        p1, p2, p3, p4 = g.pick(4)
        vals = {
            "date": g.date(), "p1_short": g.tp(f, p1, "short"), "p2_short": g.tp(f, p2, "short"),
            "p3_short": g.tp(f, p3, "short"), "p4_full": g.tp(f, p4, "full"),
            "p1_surname": g.tp(f, p1, "surname"), "p2_dat": g.tp(f, p2, "dat"),
            "p3_surname": g.tp(f, p3, "surname"), "p4_surname": g.tp(f, p4, "dat"),
            "host": g.t(f, "HOST", g.r.choice(g.hosts)), "ip": g.t(f, "IP", g.ip()),
            "amount": g.t(f, "AMT", g.amount(), hard=False),
            "org": g.t(f, "ORG", g.r.choice(VOCAB["orgs"])),
        }
        (d / f).write_text("\n".join(x.format(**vals) for x in VOCAB["notes"]) + "\n",
                           encoding="utf-8")


def write_incidents(g: Gen, d: Path, n=2):
    from fpdf import FPDF
    for i in range(n):
        f = f"incident_{i + 1}.pdf"
        p1, p2, p3 = g.pick(3)
        h1, h2 = g.r.sample(g.hosts, 2)
        vals = {
            "num": f"INC-{g.r.randint(1000, 9999)}", "date": g.date(),
            "p1_full": g.tp(f, p1, "full"), "p1_short": g.tp(f, p1, "short"),
            "p2_full": g.tp(f, p2, "full"), "p3_full": g.tp(f, p3, "full"),
            "email": g.t(f, "EMAIL", g.email(p1)), "phone": g.t(f, "PHONE", g.phone()),
            "host": g.t(f, "HOST", h1), "host2": g.t(f, "HOST", h2),
            "ip": g.t(f, "IP", g.ip()), "ip2": g.t(f, "IP", g.ip()),
        }
        pdf = FPDF()
        pdf.add_page()
        pdf.add_font("uni", "", FONT)
        pdf.set_font("uni", size=11)
        for line in VOCAB["incident"]:
            pdf.multi_cell(0, 7, line.format(**vals))
            pdf.ln(1)
        pdf.output(str(d / f))


def write_configs(g: Gen, d: Path):
    (d / "configs").mkdir(exist_ok=True)
    for h in g.hosts[4:6]:
        f = f"configs/{h.split('.')[0]}.cfg"
        admin = g.r.choice([p for p in g.people if not p.cyr])
        lines = [
            f"hostname {g.t(f, 'HOST', h.split('.')[0])}",
            f"enable secret {g.t(f, 'SECRET', g.password())}",
            f"username admin privilege 15 secret {g.t(f, 'SECRET', g.password())}",
            f"snmp-server community {g.t(f, 'SECRET', 'c0mm-' + g.digits(6))} RO",
            "interface Vlan10",
            f" ip address {g.t(f, 'IP', g.ip())} 255.255.255.0",
            f"radius-server host {g.t(f, 'IP', g.ip())} key {g.t(f, 'SECRET', g.password())}",
            f"ntp server {g.t(f, 'IP', g.ip(public=True))}",
            f"banner motd ^ Owner: {g.tp(f, admin, 'full')} {g.t(f, 'PHONE', g.phone())} ^",
            "end",
        ]
        (d / f).write_text("\n".join(lines) + "\n", encoding="utf-8")

    f = "configs/app.env"
    svc = g.r.choice(g.people)
    lines = [
        f"DB_HOST={g.t(f, 'HOST', g.hosts[2])}",
        f"DB_USER={g.t(f, 'ACC', 'svc_' + svc.login.replace('.', '_'))}",
        f"DB_PASSWORD={g.t(f, 'SECRET', g.password())}",
        f"API_TOKEN={g.t(f, 'SECRET', ''.join(g.r.choice('0123456789abcdef') for _ in range(32)))}",
        f"ADMIN_EMAIL={g.t(f, 'EMAIL', g.email(svc))}",
        f"SMTP_RELAY={g.t(f, 'IP', g.ip())}",
    ]
    (d / f).write_text("\n".join(lines) + "\n", encoding="utf-8")

    f = "configs/backup.ps1"
    op = g.r.choice(g.people)
    lines = [
        f"$user = 'CORP\\{g.t(f, 'ACC', op.login)}'",
        f"$pass = ConvertTo-SecureString '{g.t(f, 'SECRET', g.password())}' -AsPlainText -Force",
        "$cred = New-Object System.Management.Automation.PSCredential($user, $pass)",
        f"Invoke-Command -ComputerName {g.t(f, 'HOST', g.hosts[6])} -Credential $cred "
        "-ScriptBlock { wbadmin start backup -quiet }",
    ]
    (d / f).write_text("\r\n".join(lines) + "\r\n", encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("case")
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args(argv)
    try:
        case = init_case(a.case, title=f"Synthetic {a.case}",
                         description="synthetic corpus with ground truth (fake data)")
    except CaseError:
        case = load_case(a.case)
        if case.source_files():
            print(f"error: case {a.case} already has data", file=sys.stderr)
            return 1
    g = Gen(a.seed)
    d = case.data_dir
    for fn in (write_ad_csv, write_hr_xlsx, write_emails, write_contracts, write_notes,
               write_incidents, write_configs):
        fn(g, d)
    uniq = {(t["file"], t["type"], t["value"]): t for t in g.truth}
    (case.root / "truth.json").write_text(json.dumps(list(uniq.values()), ensure_ascii=True,
                                                     indent=0), encoding="utf-8")
    print(f"{len(case.source_files())} files, {len(uniq)} truth entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
