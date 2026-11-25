"""Regression bench on the public dlptest.com sample datasets (synthetic PII/PCI).

Fixtures in tests/fixtures/dlptest/ were downloaded from https://dlptest.com/sample-data/
("All values are fabricated test data"). Ground truth is derived from the CSV columns:
Name -> PER, SSN -> ID, Credit Card Number -> BANK, Email -> EMAIL; the docx/pdf/xlsx carry
the same rows as name-ssn-ccn.csv. Dates, ZIPs and expiry are not truth: they must NOT
become entities (that is what unrelated_values counts).

    DATAVAULT_HOME=<scratch> .venv/bin/python scripts/dlptest_bench.py [--no-llm]
"""
import csv
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "dlptest"
DV = Path(sys.executable).with_name("datavault")  # the venv that runs this script
CASE = "bench-dlp"
COLS = {"Name": "PER", "SSN": "ID", "Credit Card Number": "BANK", "Email": "EMAIL"}


def build_truth() -> list[dict]:
    truth = []
    for f in sorted(FIXTURES.glob("*.csv")):
        with open(f, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        for r in rows:
            if "First Name" in r:
                truth.append({"file": f.name, "type": "PER", "value": r["First Name"],
                              "hard": False})
                truth.append({"file": f.name, "type": "PER", "value": r["Last Name"],
                              "hard": True})
            for col, typ in COLS.items():
                if r.get(col):
                    truth.append({"file": f.name, "type": typ, "value": r[col], "hard": True})
    base = [t for t in truth if t["file"] == "dlptest-name-ssn-ccn.csv"]
    for ext in ("docx", "pdf", "xlsx"):
        truth += [{**t, "file": f"dlptest-name-ssn-ccn.{ext}"} for t in base]
    return truth


def main() -> int:
    home = Path(os.environ.get("DATAVAULT_HOME", "")).expanduser()
    if not os.environ.get("DATAVAULT_HOME"):
        print("set DATAVAULT_HOME to a scratch dir", file=sys.stderr)
        return 2
    case_dir = home / "cases" / CASE
    if case_dir.exists():
        shutil.rmtree(case_dir)
    subprocess.run([DV, "case-new", CASE, "--title", "dlptest.com samples", "--description",
                    "synthetic: dlptest.com PII/PCI datasets"], check=True, capture_output=True)
    for f in FIXTURES.iterdir():
        shutil.copy(f, case_dir / "data" / f.name)
    truth = build_truth()
    (case_dir / "truth.json").write_text(json.dumps(truth, indent=1))
    subprocess.run([DV, "ingest", CASE, *sys.argv[1:]], check=True, capture_output=True)
    out = subprocess.run([DV, "eval", CASE], check=True, capture_output=True, text=True).stdout
    rep = json.loads(out[out.index("{"):])
    print(f"dlptest: recall_hard={rep['recall_hard']} recall_all={rep['recall_all']} "
          f"leaks={rep['leaks']} unrelated={rep['unrelated_values']} "
          f"truth={len(truth)} not_in_text={rep['truth_not_in_text']}")
    return 0 if rep["leaks"] == 0 and not rep["unrelated_values"] else 1


if __name__ == "__main__":
    sys.exit(main())
