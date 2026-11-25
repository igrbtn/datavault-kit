import pytest
from openpyxl import Workbook

from datavault.cases import init_case

# Cyrillic test data as code points (ASCII-only sources)
IVANOV = "\u0418\u0432\u0430\u043d\u043e\u0432"          # surname
FIO = "\u0424\u0418\u041e"                                 # "full name"
SECRET_SURNAME_FILE = f"{IVANOV}_salary.csv"
CARD = "4111 1111 1111 1111"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("DATAVAULT_HOME", str(tmp_path))
    return tmp_path


@pytest.fixture
def case(home):
    c = init_case("demo-case", title="Demo", description="test case")
    (c.data_dir / SECRET_SURNAME_FILE).write_text(
        f"{FIO};amount;date;active\n{IVANOV};1200.50;2026-01-02;yes\nPetrov;300;2026-02-03;no\n",
        encoding="utf-8",
    )
    wb = Workbook()
    ws = wb.active
    ws.title = "Staff"
    ws.append(["login", CARD, "age"])
    ws.append(["jdoe", "x", 31])
    ws.append(["asmith", None, 45])
    wb.save(c.data_dir / "hr.xlsx")
    (c.data_dir / "notes.txt").write_text("line1\nline2\n", encoding="utf-8")
    (c.data_dir / "scan.pdf").write_bytes(b"%PDF-1.4 fake")
    return c
