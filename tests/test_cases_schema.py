import json

import pytest
from conftest import CARD, IVANOV

from datavault.cases import CaseError, init_case, list_cases, load_case
from datavault.inspect_src import inspect_source, list_sources


def test_case_name_rejects_traversal(home):
    for bad in ("../x", "A", "a/b", "", "x" * 70):
        with pytest.raises(CaseError):
            init_case(bad)
    with pytest.raises(CaseError):
        load_case("..")


def test_list_and_duplicate(case):
    assert [c.name for c in list_cases()] == ["demo-case"]
    with pytest.raises(CaseError):
        init_case("demo-case")


def test_sources_masked_by_default(case):
    srcs = list_sources(case)
    assert [s["id"] for s in srcs] == ["f001", "f002", "f003", "f004"]
    blob = json.dumps(srcs, ensure_ascii=False)
    assert IVANOV not in blob
    assert "hr" not in [s["label"] for s in srcs]


def _src_id(case, name):
    ids = {p.name: f"f{i:03d}" for i, p in enumerate(case.source_files(), start=1)}
    return ids[name]


def test_csv_structure_no_values(case):
    fid = next(s["id"] for s in list_sources(case) if s["ext"] == ".csv")
    info = inspect_source(case, fid)
    t = info["tables"][0]
    assert t["rows"] == 2
    types = [c["type"] for c in t["columns"]]
    assert types == ["text", "float", "date", "bool"]
    blob = json.dumps(info, ensure_ascii=False)
    assert IVANOV not in blob and "Petrov" not in blob and "1200" not in blob


def test_xlsx_dlp_on_column_labels(case):
    info = inspect_source(case, _src_id(case, "hr.xlsx"))
    sheet = info["tables"][0]
    assert sheet["label"] == "Staff"
    labels = [c["label"] for c in sheet["columns"]]
    assert labels[0] == "login"
    assert labels[1] == "[[REDACTED]]"
    assert CARD not in json.dumps(info)
    assert sheet["columns"][2]["type"] == "int"
    assert "jdoe" not in json.dumps(info)


def test_text_and_binary(case):
    txt = inspect_source(case, _src_id(case, "notes.txt"))
    assert txt["kind"] == "text" and txt["text_chunks"] == 1
    assert inspect_source(case, _src_id(case, "scan.pdf"))["kind"] == "skipped"


def test_xlsx_title_row_skipped(home):
    from openpyxl import Workbook

    from datavault.cases import init_case
    c = init_case("xl-case")
    wb = Workbook()
    ws = wb.active
    ws.append(["Inventory of site A"])
    ws.append([])
    ws.append(["Hostname", "Role", "OS"])
    ws.append(["srv-01", "DC", "Windows 2022"])
    wb.save(c.data_dir / "inv.xlsx")
    info = inspect_source(c, "f001")
    assert [col["label"] for col in info["tables"][0]["columns"]] == ["Hostname", "Role", "OS"]
    assert info["tables"][0]["rows"] == 1


def test_unknown_source(case):
    with pytest.raises(CaseError):
        inspect_source(case, "f999")


def test_case_rm_removes_only_derived_files(home, tmp_path):
    from datavault.cases import case_footprint, delete_case, init_case, list_cases
    src = tmp_path / "customer"
    src.mkdir()
    (src / "export.csv").write_text("a,b\n1,2\n")
    c = init_case("auto-x", source_dir=str(src), include=["export.csv"])
    (c.out_dir / "report.md").write_text("x")
    (c.root / "store.db.bak-1").write_text("x")
    fp = case_footprint("auto-x")
    assert fp["out_files"] == 1 and fp["store_backups"] == 1 and not fp["copies_of_sources"]
    delete_case("auto-x")
    assert list_cases() == [] and (src / "export.csv").exists()
