import json
import sqlite3

import pytest
from conftest import IVANOV

from datavault.cases import init_case
from datavault.detect import regex_detect
from datavault.evaluate import evaluate
from datavault.ingest import IngestOptions, ingest, store_path
from datavault.parsers import chunk_text, parse
from datavault.store import HANDLE_RE, Store, is_noise

# Cyrillic as code points (ASCII-only sources)
PAROL = "\u043f\u0430\u0440\u043e\u043b\u044c"
IVANOVU = IVANOV + "\u0443"            # dative
IVANOVA_F = IVANOV + "\u0430"          # female / genitive
IVANOVOY = IVANOV + "\u043e\u0439"     # female dative
AZIZ = "\u0410\u0437\u0438\u0437"


def _det(text):
    return {(d.type, d.value) for d in regex_detect(text)}


@pytest.mark.parametrize("text,expected", [
    ("enable secret 2FWXWD5KaPHI", ("SECRET", "2FWXWD5KaPHI")),
    ("snmp-server community c0mm-590673 RO", ("SECRET", "c0mm-590673")),
    ("DB_PASSWORD=Summer2024!", ("SECRET", "Summer2024!")),
    (f"{PAROL} Welcome2021!. ok", ("SECRET", "Welcome2021!")),
    ("call (91) 996-03-08 now", ("PHONE", "(91) 996-03-08")),
    ("+998 90 123 45 67", ("PHONE", "+998 90 123 45 67")),
    ("acc 20201234567890123456", ("BANK", "20201234567890123456")),
    ("pinfl 31234567890123", ("ID", "31234567890123")),
    ("passport AB1234567", ("ID", "AB1234567")),
    ("$u = 'CORP\\a.karimov'", ("ACC", "a.karimov")),
    ("Invoke-Command -ComputerName srv-backup02 -Credential $c", ("HOST", "srv-backup02")),
    ("ping srv-dc01.corp.tpp.local", ("HOST", "srv-dc01.corp.tpp.local")),
    ("ntp server 91.55.49.24", ("IP", "91.55.49.24")),
    ("quote 19 800 000 UZS", ("AMT", "19 800 000")),
])
def test_regex_detects(text, expected):
    assert expected in _det(text)


@pytest.mark.parametrize("text", [
    "the key point is here",
    "snmp-server community",
    "password policy applies to everyone",
])
def test_regex_no_prose_secrets(text):
    assert not {t for t in _det(text) if t[0] == "SECRET"}


def test_noise_values():
    assert is_noise("ACC", "admin") and is_noise("IP", "255.255.255.0")
    assert not is_noise("IP", "10.1.2.3")


def test_store_handles_and_sweep(tmp_path):
    st = Store(tmp_path / "v.sqlite")
    h_full = st.add_entity("PER", f"{IVANOV} {AZIZ}", "test")
    h_short = st.add_entity("PER", f"{IVANOV} A.", "test")
    assert h_short == h_full  # linked by surname
    h_mail = st.add_entity("EMAIL", "a.ivanov@corp.test", "test")
    assert st.add_entity("ACC", "a.ivanov", "x") != h_mail  # login derived from email
    st.add_entity("PHONE", "+998 90 123 45 67", "test")
    sw = st.build_sweeper()
    text = (f"{IVANOVU} and {IVANOVA_F}, mail a.ivanov@corp.test, login a.ivanov, "
            f"call (90) 123-45-67; {AZIZ}")
    out = sw.apply(text)
    assert IVANOV not in out and "a.ivanov" not in out and "123" not in out
    assert AZIZ not in out
    assert len(set(HANDLE_RE.findall(out))) == 4  # person, email, login, phone
    assert st.counts()["PER"] == 1
    st.close()


def test_handles_stable_across_reopen(tmp_path):
    p = tmp_path / "v.sqlite"
    st = Store(p)
    h = st.add_entity("IP", "10.1.2.3", "t")
    st.close()
    st = Store(p)
    assert st.add_entity("IP", "10.1.2.3", "t") == h
    st.close()


def test_type_priority_retags(tmp_path):
    st = Store(tmp_path / "v.sqlite")
    h1 = st.add_entity("ACC", "x.Ivanov2!", "regex")
    h2 = st.add_entity("SECRET", "x.Ivanov2!", "regex")
    assert h1 != h2 and h2.startswith("[[DV:SECRET:") and h1[-8:] == h2[-8:]
    st.close()


def test_chunk_text_bounds():
    chunks = chunk_text("a" * 4000 + "\nb\n", size=1500)
    assert all(len(c) <= 1500 for c in chunks) and "".join(chunks).count("a") == 4000


def test_parse_types(case):
    kinds = {p.suffix: parse(p).kind for p in case.source_files()}
    assert kinds[".csv"] == "table" and kinds[".xlsx"] == "table"
    assert kinds[".txt"] == "text" and kinds[".pdf"] == "skipped"  # fake pdf, no text layer


def test_ingest_regex_only_and_eval(home):
    c = init_case("synth-mini", description="synthetic mini")
    (c.data_dir / "a.env").write_text(
        "DB_HOST=srv-sql01.corp.test\nDB_PASSWORD=Xy7!kLm2pQ\nADMIN_EMAIL=b.smith@corp.test\n")
    (c.data_dir / "b.txt").write_text(
        "Ask b.smith about srv-sql01.corp.test, password Xy7!kLm2pQ, phone +998 90 111 22 33\n")
    truth = [{"file": "a.env", "type": "SECRET", "value": "Xy7!kLm2pQ", "hard": True},
             {"file": "b.txt", "type": "SECRET", "value": "Xy7!kLm2pQ", "hard": True},
             {"file": "b.txt", "type": "ACC", "value": "b.smith", "hard": True},
             {"file": "b.txt", "type": "PHONE", "value": "+998 90 111 22 33", "hard": True}]
    (c.root / "truth.json").write_text(json.dumps(truth))
    rep = ingest(c, None, IngestOptions(llm=False, columns=False, embed=False))
    assert rep.files == 2 and rep.chunks == 2
    res = evaluate(c)
    assert res["recall_hard"] == 1.0, res["leaks"]
    db = sqlite3.connect(store_path(c))
    pseudo = "".join(r[0] for r in db.execute("SELECT pseudo FROM chunks"))
    assert "Xy7!kLm2pQ" not in pseudo and "DB_PASSWORD=[[DV:SECRET:" in pseudo
    assert oct(store_path(c).stat().st_mode)[-3:] == "600"


def test_status_tool(home):
    from mcp_helpers import call
    c = init_case("st-case")
    (c.data_dir / "x.txt").write_text("host 10.9.8.7\n")
    ingest(c, None, IngestOptions(llm=False, columns=False, embed=False))
    data = call("status", {"case": "st-case"})
    assert data["ingested"] and data["handles_by_type"] == {"IP": 1}
    assert "10.9.8.7" not in json.dumps(data)


@pytest.mark.parametrize("header,expected", [
    ("SamAccountName", "ACC"), ("UserPrincipalName", "ACC"), ("Mail", "EMAIL"),
    ("DisplayName", "PER"), ("DNSHostName", "HOST"), ("IPv4Address", "IP"),
    ("TelephoneNumber", "PHONE"), ("Password Last Set", "NONE"), ("whenCreated", "NONE"),
    ("DistinguishedName", "NONE"), ("Name", None), ("ФИО", "PER"),
])
def test_header_rules(header, expected):
    from datavault.detect import header_type
    assert header_type(header) == expected


def test_header_rules_skip_llm(home):
    from datavault.detect import table_detect
    from datavault.parsers import Table
    t = Table("t1", ["SamAccountName", "Mail", "Enabled"],
              [["j.doe", "j.doe@corp.test", "True"], ["a.lee", "a.lee@corp.test", "False"]])
    found = {(d.type, d.value) for d in table_detect(None, t)}
    assert ("ACC", "j.doe") in found and ("EMAIL", "a.lee@corp.test") in found
    assert not any(v in ("True", "False") for _, v in found)


@pytest.mark.parametrize("typ,value", [
    ("SECRET", "Veeam"),
    ("PER", "\u0418\u0441\u043f\u043e\u043b\u043d\u0438\u0442\u0435\u043b\u044c"),
    ("HOST", "103"), ("HOST", "LAG"), ("ACC", "for"), ("ID", "NFS"), ("ORG", "SAP"),
    ("EMAIL", "____"), ("AMT", "4.0"), ("IP", "OOB"),
])
def test_implausible_values_rejected(tmp_path, typ, value):
    st = Store(tmp_path / "v.sqlite")
    assert st.add_entity(typ, value, "llm") is None
    st.close()


def test_header_origin_trusted(tmp_path):
    st = Store(tmp_path / "v.sqlite")
    assert st.add_entity("SECRET", "qwerty", "header")  # weak password in a Password column
    assert st.add_entity("SECRET", "qwerty", "llm")  # same value, already known
    assert st.add_entity("SECRET", "letmein", "llm") is None
    st.close()


def test_product_words_not_entities(tmp_path):
    st = Store(tmp_path / "v.sqlite")
    for typ, v in (("ACC", "ESXi"), ("ACC", "vCenter"), ("AMT", "1500"), ("AMT", "02:00"),
                   ("SECRET", "das.isolationaddress0"), ("PER", "HPE OneView")):
        assert st.add_entity(typ, v, "llm") is None, (typ, v)
    assert st.add_entity("ACC", "a.karimov", "llm") and st.add_entity("AMT", "78 000 000", "llm")
    st.close()


def test_alias_not_promoted_by_implausible_type(tmp_path):
    st = Store(tmp_path / "v.sqlite")
    h = st.add_entity("PER", "Veeamov Ivan", "llm")  # alias "Veeamov"
    assert st.add_entity("SECRET", "Veeamov", "llm") == h  # stays the person's alias
    assert st.counts() == {"PER": 1}
    st.close()


def test_sweep_after_dot_and_dc_form():
    from datavault.store import Entity, Sweeper
    sw = Sweeper([Entity("[[DV:HOST:aaaaaa]]", "HOST", "corp.example"),
                  Entity("[[DV:HOST:bbbbbb]]", "HOST", "DC=corp,DC=example"),
                  Entity("[[DV:ACC:cccccc]]", "ACC", "example")])
    out = sw.apply("srv1.corp.example CN=x,OU=y,DC=corp,DC=example other.example")
    assert out == ("srv1.[[DV:HOST:aaaaaa]] CN=x,OU=y,[[DV:HOST:bbbbbb]] other.example")


def test_ip_ranges_and_templates():
    found = {(d.type, d.value) for d in regex_detect(
        "OOB 10.55.55.<N>, range 10.55.50-55.0/24, hosts 10.1.2.x")}
    assert {("IP", "10.55.55.<N>"), ("IP", "10.55.50-55.0/24"), ("IP", "10.1.2.x")} <= found
    assert is_noise("IP", "255.255.255.0") and not is_noise("IP", "10.55.50.0/24")


def test_host_short_and_fqdn_share_handle(tmp_path):
    st = Store(tmp_path / "v.sqlite")
    h1 = st.add_entity("HOST", "erp_bkp02.corp.local", "regex")
    assert st.add_entity("HOST", "erp_bkp02", "header") == h1
    h2 = st.add_entity("HOST", "srv-01", "header")
    assert st.add_entity("HOST", "srv-01.corp.local", "regex") == h2
    assert st.add_entity("HOST", "erpxbkp02", "header") != h1  # "_" is literal in LIKE
    st.close()


def test_placeholders_and_small_numbers(tmp_path):
    st = Store(tmp_path / "v.sqlite")
    assert st.add_entity("EMAIL", "______", "header") is None
    assert st.add_entity("SECRET", "4096", "llm") is None
    assert st.add_entity("ADDR", "30 d", "llm") is None
    assert st.add_entity("ADDR", "Tashkent, Amir Temur street 108", "llm")
    st.close()
