import io
import json

from test_p2 import SECRET, p2case  # noqa: F401

from datavault import promptguard
from datavault.promptguard import Policy, scan


def test_secret_blocks_and_is_cut(tmp_path, monkeypatch):
    monkeypatch.setenv("DATAVAULT_HOME", str(tmp_path))
    v = scan("connect with AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY please")
    assert v.decision == "block" and v.regex["SECRET"] == 1
    assert "wJalrXUtnFEMI" not in v.masked and "[AWS_SECRET_ACCESS_KEY_1]" in v.masked
    assert v.verdicts["secrets"] == "block" and v.verdicts["injection"] == "ok"


def test_case_value_blocks_and_becomes_handle(p2case):  # noqa: F811
    v = scan("what runs on srv-sql01.corp.test and who is the admin")
    assert v.decision == "block" and "p2" in next(iter(v.cases))
    assert "srv-sql01" not in v.masked and "[[DV:HOST:" in v.masked


def test_plain_prompt_passes_fast(p2case):  # noqa: F811
    v = scan("please summarise the backup policy and list open risks")
    assert v.decision == "ok" and v.seconds < 1.0


def test_ip_only_warns_and_allow_pattern(tmp_path, monkeypatch):
    monkeypatch.setenv("DATAVAULT_HOME", str(tmp_path))
    v = scan("ping 10.77.1.5 from the jump host")
    assert v.decision == "warn" and v.regex["IP"] == 1
    (tmp_path / "promptguard.yaml").write_text("allow: ['^10[.]77[.]']\n")
    assert scan("ping 10.77.1.5 from the jump host", Policy.load()).decision == "ok"


def test_hook_json_contract(tmp_path, monkeypatch):
    monkeypatch.setenv("DATAVAULT_HOME", str(tmp_path))
    out = io.StringIO()
    rc = promptguard.hook_main(io.StringIO(json.dumps({"prompt": "token ghp_" + "a1" * 20})), out)
    d = json.loads(out.getvalue())
    assert rc == 0 and d["decision"] == "block" and "ghp_a1a1" not in d["reason"]
    out = io.StringIO()
    rc = promptguard.hook_main(io.StringIO("not json"), out)
    assert rc == 0 and out.getvalue() == ""


def test_url_password_and_key_name_kept(tmp_path, monkeypatch):
    monkeypatch.setenv("DATAVAULT_HOME", str(tmp_path))
    pw = "Super" + "SecretPassword123"
    v = scan(f"DATABASE_URL=postgresql://prod_admin:{pw}@10.10.20.15:5432/db "
             "JWT_SECRET=9f8a7b6c5d4e3f2a1b0c ok")
    assert v.decision == "block" and v.regex["SECRET"] == 2 and v.regex["IP"] == 1
    assert pw not in v.masked and "9f8a7b6c" not in v.masked
    assert "prod_admin:[URL_PASSWORD_1]@10.10.20.15" in v.masked
    assert "JWT_SECRET=[JWT_SECRET_1]" in v.masked


def test_url_password_without_user(tmp_path, monkeypatch):
    monkeypatch.setenv("DATAVAULT_HOME", str(tmp_path))
    v = scan("REDIS_URL=redis://:RedisPass" + "word123@10.10.20.20:6379/0 and 10.10.20.15")
    assert v.regex["SECRET"] == 1 and v.regex["IP"] == 2
    assert "redis://:[URL_PASSWORD_1]@10.10.20.20" in v.masked


def test_masked_copy_passes_when_pasted_back(tmp_path, monkeypatch):
    monkeypatch.setenv("DATAVAULT_HOME", str(tmp_path))
    pw = "Redis" + "Secret123"
    first = scan(f"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\n"
                 f"REDIS_URL=redis://:{pw}@10.10.20.20:6379/0\nJWT_SECRET=9f8a7b6c5d4e3f2a1b0c")
    assert first.decision == "block" and first.regex["SECRET"] == 3
    again = scan(first.masked)
    assert again.decision == "warn" and again.regex["SECRET"] == 0 and again.masked == first.masked


def test_harness_notifications_and_tool_ids_pass(tmp_path, monkeypatch):
    monkeypatch.setenv("DATAVAULT_HOME", str(tmp_path))
    note = ("<task-notification>\n<tool-use-id>toolu_01AbCdEfGhIjKlMnOpQrStUv</tool-use-id>\n"
            "<status>completed</status>\n</task-notification>")
    assert scan(note).decision == "ok"
    # the same id typed by a human is still not a secret
    assert scan("look at toolu_01AbCdEfGhIjKlMnOpQrStUv please").regex["SECRET"] == 0
