"""Entity detection on raw text: regex rules, table column typing, local LLM NER.

Detection feeds the handle store; replacement in text is done later by the sweep,
so a detector only has to find a value once anywhere in the case.
"""
from __future__ import annotations

import pathlib
import re
from dataclasses import dataclass

from .dlp.detectors import scan
from .gateway import GatewayError, ModelGateway
from .parsers import Table
from .store import name_like, random_letters, surname_shaped

TYPES = ["PER", "ORG", "ACC", "EMAIL", "PHONE", "HOST", "IP", "ID", "BANK", "SECRET", "ADDR",
         "AMT"]

_DLP_MAP = {
    "uz_bank_card": "BANK", "credit_card": "BANK", "iban": "BANK",
    "uz_pinfl": "ID", "uz_inn": "ID", "uz_passport": "ID", "ru_passport": "ID", "ru_snils": "ID",
    "uz_phone": "PHONE", "ru_phone": "PHONE", "email": "EMAIL", "ipv4_private": "IP",
}


# keyword=value matches: our own rules capture just the value, keeping the key readable
_SKIP_DLP = {"password", "api_secret"}


@dataclass(frozen=True)
class Detection:
    type: str
    value: str
    source: str     # regex | column | llm


def _d(typ, value, source="regex"):
    value = value.strip().strip("'\"")
    return Detection(typ, value, source) if len(value) >= 2 else None


_PAROL = "\u043f\u0430\u0440\u043e\u043b"  # Russian "parol" stem (parol', parolya, ...)
_WEAK_SECRET = re.compile(r"(?i)(?<!\w)(?:secret|password|passwd|key|community|pre-shared-key|"
                          r"psk|" + _PAROL + r"\w{0,2})\s*[:=]?\s+(?:\d\s+)?(?![<\[{])"
                          r"([^\s'\"]{4,}?)[.,;:)]*(?=\s|$)", re.MULTILINE)

_KV_SECRET = re.compile(r"(?im)^\s*(?:export\s+|set\s+)?[A-Z0-9_]*(?:PASS|PASSWORD|PASSWD|"
                          r"SECRET|TOKEN|KEY|PWD|CREDENTIAL)[A-Z0-9_]*\s*[=:]\s*['\"]?"
                          r"([^'\"\s#]+)")

_RULES: list[tuple[str, re.Pattern[str], int]] = [
    # ranges and templates of an addressing plan: 10.55.50-55.0/24, 10.55.55.<N>, 10.1.2.x
    ("IP", re.compile(r"(?<![\d.])\d{1,3}\.\d{1,3}\.\d{1,3}(?:-\d{1,3})?\."
                      r"(?:\d{1,3}-\d{1,3}|[xX*]|<\w+>|N)(?:/\d{1,2})?(?![\w.])|"
                      r"(?<![\d.])\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}\.\d{1,3}(?:/\d{1,2})?"
                      r"(?![\d.])"), 0),
    ("IP", re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
                      r"(?:/\d{1,2})?(?![\d.])"), 0),
    # IPv6 (ULA prefixes of a plan, global addresses); validated in ipv6_ok
    ("IP", re.compile(r"(?i)(?<![\w:])(?:[0-9a-f]{1,4}:){1,7}(?::|(?::[0-9a-f]{1,4}){1,6}|"
                      r"[0-9a-f]{1,4})(?:/\d{1,3})?(?![\w:])"), 0),
    ("HOST", re.compile(r"(?i)\b(?=[a-z0-9-]*[a-z])[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\."
                        r"(?:local|lan|corp|internal|intra|loc|test|uz|ru|kz)\b"), 0),
    ("HOST", re.compile(r"(?im)^\s*(?:hostname|sysname|set system host-name|"
                        r"/system identity set name=)\s*\"?([\w.-]+)"), 1),
    ("HOST", re.compile(r"(?i)(?:^|\s)-(?:ComputerName|Server|HostName)\s+['\"]?([\w.-]+)"), 1),
    # US SSN (area 001-899 except 666, group 01-99, serial 0001-9999)
    ("ID", re.compile(r"(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])"), 0),
    ("SECRET", _KV_SECRET, 1),
    ("SECRET", _WEAK_SECRET, 1),
    # vendor syntax with a format word before the value: Aruba "password ciphertext X",
    # Cisco "secret 9 X", Huawei "password cipher X", MikroTik "password=X"
    ("SECRET", re.compile(r"(?i)\b(?:password|secret|key|community)\s+(?:ciphertext|plaintext|"
                          r"cipher|irreversible-cipher|encrypted|hashed|sha256|md5|"
                          r"\d{1,2})\s+(\S{4,})"), 1),
    ("ID", re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b|\b(?:[0-9a-f]{4}\.){2}"
                      r"[0-9a-f]{4}\b"), 0),
    ("SECRET", re.compile(r"(?i)ConvertTo-SecureString\s+['\"]([^'\"]+)['\"]"), 1),
    ("SECRET", re.compile(r"(?i)-(?:Password|Pass|Secret|Token)\s+['\"]([^'\"]+)['\"]"), 1),
    ("PHONE", re.compile(r"\(\d{2}\)\s?\d{3}[\s-]\d{2}[\s-]\d{2}\b"), 0),
    ("PHONE", re.compile(r"\+?998[\s-]?\d{2}[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}\b"), 0),
    ("BANK", re.compile(r"\b\d{20}\b"), 0),
    ("AMT", re.compile(r"(?i)(?<![\w.])(\d{1,3}(?:[ \u00a0]\d{3})+(?:[.,]\d+)?|\d{4,}(?:[.,]\d+)?)\s*"
                       r"(?:\u0441\u0443\u043c|uzs|usd|eur|rub|\u0440\u0443\u0431|so'm)\b"), 1),
    ("AMT", re.compile(r"(?<![\w$])\$\s?(\d[\d,. ]*\d)"), 1),
    ("ID", re.compile(r"\b[3-6]\d{13}\b"), 0),
    ("ID", re.compile(r"\b[A-Z]{2}\d{7}\b"), 0),
    ("ACC", re.compile(r"(?i)\b(?:[A-Z][A-Z0-9-]{1,14})\\([\w.$-]{2,})"), 1),
    ("ACC", re.compile(r"(?im)^\s*[A-Z0-9_]*(?:USER|LOGIN|USERNAME)[A-Z0-9_]*\s*[=:]\s*['\"]?"
                       r"([^'\"\s#]+)"), 1),
    ("ACC", re.compile(r"(?i)\busername\s+([\w.$-]{2,})"), 1),
]


def regex_detect(text: str) -> list[Detection]:
    out = []
    for f in scan(text):
        if f.detector in _SKIP_DLP or not _plausible(f):
            continue
        typ = _DLP_MAP.get(f.detector) or ("SECRET" if f.category in ("secret", "credential")
                                              else None)
        val = f.value
        if f.detector == "high_entropy_secret" and _LABEL_SHAPE.fullmatch(val):
            typ = "HOST"
        if typ in ("ID", "BANK") and (m := re.search(r"[A-Z]{0,2}\d[\d\s-]{6,}\d", val)):
            val = m.group(0)  # drop keyword prefixes such as "pinfl " captured with the number
        if typ and (d := _d(typ, val, f"regex/{f.detector}")):
            out.append(d)
    for n, (typ, rx, grp) in enumerate(_RULES):
        for m in rx.finditer(text):
            val = m.group(grp)
            if (rx is _WEAK_SECRET or rx is _KV_SECRET) and not _secret_like(val):
                continue
            if typ == "IP" and ":" in val and not ipv6_ok(val):
                continue
            if d := _d(typ, val, f"regex/{typ.lower()}{n}"):
                out.append(d)
    return out


def ipv6_ok(v: str) -> bool:
    """A real IPv6 address/prefix, not a MAC (aa:bb:cc:dd:ee:ff), a time or loopback."""
    import ipaddress
    groups = v.split("/")[0].split(":")
    if "::" not in v and len(groups) != 8:
        return False
    if sum(1 for g in groups if g) < 3:
        return False  # "abc::def" in code, not an address
    if all(len(g) == 2 for g in groups if g):
        return False
    try:
        ip = ipaddress.ip_interface(v).ip
    except ValueError:
        return False
    # link-local stays: its interface id is derived from the MAC, which is masked too
    return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast)


# dash/underscore-joined readable segments: VM, snapshot and datastore names
_LABEL_SHAPE = re.compile(r"[A-Za-z][A-Za-z0-9]{1,}(?:[-_][A-Za-z0-9]{2,}){1,6}")
_HYPHEN_WORDS = re.compile(r"[a-z]{3,}(?:-[a-z]{3,})+")


def _secret_like(v: str) -> bool:
    """Prose guard for the 'keyword value' rule: a real secret has a digit or a symbol
    ("Password Last Set", "Never Expires" must not count)."""
    if v.isdigit():
        return len(v) >= 8  # "key 1234" is a port, a PIN column or a counter, not a secret
    if len(v) < 6 or _HYPHEN_WORDS.fullmatch(v):
        return False  # "key guest-operations" names a feature, not a secret
    return bool(re.search(r"\d", v) or re.search(r"[^\w]", v)) or random_letters(v)


def _plausible(f) -> bool:
    """Drop DLP detector hits that are AD/infra artefacts rather than secrets or bank data."""
    v = f.value
    if f.detector == "high_entropy_secret":
        # canonical names / paths (corp.example/Branches/Users) and digit-free words;
        # a slash next to underscores, dashes or dots is a path ([DS_01] folder/vm.vmdk),
        # a base64 key has slashes but none of those
        if "/" in v and re.search(r"[_.\-\\\[\]]", v):
            return False
        return bool(re.search(r"\d", v)) and v.count("/") < 2
    if f.detector == "credit_card":
        groups = re.split(r"[\s-]", v.strip())
        if len(groups) > 1:
            return all(len(g) == 4 for g in groups)
        # a bare digit run passes Luhn one time in ten: byte counts and ids are not cards.
        # Unformatted, only 15-16 digits with a card network prefix count
        return len(v) in (15, 16) and v[0] in "3456"
    if f.detector == "iban":
        return "-" not in v
    if f.detector == "ru_snils":
        return "." not in v
    return True


# --- local LLM -----------------------------------------------------------------

NER_SYSTEM = """You extract sensitive entities from documents for pseudonymization.
Return every occurrence of:
PER person name or surname (any form: full, initials, declined Russian forms like Karimovu),
ORG organization name, ACC account/login, EMAIL, PHONE, HOST hostname/server name,
IP address, ID passport/PINFL/INN/tax or personal id, BANK account/card number,
SECRET password/key/token/community string, ADDR street address, AMT money amount.
Copy each entity text EXACTLY as it appears in the document (same case, same spelling,
same grammatical form). Do not normalize, translate or invent. Do not include job titles,
departments or generic words. If none, return an empty list."""

NER_SCHEMA = {
    "type": "object",
    "properties": {
        "entities": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"type": {"type": "string", "enum": TYPES},
                               "text": {"type": "string"}},
                "required": ["type", "text"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["entities"],
    "additionalProperties": False,
}

COLUMN_SYSTEM = """You classify a table column by its header and sample values.
Answer the entity type if the column holds identifying or secret values, else NONE.
Types: PER person names, ORG organizations, ACC logins/accounts, EMAIL, PHONE, HOST hostnames,
IP addresses, ID personal/tax/passport ids, BANK bank accounts/cards, SECRET passwords/keys,
ADDR addresses, AMT money amounts (salaries, prices). Dates, departments, job titles,
statuses, booleans, counts, model names -> NONE."""

COLUMN_SCHEMA = {
    "type": "object",
    "properties": {"type": {"type": "string", "enum": TYPES + ["NONE"]}},
    "required": ["type"],
    "additionalProperties": False,
}


def llm_detect(gw: ModelGateway, text: str) -> list[Detection]:
    try:
        data, _ = gw.complete_json(
            "ner",
            [{"role": "system", "content": NER_SYSTEM}, {"role": "user", "content": text}],
            NER_SCHEMA, max_tokens=2048)
    except GatewayError:
        return []
    out = []
    for e in data.get("entities", []):
        val, typ = str(e.get("text", "")).strip(), e.get("type")
        # keep only verbatim spans: a hallucinated value cannot be swept anyway
        if typ in TYPES and val and val in text and (d := _d(typ, val, "llm")):
            out.append(d)
    return out


# Self-describing headers (AD exports, HR sheets, inventories): decided without the LLM.
# Matched against the header lowercased with non-alphanumerics removed.
# "name" is deliberately absent: a person in Users.csv, a host in Computers.csv.
HEADER_RULES: list[tuple[str, str]] = [
    (r"(samaccountname|userprincipalname|upn|logonname|username|login|account(name)?|"
     r"\u043b\u043e\u0433\u0438\u043d|\u0443\u0447\u0435\u0442\u043d\w*|\u0443\u0447\u0451\u0442\u043d\w*)", "ACC"),
    (r"(e?mail(address)?|\u043f\u043e\u0447\u0442\u0430|\u044d\u043b\u0435\u043a\u0442\u0440\u043e\u043d\u043d\u0430\u044f\u043f\u043e\u0447\u0442\u0430|proxyaddresses)", "EMAIL"),
    (r"(displayname|fullname|givenname|firstname|lastname|surname|sn|middlename|manager|"
     r"\u0444\u0438\u043e|\u0444\u0430\u043c\u0438\u043b\u0438\u044f|\u0438\u043c\u044f|\u043e\u0442\u0447\u0435\u0441\u0442\u0432\u043e|\u0441\u043e\u0442\u0440\u0443\u0434\u043d\u0438\u043a|\u043e\u0442\u0432\u0435\u0442\u0441\u0442\u0432\u0435\u043d\u043d\w*)", "PER"),
    (r"(dnshostname|hostname|computername|fqdn|servername|dnsname|netbios(name)?|\u0445\u043e\u0441\u0442|\u0438\u043c\u044f\u0445\u043e\u0441\u0442\u0430|\u0441\u0435\u0440\u0432\u0435\u0440)",
     "HOST"),
    (r"(ipv4address|ipv6address|ipaddress|ip|ip\u0430\u0434\u0440\u0435\u0441|\u0430\u0434\u0440\u0435\u0441ip)", "IP"),
    (r"(telephonenumber|telephone|mobile|mobilephone|ipphone|homephone|phone|\u0442\u0435\u043b\u0435\u0444\u043e\u043d\w*)",
     "PHONE"),
    # a SID is domain SID + RID: it identifies the tenant and the account; as a handle it
    # still joins GroupMembers to Users (same value = same handle)
    (r"(objectsid|sid|sidhistory|objectguid|guid|memberobjectsid|membersid|msdscreatorsid|creatorsid|\w*sid)", "ID"),
    # card and SSN columns: a short or Luhn-invalid value is still the customer's number
    (r"(creditcard\w*|cardnumber|cardno|pan|ccn|iban|account(number|no)|"
     r"\u043d\u043e\u043c\u0435\u0440\u043a\u0430\u0440\u0442\u044b|\u0441\u0447\u0435\u0442|\u0441\u0447\u0451\u0442)", "BANK"),
    (r"(ssn|socialsecurity\w*|nationalid|taxid|tin)", "ID"),
    # dates are not identifiers on their own
    (r"(\w*(date|dob|birth|expiry|expires|expiration)\w*)", "NONE"),
    (r"(employeeid|employeenumber|pinfl|\u043f\u0438\u043d\u0444\u043b|passport|\u043f\u0430\u0441\u043f\u043e\u0440\u0442\w*|inn|\u0438\u043d\u043d|snils|\u0441\u043d\u0438\u043b\u0441)", "ID"),
    (r"(password|passwd|pwd|secret|apikey|token|\u043f\u0430\u0440\u043e\u043b\u044c)", "SECRET"),
    (r"(salary|\u043e\u043a\u043b\u0430\u0434|\u0437\u0430\u0440\u043f\u043b\u0430\u0442\u0430|\u0441\u0443\u043c\u043c\u0430|amount)", "AMT"),
    # AD "company" is the employer, i.e. usually the customer itself
    (r"(company|organization|organisation|\u043a\u043e\u043c\u043f\u0430\u043d\u0438\u044f|"
     r"\u043e\u0440\u0433\u0430\u043d\u0438\u0437\u0430\u0446\u0438\u044f)", "ORG"),
    (r"(streetaddress|address|\u0430\u0434\u0440\u0435\u0441|homeaddress)", "ADDR"),
    # structural / non-identifying: skip the LLM
    (r"(distinguishedname|dn|canonicalname|objectguid|\w*sid|sidhistory|\w*guid|rid|"
     r"\w*(date|time|created|changed|modified|lastlogon\w*|pwdlastset|passwordlastset|"
     r"expires|age|days|count|enabled|disabled|flag\w*|status|version|level|type|class|"
     r"os|operatingsystem\w*|servicepack|description|title|department|company|office|"
     r"ou|path|site|domain|policy|gpo\w*|\u0434\u043e\u043b\u0436\u043d\u043e\u0441\u0442\u044c|\u043e\u0442\u0434\u0435\u043b|\u043f\u043e\u0434\u0440\u0430\u0437\u0434\u0435\u043b\u0435\u043d\u0438\u0435|\u0434\u0430\u0442\u0430\w*|\u0441\u0442\u0430\u0442\u0443\u0441))",
     "NONE"),
]
_HEADER_RX = [(re.compile(rf"^{p}$"), t) for p, t in HEADER_RULES]


def header_type(header: str) -> str | None:
    key = re.sub(r"[^\w]|_", "", header.casefold())
    if not key:
        return None
    for rx, typ in _HEADER_RX:
        if rx.match(key):
            return typ
    return None


_DICT_PATH = pathlib.Path("/usr/share/dict/words")
_dict_words: set[str] | None = None


def is_dict_word(w: str) -> bool:
    """Common-language word per the system dictionary (empty set when there is none)."""
    global _dict_words
    if _dict_words is None:
        try:
            _dict_words = {x.strip().casefold() for x in _DICT_PATH.read_text().splitlines()
                           if len(x) > 3}
        except OSError:
            _dict_words = set()
    w = w.casefold()
    # web2 lists lemmas: "computer", not "computers"
    return w in _dict_words or (w.endswith("s") and w[:-1] in _dict_words) \
        or (w.endswith("es") and w[:-2] in _dict_words)


_PERSON_HEADER = re.compile(r"(givenname|firstname|lastname|surname|middlename|title|"
                            r"department|employee|samaccountname|userprincipalname|mail)")
_NAME_HEADER = re.compile(r"^(displayname|fullname|manager|name)$")
# identifiers that belong to a person (a GUID or SID column does not make a table about people)
_PERSON_KEY = re.compile(r"(ssn|socialsecurity|nationalid|taxid|^tin$|pinfl|passport|employee|"
                         r"creditcard|cardnumber|^ccn$|^pan$|iban|phone|mobile|e?mail|"
                         r"\u043f\u0438\u043d\u0444\u043b|\u043f\u0430\u0441\u043f\u043e\u0440\u0442|"
                         r"\u0442\u0435\u043b\u0435\u0444\u043e\u043d|\u043f\u043e\u0447\u0442\u0430)")
_KV_KEY = {"category", "name", "key", "parameter", "setting", "attribute", "property"}
_KV_VALUE = {"value", "values"}


def _hkey(header: str) -> str:
    return re.sub(r"[^\w]|_", "", (header or "").casefold())


def is_person_table(t: Table) -> bool:
    """Users/GroupMembers-like tables; a DisplayName in GPOs or Groups is not a person.
    A table keyed by SSN, card, mail or phone is about people even with a bare Name column."""
    return any(_PERSON_HEADER.search(_hkey(h)) or _PERSON_KEY.search(_hkey(h)) for h in t.header)


def is_kv_table(t: Table) -> bool:
    """Two-column Category | Value sheets (ADRecon Domain/Forest/About)."""
    return len(t.header) == 2 and _hkey(t.header[0]) in _KV_KEY and _hkey(t.header[1]) in _KV_VALUE


def column_types(gw: ModelGateway | None, t: Table, context: str = "") -> dict[int, str]:
    """Column index -> entity type for sensitive columns: header rules first, LLM for the rest."""
    out = {}
    if is_kv_table(t):
        return out  # typed row by row in table_detect
    person = is_person_table(t)
    width = max([len(t.header)] + [len(r) for r in t.rows[:50]]) if t.rows else len(t.header)
    for j in range(width):
        vals = [r[j] for r in t.rows if j < len(r) and r[j]][:8]
        if not vals:
            continue
        header = t.header[j] if j < len(t.header) else ""
        typ = header_type(header)
        if typ == "PER" and not person and _NAME_HEADER.match(_hkey(header)):
            typ = None
        if typ is None and gw is not None:
            try:
                data, _ = gw.complete_json(
                    "classify",
                    [{"role": "system", "content": COLUMN_SYSTEM},
                     {"role": "user", "content": f"File/sheet: {context!r} / {t.label!r}\n"
                                                 f"Header: {header!r}\nValues: {vals!r}"}],
                    COLUMN_SCHEMA, max_tokens=32)
                typ = data.get("type")
            except GatewayError:
                typ = None
        if typ == "AMT" and header_type(header) != "AMT":
            typ = None
        if typ in ("ACC", "PER") and header_type(header) != typ:
            # a guessed login/name column whose values are mostly plain words (OU names
            # "Computers", "Printers") is a label column
            words = [v for v in vals if len(v.split()) == 1]
            if words and sum(is_dict_word(v) for v in words) * 2 >= len(words):
                typ = None
        if typ and typ != "NONE":
            out[j] = typ
    return out


_DN_HEADER = re.compile(r"^(member)?(distinguishedname|dn)$")
_CN = re.compile(r"^\s*CN=((?:[^,\\]|\\.)+)", re.IGNORECASE)


_LOGIN_IN_TEXT = re.compile(
    r"(?<![\w.@/\\-])(?:(?:svc|it|adm|admin|sys|srv|app|usr|user|bot|api|sa|ad|db|sql|"
    r"backup|bkp|mail|scan|print|ftp|web|www|test)_[a-z0-9_]{2,}|"
    r"[a-z0-9]{2,}_(?:svc|admin|adm|user|usr|bot|service|srv|sa|test))(?![\w.@/\\-])")
_FREE_TEXT_HEADER = re.compile(r"(description|notes?|comments?|info|remarks?|memo)")


def table_detect(gw: ModelGateway | None, t: Table, context: str = "") -> list[Detection]:
    out = []
    if is_kv_table(t):
        for r in t.rows:
            if len(r) >= 2 and r[0] and (typ := header_type(r[0])) and typ != "NONE":
                if d := _d(typ, r[1], "header"):
                    out.append(d)
        return out
    types = column_types(gw, t, context)
    person = is_person_table(t)
    for j, typ in types.items():
        header = t.header[j] if j < len(t.header) else ""
        source = "header" if header_type(header) == typ else "column"
        for r in t.rows:
            if j < len(r) and (d := _d(typ, r[j], source)):
                if typ == "PER" and not person and not surname_shaped(d.value):
                    continue  # GPO/group/OU labels that look like names
                if typ == "ACC" and source == "column" and is_dict_word(d.value):
                    continue  # a guessed login column holding "Computers", "Printers"
                out.append(d)
    # logins quoted inside free text ("shared account it_service")
    for j, header in enumerate(t.header):
        if not _FREE_TEXT_HEADER.search(_hkey(header)):
            continue
        for r in t.rows:
            if j < len(r) and r[j]:
                for m in _LOGIN_IN_TEXT.finditer(r[j]):
                    if d := _d("ACC", m.group(0), "regex/login"):
                        out.append(d)
    # in a table about people the CN of a DN is the person's name ("CN=Ivanov Ivan,OU=...")
    if person and any(typ in ("PER", "ACC") for typ in types.values()):
        for j, header in enumerate(t.header):
            if not _DN_HEADER.match(re.sub(r"[^\w]|_", "", (header or "").casefold())):
                continue
            for r in t.rows:
                if j < len(r) and r[j] and (m := _CN.match(r[j])):
                    cn = m.group(1).replace("\\", "").strip()
                    # CN in capitals ("IVANOV IVAN") is common in local AD exports; the
                    # sweep is case-insensitive, so the title-cased form masks it as well
                    if cn.isupper():
                        cn = cn.title()
                    shaped = name_like(cn)
                    if 2 <= len(cn.split()) <= 4 and shaped and (d := _d("PER", cn, "dn")):
                        out.append(d)
    return out
