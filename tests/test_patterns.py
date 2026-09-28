"""lacre/patterns.py, the Extractor build and tools/extract_check.py.

The Extractor splices patterns.py and dkimbody.py; extract_check.py runs
them off chain. These tests hold amazon.json to the three expressions the
body probe measured on Bradbury, pin the matching rules docs/extractor.md
states, and check the built artifact is what its build produces now.
"""

import ast
import base64
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from lacre import dkimbody, patterns

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import extract_check

AMAZON = (ROOT / "lacre" / "extractors" / "amazon.json").read_text(encoding="ascii")
EMPTY = json.dumps({"eta_date": [], "eta_day": [], "order_id": [], "shipped": []})


def load_build():
    path = ROOT / "contracts" / "extractor" / "build.py"
    spec = importlib.util.spec_from_file_location("extractor_build", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def document(**changes):
    base = {"eta_date": [], "eta_day": [], "order_id": [], "shipped": []}
    base.update(changes)
    return json.dumps(base)


def mime(text, encoding="7bit"):
    payload = text.encode("utf-8")
    if encoding == "base64":
        payload = base64.b64encode(payload)
    elif encoding == "quoted-printable":
        payload = payload.replace(b"\xc3\xa9", b"=C3=A9")
    return (b"--b1\r\nContent-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: " + encoding.encode() + b"\r\n\r\n"
            + payload + b"\r\n--b1--\r\n")


def read(text, doc=AMAZON, encoding="7bit", canon="simple"):
    body = mime(text, encoding)
    return patterns.extract_body(body, dkimbody.body_hash_b64(body, canon), canon, doc)


# The build.

def test_the_built_contract_is_current_and_under_the_budget():
    build = load_build()
    source, _ = build.build()
    artifact = ROOT / "contracts" / "extractor" / "extractor.py"
    assert artifact.read_text(encoding="ascii") == source
    assert build.check(source) == []
    assert len(source) < 13000


def test_only_the_runner_line_survives_as_a_comment():
    source, _ = load_build().build()
    comments = [line for line in source.split("\n") if line.lstrip().startswith("#")]
    assert comments == [source.split("\n", 1)[0]]
    assert comments[0].startswith('# { "Depends": "py-genlayer:')


def test_the_build_drops_the_fixed_patterns_and_the_lacre_import():
    source, dropped = load_build().build()
    assert dropped["dkimbody.py"] == ["_ETA_DAY", "_ORDER_ID", "_SHIPPED", "count_bare_lf",
                                      "extract_fields"]
    assert dropped["patterns.py"] == []
    assert "from lacre" not in source
    assert source.count("\nimport re\n") == 1 and source.count("\nimport hashlib\n") == 1


def test_compact_keeps_the_program_and_multiline_strings():
    build = load_build()
    source = ('# head\nclass A:\n    def f(self, x):\n        y = (x +\n'
              '             1)\n\n        s = """a\n    b\n"""\n        return y, s\n')
    compacted = build.compact(source)
    assert ast.dump(ast.parse(compacted)) == ast.dump(ast.parse(source))
    assert '"""a\n    b\n"""' in compacted
    assert "\n\n" not in compacted


def test_the_extractor_knows_no_order_number_and_no_key():
    source, _ = load_build().build()
    for word in ("order_id\"]).group", "n_hex", "key_status", "keycache", "exec_prompt"):
        assert word not in source, word


# The document.

def test_amazon_json_is_a_valid_document():
    doc = patterns.load_patterns(AMAZON)
    assert doc["eta_date"] == []
    assert AMAZON.isascii()


@pytest.mark.parametrize("text, message", [
    ("{", "patterns not JSON"),
    ("[]", "patterns need lists under eta_date eta_day order_id shipped"),
    (json.dumps({"shipped": []}), "patterns need lists under eta_date eta_day order_id shipped"),
    (document(extra=[]), "patterns need lists under eta_date eta_day order_id shipped"),
    (document(shipped="x"), "patterns need lists under eta_date eta_day order_id shipped"),
    (document(shipped=["("]), "patterns key does not compile: shipped"),
    (document(order_id=[7]), "patterns key does not compile: order_id"),
    (document(eta_date=[r"(?P<y>\d{4})-(?P<m>\d\d)"]), "eta_date needs groups y m d"),
    (document(shipped=["a" * 4096]), "patterns too large"),
])
def test_a_bad_document_is_rejected(text, message):
    with pytest.raises(ValueError) as error:
        patterns.load_patterns(text)
    assert str(error.value) == message


def test_the_size_limit_is_on_the_trimmed_utf8_bytes():
    padding = 4096 - len(document(shipped=[""]))
    fits = document(shipped=["a" * padding])
    assert len(fits) == 4096
    patterns.load_patterns("  \n" + fits + "\n\n")
    with pytest.raises(ValueError):
        patterns.load_patterns(document(shipped=["a" * (padding + 1)]))
    with pytest.raises(ValueError):
        # Two bytes per character in UTF-8, one character in the string.
        patterns.load_patterns(document(shipped=["\u00e9" * (padding // 2 + 1)]))


def test_the_digest_ignores_surrounding_whitespace_only():
    assert patterns.document_sha256(AMAZON) == patterns.document_sha256(AMAZON.strip())
    assert patterns.document_sha256(AMAZON) != patterns.document_sha256(
        AMAZON.replace(": [", ":["))


# Matching, held to the body probe.

PROBE_TEXTS = (
    "Hola, tu pedido 111-2222222-3333333 se envio. Llega el mi\u00e9rcoles.",
    "Se enviaron tus articulos y llega el s\u00e1bado",
    "Tu paquete ha sido enviado, llega el manana",
    "Pedido 11-2222222-3333333 llega el viernes",
    "Nada que ver aqui",
    "SE ENVI\u00d3 el pedido 123-1234567-1234567, LLEGA EL LUNES",
    "llega el domingo, llega el lunes",
    "",
)


@pytest.mark.parametrize("text", PROBE_TEXTS)
def test_amazon_json_reads_what_the_probe_read(text):
    probe = dkimbody.extract_fields(text)
    parts = read(text).split("|")
    assert parts[0] == "1"
    assert (parts[1] == "1", parts[2], parts[4] == "1") == (
        probe["shipped"], probe["eta_day"], bool(probe["order_id"]))


def test_the_order_number_never_reaches_the_canonical_string():
    agreed = read("pedido 111-2222222-3333333 ha sido enviado")
    assert "2222222" not in agreed and agreed.split("|")[4] == "1"


def test_the_first_expression_yielding_a_weekday_wins():
    doc = document(eta_day=[r"llega el (\w+)", r"entrega (\w+)", "jueves"])
    assert read("llega el pronto, entrega martes", doc).split("|")[2] == "martes"
    assert read("llega el pronto, nada mas", doc).split("|")[2] == ""
    assert read("el jueves", doc).split("|")[2] == "jueves"


def test_only_the_first_match_of_an_expression_is_offered():
    doc = document(eta_day=[r"llega el (\w+)"])
    assert read("llega el pronto; llega el lunes", doc).split("|")[2] == ""


@pytest.mark.parametrize("text, date", [
    ("entrega 2026-10-07", "2026-10-07"),
    ("entrega 2026-1-7", "2026-01-07"),
    ("entrega 2026-02-29", ""),
    ("entrega 2028-02-29", "2028-02-29"),
    ("entrega 2000-02-29", "2000-02-29"),
    ("entrega 1900-02-29", ""),
    ("entrega 2026-04-31", ""),
    ("entrega 2026-08-31", "2026-08-31"),
    ("entrega 2026-00-10", ""),
    ("entrega 2026-12-00", ""),
    ("entrega \u0662\u0660\u0662\u0666-10-07", ""),
])
def test_a_date_is_iso_and_valid_or_empty(text, date):
    doc = document(eta_date=[r"entrega (?P<y>\d+)-(?P<m>\d+)-(?P<d>\d+)"])
    assert read(text, doc).split("|")[3] == date


def test_a_date_can_come_from_a_later_expression():
    doc = document(eta_date=[r"el (?P<d>\d+)/(?P<m>\d+)/(?P<y>\d+)",
                             r"entrega (?P<y>\d{4})-(?P<m>\d\d)-(?P<d>\d\d)"])
    assert read("el 31/02/2026, entrega 2026-03-01", doc).split("|")[3] == "2026-03-01"


def test_every_transfer_encoding_reads_the_same():
    text = "ha sido enviado, llega el mi\u00e9rcoles"
    expected = read(text)
    assert read(text, encoding="base64") == expected
    assert read(text, encoding="quoted-printable") == expected


# The canonical string.

def test_a_body_that_does_not_match_carries_no_field():
    body = mime("ha sido enviado 111-2222222-3333333 llega el lunes")
    agreed = patterns.extract_body(body, dkimbody.body_hash_b64(body + b"x", "simple"),
                                   "simple", AMAZON)
    assert agreed == "0|0|||0|%s|bh mismatch" % (patterns.document_sha256(AMAZON),)


def test_the_body_cap_is_inclusive():
    digest = patterns.document_sha256(AMAZON)
    assert patterns.extract_body(b"a" * 262145, "", "simple", AMAZON) == \
        "0|0|||0|%s|body too large" % (digest,)
    assert patterns.extract_body(b"a" * 262144, "", "simple", AMAZON).endswith("|bh mismatch")


def test_relaxed_and_simple_are_both_checked():
    text = "ha sido enviado  \t\r\nllega el lunes   "
    assert read(text, canon="relaxed").startswith("1|1|lunes|")
    assert read(text, canon="simple").startswith("1|1|lunes|")
    body = mime(text)
    assert patterns.extract_body(body, dkimbody.body_hash_b64(body, "relaxed"), "simple",
                                 AMAZON).endswith("|bh mismatch")


def test_a_matching_body_with_no_text_part_is_match_true_and_empty():
    body = b"just text, no MIME\r\n"
    agreed = patterns.extract_body(body, dkimbody.body_hash_b64(body, "simple"), "simple",
                                   AMAZON)
    assert agreed == "1|0|||0|%s|no text part" % (patterns.document_sha256(AMAZON),)


def test_a_reading_that_fails_is_match_false_and_never_raises():
    body = (b"--b1\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n"
            b"A\r\n--b1--\r\n")
    agreed = patterns.extract_body(body, dkimbody.body_hash_b64(body, "simple"), "simple",
                                   AMAZON)
    assert agreed.startswith("0|0|||0|") and "|extract failed: " in agreed
    assert patterns.extract_body(b"x", "", "nowsp", AMAZON).endswith("|extract failed: ValueError")


def test_the_canonical_string_is_ascii_with_seven_fields():
    agreed = read("ha sido enviado, llega el mi\u00e9rcoles 111-2222222-3333333")
    assert agreed.isascii() and len(agreed.split("|")) == 7


# extract_check.py.

def message(text, canon="simple", extra=""):
    body = mime(text)
    bh = dkimbody.body_hash_b64(body, canon if canon in ("simple", "relaxed") else "simple")
    head = ("DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/%s; d=Example.com; s=sel;%s"
            " h=from; bh=%s;\r\n b=AAAA\r\nFrom: a@example.com\r\n\r\n" % (canon, extra, bh))
    return head.encode("ascii") + body


def test_extract_check_reproduces_the_canonical_string():
    raw = message("ha sido enviado, llega el jueves")
    agreed, facts = extract_check.check(raw, AMAZON, "example.com")
    assert agreed.startswith("1|1|jueves||0|")
    assert facts == {"domain": "example.com", "body_canon": "simple"}
    relaxed, _ = extract_check.check(message("llega el jueves", "relaxed"), AMAZON)
    assert relaxed.startswith("1|0|jueves|")


def test_extract_check_refuses_what_the_chain_would_refuse():
    with pytest.raises(ValueError):
        extract_check.check(message("x"), "{}")
    with pytest.raises(ValueError, match="no DKIM-Signature"):
        extract_check.check(message("x"), AMAZON, "other.com")
    with pytest.raises(ValueError, match="l="):
        extract_check.check(message("x", extra=" l=10;"), AMAZON)
    with pytest.raises(ValueError, match="refuses it"):
        extract_check.check(message("x", canon="nowsp"), AMAZON)


def test_extract_check_exit_codes(tmp_path, capsys):
    good = tmp_path / "good.eml"
    good.write_bytes(message("ha sido enviado"))
    bad = tmp_path / "bad.eml"
    bad.write_bytes(message("ha sido enviado") + b"tail")
    doc = tmp_path / "doc.json"
    doc.write_text(AMAZON, encoding="ascii")
    assert extract_check.main([str(good), str(doc)]) == 0
    out = capsys.readouterr().out
    assert "document sha256 : %s" % (patterns.document_sha256(AMAZON),) in out
    assert extract_check.main([str(bad), str(doc)]) == 2
    assert extract_check.main([str(good), str(tmp_path / "missing.json")]) == 1
