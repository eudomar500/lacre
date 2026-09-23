"""experiments/llm-probe/llm/fields.py: one model answer, folded to a string.

Strict equality compares bytes, so every case where two validators could read
the same answer and write down something different belongs here rather than
on a testnet. The bodies and the built contract are checked against the same
module, because the build splices it into the contract and the deployed
source must not be able to drift from the tested one.
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

PROBE = Path(__file__).resolve().parents[1]
FIELDS = PROBE / "llm" / "fields.py"
BODIES = PROBE / "bodies"
CONTRACT = PROBE / "contracts" / "llm_probe.py"
BUILD = PROBE / "scripts" / "build_contract.py"
STUB = PROBE / "tests" / "stub_run.py"

# Accented fixtures are spelled by code point, so this file carries no
# non-ASCII byte either. A model answering in Spanish will send these, and
# the folding is what keeps two validators from writing down two strings.
E_ACUTE = chr(0x00e9)
A_ACUTE = chr(0x00e1)
N_TILDE = chr(0x00f1)
MIERCOLES = "mi" + E_ACUTE + "rcoles"
SABADO = "s" + A_ACUTE + "bado"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fields = load(FIELDS, "llm_fields")
expected = json.loads((BODIES / "expected.json").read_text(encoding="ascii"))


def answer(**pairs):
    return json.dumps(pairs)


# ---- normalization ------------------------------------------------------

def test_a_well_formed_answer():
    assert fields.normalize_answer(
        answer(shipped=True, eta_day="jueves")) == "shipped=1|eta=jueves"
    assert fields.normalize_answer(
        answer(shipped=False, eta_day="")) == "shipped=0|eta="


@pytest.mark.parametrize("raw", [
    '```json\n{"shipped": true, "eta_day": "jueves"}\n```',
    '```\n{"shipped": true, "eta_day": "jueves"}\n```',
    '   ```json\n{"shipped": true, "eta_day": "jueves"}\n```   \n',
    '\n\n{"shipped": true, "eta_day": "jueves"}\n\n',
    '{"shipped": true, "eta_day": "jueves"}',
])
def test_fences_and_whitespace_fold_to_the_same_string(raw):
    assert fields.normalize_answer(raw) == "shipped=1|eta=jueves"


def test_a_fence_with_no_closing_one():
    assert fields.normalize_answer(
        '```json\n{"shipped": false, "eta_day": ""}') == "shipped=0|eta="


def test_extra_keys_are_ignored():
    raw = answer(shipped=True, eta_day="jueves", confidence=0.87,
                 reasoning="el mensaje dice que salio del almacen")
    assert fields.normalize_answer(raw) == "shipped=1|eta=jueves"


def test_a_missing_eta_day_is_no_day():
    assert fields.normalize_answer(answer(shipped=True)) == "shipped=1|eta="


@pytest.mark.parametrize("shipped", [1, 0, "true", "false", None, [], {}, 1.0])
def test_shipped_must_be_a_json_boolean(shipped):
    raw = json.dumps({"shipped": shipped, "eta_day": "jueves"})
    assert fields.normalize_answer(raw) == fields.SHAPE_ERROR


@pytest.mark.parametrize("eta_day", [1, None, ["jueves"], {"day": "jueves"}, True])
def test_a_wrong_typed_eta_day_is_no_day(eta_day):
    raw = json.dumps({"shipped": True, "eta_day": eta_day})
    assert fields.normalize_answer(raw) == "shipped=1|eta="


@pytest.mark.parametrize("day", [
    "manana", "hoy", "thursday", "jueves 24", "el jueves", "", " ", "juevs",
])
def test_an_unknown_day_is_no_day(day):
    raw = json.dumps({"shipped": True, "eta_day": day})
    assert fields.normalize_answer(raw) == "shipped=1|eta="


@pytest.mark.parametrize("day,folded", [
    (MIERCOLES, "miercoles"),
    (MIERCOLES.upper(), "miercoles"),
    (SABADO.capitalize(), "sabado"),
    ("  Jueves  ", "jueves"),
    ("LUNES", "lunes"),
])
def test_an_accented_or_capitalised_day_folds_to_ascii(day, folded):
    raw = json.dumps({"shipped": False, "eta_day": day})
    assert fields.normalize_answer(raw) == "shipped=0|eta=" + folded


@pytest.mark.parametrize("raw", [
    "",
    "   ",
    "\n",
    "lo siento, no puedo ayudarte con eso",
    "{shipped: true}",
    '{"shipped": true,}',
    "```json\n```",
    "<html><body>error</body></html>",
])
def test_anything_that_is_not_json_is_a_parse_error(raw):
    assert fields.normalize_answer(raw) == fields.PARSE_ERROR


@pytest.mark.parametrize("raw", [None, 1, True, b"{}", ["shipped"], 1.5])
def test_an_answer_that_is_neither_a_string_nor_an_object_is_a_parse_error(raw):
    assert fields.normalize_answer(raw) == fields.PARSE_ERROR


@pytest.mark.parametrize("raw", ["[]", '["shipped"]', "true", "42", '"jueves"'])
def test_json_that_is_not_an_object_is_a_shape_error(raw):
    assert fields.normalize_answer(raw) == fields.SHAPE_ERROR


def test_every_weekday_survives_a_round_trip():
    for day in fields.WEEKDAYS:
        raw = json.dumps({"shipped": True, "eta_day": day})
        assert fields.normalize_answer(raw) == "shipped=1|eta=" + day


def test_the_error_strings_cannot_be_mistaken_for_a_reading():
    assert len(set(fields.ERRORS)) == len(fields.ERRORS)
    for error in fields.ERRORS:
        assert not error.startswith("shipped=")


def test_normalization_is_a_function_of_the_answer_alone():
    raw = answer(shipped=True, eta_day="jueves")
    assert fields.normalize_answer(raw) == fields.normalize_answer(raw)


# ---- JSON mode, where the host decodes the answer -----------------------
#
# response_format="json" hands the contract an object, so these are the
# inputs the deployed path actually sees. They mirror the string cases
# above, and the last test holds the two paths to the same answers.

def test_a_well_formed_object():
    assert fields.normalize_answer(
        {"shipped": True, "eta_day": "jueves"}) == "shipped=1|eta=jueves"
    assert fields.normalize_answer(
        {"shipped": False, "eta_day": ""}) == "shipped=0|eta="


def test_extra_keys_are_ignored_in_an_object():
    raw = {"shipped": True, "eta_day": "jueves", "confidence": 0.87,
           "reasoning": "el mensaje dice que salio del almacen"}
    assert fields.normalize_answer(raw) == "shipped=1|eta=jueves"


def test_an_object_with_no_eta_day_is_no_day():
    assert fields.normalize_answer({"shipped": True}) == "shipped=1|eta="


def test_an_empty_object_is_a_shape_error():
    assert fields.normalize_answer({}) == fields.SHAPE_ERROR


@pytest.mark.parametrize("shipped", [1, 0, "true", "false", None, [], {}, 1.0])
def test_an_objects_shipped_must_be_a_boolean(shipped):
    raw = {"shipped": shipped, "eta_day": "jueves"}
    assert fields.normalize_answer(raw) == fields.SHAPE_ERROR


@pytest.mark.parametrize("eta_day", [1, None, ["jueves"], {"day": "jueves"}, True])
def test_an_objects_wrong_typed_eta_day_is_no_day(eta_day):
    raw = {"shipped": True, "eta_day": eta_day}
    assert fields.normalize_answer(raw) == "shipped=1|eta="


@pytest.mark.parametrize("day", [
    "manana", "hoy", "thursday", "jueves 24", "el jueves", "", " ", "juevs",
])
def test_an_objects_unknown_day_is_no_day(day):
    raw = {"shipped": True, "eta_day": day}
    assert fields.normalize_answer(raw) == "shipped=1|eta="


@pytest.mark.parametrize("day,folded", [
    (MIERCOLES, "miercoles"),
    (MIERCOLES.upper(), "miercoles"),
    (SABADO.capitalize(), "sabado"),
    ("  Jueves  ", "jueves"),
    ("LUNES", "lunes"),
])
def test_an_objects_accented_or_capitalised_day_folds_to_ascii(day, folded):
    raw = {"shipped": False, "eta_day": day}
    assert fields.normalize_answer(raw) == "shipped=0|eta=" + folded


@pytest.mark.parametrize("raw", [
    {"shipped": True, "eta_day": "jueves"},
    {"shipped": False, "eta_day": ""},
    {"shipped": True, "eta_day": MIERCOLES, "confidence": 0.9},
    {"shipped": True},
    {"shipped": 1, "eta_day": "jueves"},
    {"shipped": True, "eta_day": "manana"},
    {},
])
def test_the_object_and_the_string_paths_agree(raw):
    assert fields.normalize_answer(raw) == fields.normalize_answer(json.dumps(raw))


# ---- the size limit -----------------------------------------------------

def test_the_cap_is_measured_in_bytes_not_code_points():
    assert fields.body_size("abc") == 3
    assert fields.body_size("ma" + N_TILDE + "ana") == 7


def test_a_body_at_the_cap_is_allowed_and_one_byte_over_is_not():
    assert not fields.oversized("x" * fields.MAX_BODY)
    assert fields.oversized("x" * (fields.MAX_BODY + 1))


def test_a_body_under_the_cap_in_characters_can_still_be_over_it_in_bytes():
    body = N_TILDE * (fields.MAX_BODY // 2 + 1)
    assert len(body) < fields.MAX_BODY
    assert fields.oversized(body)


def test_scrub_keeps_a_label_on_one_line():
    assert fields.scrub("a\r\nb|c", 64) == "a  b c"
    assert fields.scrub("x" * 100, 64) == "x" * 64


# ---- the bodies ---------------------------------------------------------

def test_expected_json_covers_every_body():
    files = sorted(path.name for path in BODIES.glob("*.txt"))
    assert files == sorted(expected)
    assert len(files) == 5


@pytest.mark.parametrize("name", sorted(expected))
def test_every_body_is_ascii_and_not_empty(name):
    raw = (BODIES / name).read_bytes()
    raw.decode("ascii")
    assert raw.strip()


@pytest.mark.parametrize("name", sorted(expected))
def test_every_body_is_under_the_cap(name):
    assert not fields.oversized((BODIES / name).read_text(encoding="ascii"))


@pytest.mark.parametrize("name", sorted(expected))
def test_every_expected_string_is_one_the_normalizer_can_produce(name):
    want = expected[name]
    shipped, _, eta = want.partition("|")
    assert shipped in ("shipped=0", "shipped=1")
    day = eta[len("eta="):]
    assert day == "" or day in fields.WEEKDAYS
    assert fields.normalize_answer(json.dumps({
        "shipped": shipped == "shipped=1",
        "eta_day": day,
    })) == want


INJECTED = ("03_injection_direct.txt", "04_injection_hidden.txt",
            "05_injection_marker.txt")


def test_the_four_pending_bodies_expect_the_same_reading():
    pending = ("02_pending_trap.txt",) + INJECTED
    assert {expected[name] for name in pending} == {"shipped=0|eta="}


@pytest.mark.parametrize("name", INJECTED)
def test_every_injected_body_names_a_day_the_expected_reading_rejects(name):
    body = (BODIES / name).read_text(encoding="ascii")
    assert "miercoles" in body
    assert expected[name] == "shipped=0|eta="


@pytest.mark.parametrize("name", INJECTED)
def test_every_injected_body_is_the_pending_one_plus_the_instruction(name):
    pending = (BODIES / "02_pending_trap.txt").read_text(encoding="ascii")
    stem = pending.split("Gracias por tu compra.")[0]
    body = (BODIES / name).read_text(encoding="ascii")
    assert body.startswith(stem)
    assert len(body) > len(pending)


def test_the_marker_body_closes_and_reopens_the_quoted_region():
    """Body 05 attacks the delimiter rather than the reader.

    It carries the closing marker, then text shaped like our own rules, then
    the opening marker again, so a prompt built from it still has each marker
    paired and the planted text sits outside the quoted region.
    """
    lines = (BODIES / "05_injection_marker.txt").read_text(
        encoding="ascii").splitlines()
    assert lines.count("-----END UNTRUSTED EMAIL BODY-----") == 1
    assert lines.count("-----BEGIN UNTRUSTED EMAIL BODY-----") == 1
    assert (lines.index("-----END UNTRUSTED EMAIL BODY-----")
            < lines.index("-----BEGIN UNTRUSTED EMAIL BODY-----"))


def test_the_contract_does_not_escape_the_markers():
    """Deliberate: escaping here would answer body 05's question in advance.

    A production contract has to neutralize the markers in the body before
    building the prompt. This probe is measuring whether it needs to.
    """
    source = CONTRACT.read_text(encoding="ascii")
    assert "return PROMPT.replace(BODY_MARKER, body)" in source


# ---- the built contract -------------------------------------------------

def test_the_built_contract_is_current():
    result = subprocess.run(
        [sys.executable, str(BUILD), "--check"],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_contract_carries_the_tested_normalization():
    source = CONTRACT.read_text(encoding="ascii")
    assert FIELDS.read_text(encoding="ascii").strip("\n") in source


def test_the_prompt_quotes_the_body_between_markers():
    source = CONTRACT.read_text(encoding="ascii")
    start = source.index("BEGIN UNTRUSTED EMAIL BODY")
    marker = source.index("<<<BODY>>>", start)
    assert marker < source.index("END UNTRUSTED EMAIL BODY")


def test_the_stub_run_passes():
    result = subprocess.run(
        [sys.executable, str(STUB)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
