"""experiments/llm-probe-2/llm/fields.py: one answer, folded to one string.

Probe D's normalization cases with the injection flag added. Strict equality
compares bytes, so every way two validators could read the same answer and
write down two strings belongs here rather than on a testnet.
"""

import importlib.util
import json
from pathlib import Path

import pytest

PROBE = Path(__file__).resolve().parents[1]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fields = load(PROBE / "llm" / "fields.py", "probe2_fields_module")

MIERCOLES = "mi" + chr(0x00E9) + "rcoles"
SABADO = "s" + chr(0x00E1) + "bado"
N_TILDE = chr(0x00F1)


def obj(shipped=True, eta_day="jueves", injection=False, **extra):
    answer = {"shipped": shipped, "eta_day": eta_day, "injection": injection}
    answer.update(extra)
    return answer


def test_a_well_formed_answer():
    assert fields.normalize_answer(obj()) == "shipped=1|eta=jueves|inj=0"
    assert fields.normalize_answer(obj(False, "", True)) == "shipped=0|eta=|inj=1"


@pytest.mark.parametrize("raw", [
    '```json\n{"shipped": true, "eta_day": "jueves", "injection": false}\n```',
    '```\n{"shipped": true, "eta_day": "jueves", "injection": false}\n```',
    '  {"shipped": true, "eta_day": "jueves", "injection": false}  \n',
    '```json\n{"shipped": true, "eta_day": "jueves", "injection": false}',
])
def test_text_answers_fold_to_the_same_string(raw):
    assert fields.normalize_answer(raw) == "shipped=1|eta=jueves|inj=0"


def test_extra_keys_are_ignored():
    assert fields.normalize_answer(obj(confidence=0.9)) == "shipped=1|eta=jueves|inj=0"


def test_a_missing_eta_day_is_no_day():
    answer = obj()
    del answer["eta_day"]
    assert fields.normalize_answer(answer) == "shipped=1|eta=|inj=0"


@pytest.mark.parametrize("value", [1, 0, "true", "false", None, [], {}, 1.0])
def test_shipped_must_be_a_boolean(value):
    assert fields.normalize_answer(obj(shipped=value)) == fields.SHAPE_ERROR


@pytest.mark.parametrize("value", [1, 0, "true", "false", None, [], {}, 1.0])
def test_injection_must_be_a_boolean(value):
    assert fields.normalize_answer(obj(injection=value)) == fields.SHAPE_ERROR


def test_a_missing_injection_is_a_shape_error():
    answer = obj()
    del answer["injection"]
    assert fields.normalize_answer(answer) == fields.SHAPE_ERROR
    assert fields.normalize_answer(json.dumps(answer)) == fields.SHAPE_ERROR


@pytest.mark.parametrize("day", [1, None, ["jueves"], True, "manana", "thursday",
                                 "el jueves", "", " "])
def test_anything_but_a_weekday_is_no_day(day):
    assert fields.normalize_answer(obj(eta_day=day)) == "shipped=1|eta=|inj=0"


@pytest.mark.parametrize("day,folded", [
    (MIERCOLES, "miercoles"), (MIERCOLES.upper(), "miercoles"),
    (SABADO.capitalize(), "sabado"), ("  Jueves  ", "jueves"),
])
def test_accents_and_case_fold(day, folded):
    assert fields.normalize_answer(obj(eta_day=day)) == "shipped=1|eta=%s|inj=0" % folded


@pytest.mark.parametrize("raw", ["", "lo siento", "{shipped: true}", "```json\n```"])
def test_text_that_is_not_json_is_a_parse_error(raw):
    assert fields.normalize_answer(raw) == fields.PARSE_ERROR


@pytest.mark.parametrize("raw", [None, 1, True, b"{}", ["shipped"]])
def test_an_answer_of_another_type_is_a_parse_error(raw):
    assert fields.normalize_answer(raw) == fields.PARSE_ERROR


@pytest.mark.parametrize("raw", ["[]", "true", '"jueves"'])
def test_json_that_is_not_an_object_is_a_shape_error(raw):
    assert fields.normalize_answer(raw) == fields.SHAPE_ERROR


@pytest.mark.parametrize("raw", [
    obj(), obj(False, "", True), obj(eta_day=MIERCOLES), obj(injection="no"), {},
])
def test_the_object_and_the_string_paths_agree(raw):
    assert fields.normalize_answer(raw) == fields.normalize_answer(json.dumps(raw))


def test_every_combination_has_one_spelling():
    seen = set()
    for shipped in (True, False):
        for injection in (True, False):
            for day in fields.WEEKDAYS + ("",):
                seen.add(fields.normalize_answer(obj(shipped, day, injection)))
    assert len(seen) == 2 * 2 * 8


def test_the_error_vocabulary_is_probe_ds():
    assert fields.ERRORS == ("error=too_large", "error=parse", "error=shape",
                             "error=prompt")
    for error in fields.ERRORS:
        assert not error.startswith("shipped=")


def test_the_cap_is_bytes_and_8_kb():
    assert fields.MAX_BODY == 8192
    assert fields.body_size("ma" + N_TILDE + "ana") == 7
    assert not fields.oversized("x" * 8192)
    assert fields.oversized("x" * 8193)


# ---- the plain control form --------------------------------------------------

SAME_INPUTS = [
    obj(), obj(False, "", True), obj(eta_day=MIERCOLES), obj(eta_day="manana"),
    obj(shipped=1), obj(shipped="true"), {}, {"shipped": True}, "lo siento", None,
    '```json\n{"shipped": false, "eta_day": "Viernes", "injection": true}\n```',
    "[]",
]


@pytest.mark.parametrize("raw", SAME_INPUTS + [json.dumps(item) for item in SAME_INPUTS
                                               if isinstance(item, dict)])
def test_full_and_plain_differ_only_on_inj(raw):
    full = fields.normalize_answer(raw)
    plain = fields.normalize_plain(raw)
    if full.startswith("shipped="):
        assert full == plain + full[len(plain):]
        assert full[len(plain):] in ("|inj=0", "|inj=1")
    elif plain.startswith("shipped="):
        # Only inj can turn a plain reading into a full error.
        assert full == fields.SHAPE_ERROR
    else:
        assert full == plain


@pytest.mark.parametrize("value", ["false", "true", 0, 1, None, [], {}])
def test_a_bad_injection_is_an_error_in_full_and_a_reading_in_plain(value):
    answer = obj(eta_day="jueves", injection=value)
    assert fields.normalize_answer(answer) == fields.SHAPE_ERROR
    assert fields.normalize_plain(answer) == "shipped=1|eta=jueves"
    assert fields.normalize_plain(json.dumps(answer)) == "shipped=1|eta=jueves"


def test_a_missing_injection_is_an_error_in_full_and_a_reading_in_plain():
    answer = obj(False, "")
    del answer["injection"]
    assert fields.normalize_answer(answer) == fields.SHAPE_ERROR
    assert fields.normalize_plain(answer) == "shipped=0|eta="


@pytest.mark.parametrize("value", [1, "true", None])
def test_plain_keeps_the_shipped_rule(value):
    assert fields.normalize_plain(obj(shipped=value)) == fields.SHAPE_ERROR


def test_plain_folds_the_day_as_full_does():
    assert fields.normalize_plain(obj(eta_day=SABADO.upper())) == "shipped=1|eta=sabado"
    assert fields.normalize_plain(obj(eta_day="thursday")) == "shipped=1|eta="


def test_scrub_keeps_a_label_on_one_line():
    assert fields.scrub("a\r\nb|c", 64) == "a  b c"
