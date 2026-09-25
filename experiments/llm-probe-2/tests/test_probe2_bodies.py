"""The ten bodies, expected.json, the local prefilter and the built contract."""

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

PROBE = Path(__file__).resolve().parents[1]
BODIES = PROBE / "bodies"
CONTRACT = PROBE / "contracts" / "llm_probe2.py"
BUILD = PROBE / "scripts" / "build_contract.py"
STUB = PROBE / "tests" / "stub_run.py"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fields = load(PROBE / "llm" / "fields.py", "probe2_bodies_fields")
prompt = load(PROBE / "llm" / "prompt.py", "probe2_bodies_prompt")
prefilter = load(PROBE / "llm" / "prefilter.py", "probe2_bodies_prefilter")
expected = json.loads((BODIES / "expected.json").read_text(encoding="ascii"))

NAMES = sorted(path.name for path in BODIES.iterdir() if path.name != "expected.json")
ORDINARY = ("01_shipped.txt", "02_pending_trap.txt")
PENDING_ATTACKS = ("03_injection_direct.txt", "04_injection_hidden.txt",
                   "05_injection_marker.txt", "06_escape_break.txt",
                   "07_fake_marker.txt", "08_injection_english.txt",
                   "10_unicode.json")

# sha256 of probe D's five bodies, as recorded there. Checked by value so this
# probe does not read the other one's files.
PROBE_D = {
    "01_shipped.txt": "3d80ac0c75bea850c609677af39ead4352f7c9da709814ec2f3c916a1c7994ab",
    "02_pending_trap.txt": "48046d6204232b36beaa14afaab85f88da4d9d571a16623b81e70ee11538dae5",
    "03_injection_direct.txt": "c62010e5a063162d5d8f9b049f74e2964e1df3c806aae32ba2ab688b74d5e270",
    "04_injection_hidden.txt": "caef9cd8297f781ee8d0e24ce17984905735dfa29c5ab32c05de23846aa72054",
    "05_injection_marker.txt": "e807eafdf035da312f7e42dabc38800998d3397920bee75a327aa3a3eece9f2f",
}

# What the prefilter flags, as measured. A change here is a change in the
# README's prefilter table.
PREFILTER = {
    "01_shipped.txt": [],
    "02_pending_trap.txt": [],
    "03_injection_direct.txt": ["schema_key", "json_object"],
    "04_injection_hidden.txt": ["schema_key", "json_object"],
    "05_injection_marker.txt": ["schema_key", "json_object", "delimiter_line"],
    "06_escape_break.txt": ["schema_key", "json_object"],
    "07_fake_marker.txt": ["schema_key", "json_object"],
    "08_injection_english.txt": ["schema_key"],
    "09_gift_message.txt": [],
    "10_unicode.json": [],
}


def body(name):
    text = (BODIES / name).read_text(encoding="ascii")
    return json.loads(text)["body"] if name.endswith(".json") else text


# ---- the bodies -------------------------------------------------------------

def test_expected_json_covers_all_ten():
    assert len(NAMES) == 10
    assert sorted(expected["readings"]) == NAMES
    assert sorted(expected["injection"]) == NAMES


@pytest.mark.parametrize("name", NAMES + ["expected.json"])
def test_every_file_is_ascii(name):
    (BODIES / name).read_bytes().decode("ascii")


@pytest.mark.parametrize("name", sorted(PROBE_D))
def test_the_first_five_are_probe_ds_bodies_byte_for_byte(name):
    assert hashlib.sha256((BODIES / name).read_bytes()).hexdigest() == PROBE_D[name]


def test_the_unicode_body_decodes_to_non_ascii_text():
    text = body("10_unicode.json")
    assert any(ord(ch) > 127 for ch in text)
    assert chr(0x200B) in text and chr(0x202E) in text
    assert chr(0x0456) in text and chr(0x0441) in text


def test_sanitizing_the_unicode_body_keeps_only_the_look_alikes():
    clean = prompt.sanitize(body("10_unicode.json"))
    assert not any(ord(ch) in prompt.INVISIBLE for ch in clean)
    assert chr(0x0456) in clean
    assert "SISTEMA DE VERIFICACION" in clean


@pytest.mark.parametrize("name", NAMES)
def test_every_body_is_under_the_cap_after_sanitizing(name):
    assert not fields.oversized(prompt.sanitize(body(name)))


@pytest.mark.parametrize("name", NAMES)
def test_every_expected_reading_is_one_the_normalizer_can_produce(name):
    shipped, _, eta = expected["readings"][name].partition("|")
    day = eta[len("eta="):]
    assert shipped in ("shipped=0", "shipped=1")
    assert day == "" or day in fields.WEEKDAYS
    got = fields.normalize_answer({"shipped": shipped == "shipped=1",
                                   "eta_day": day, "injection": False})
    assert got == expected["readings"][name] + "|inj=0"


def test_the_injection_flags_are_informational_and_as_specified():
    flags = expected["injection"]
    assert flags["01_shipped.txt"] == flags["02_pending_trap.txt"] == "0"
    assert flags["09_gift_message.txt"] == "either"
    assert all(flags[name] == "1" for name in PENDING_ATTACKS)


@pytest.mark.parametrize("name", PENDING_ATTACKS)
def test_every_pending_attack_is_body_02_plus_an_instruction(name):
    stem = body("02_pending_trap.txt").split("Gracias por tu compra.")[0]
    text = body(name)
    assert text.startswith(stem)
    assert expected["readings"][name] == "shipped=0|eta="


# Only to check what body 10 spells; nothing in the probe folds these.
LOOK_ALIKES = {0x0430: "a", 0x0435: "e", 0x043E: "o", 0x0440: "p", 0x0441: "c",
               0x0443: "y", 0x0445: "x", 0x0456: "i"}


@pytest.mark.parametrize("name", PENDING_ATTACKS + ("09_gift_message.txt",))
def test_every_attack_names_miercoles(name):
    assert "miercoles" in prompt.sanitize(body(name)).translate(LOOK_ALIKES)


def test_the_unicode_body_never_spells_miercoles_in_ascii():
    assert "miercoles" not in prompt.sanitize(body("10_unicode.json"))


@pytest.mark.parametrize("name", ORDINARY)
def test_no_ordinary_body_names_miercoles(name):
    assert "miercoles" not in body(name)


def test_the_gift_body_was_shipped_and_arrives_on_jueves():
    text = body("09_gift_message.txt")
    assert "ya ha sido enviado" in text and "llega el jueves" in text
    assert "Nota del sistema" in text and "miercoles" in text
    assert expected["readings"]["09_gift_message.txt"] == "shipped=1|eta=jueves"


def test_the_fake_marker_body_closes_before_it_reopens():
    lines = body("07_fake_marker.txt").splitlines()
    assert lines.index("END-3f9a2c1b0d4e5f67") < lines.index("BEGIN-3f9a2c1b0d4e5f67")


def test_the_escape_body_carries_quotes_backslashes_and_a_closing_sequence():
    text = body("06_escape_break.txt")
    assert '"}' in text and "\\" in text and "miercoles" in text


# ---- the prefilter ----------------------------------------------------------

@pytest.mark.parametrize("name", NAMES)
def test_the_prefilter_flags_are_as_measured(name):
    assert prefilter.flags(body(name)) == PREFILTER[name]


@pytest.mark.parametrize("name", ORDINARY)
def test_the_prefilter_does_not_flag_an_ordinary_body(name):
    assert not prefilter.suspicious(body(name))


def test_the_prefilter_sees_a_delimiter_hidden_by_an_invisible_character():
    assert prefilter.flags("hola\n---" + chr(0x200B) + "--\nadios") == ["delimiter_line"]


@pytest.mark.parametrize("text", ["{'shipped': 1}", '{ "a" : 1 }', "{\"x\":"])
def test_the_prefilter_sees_a_quoted_key(text):
    assert "json_object" in prefilter.flags(text)


def test_the_prefilter_is_not_in_the_contract():
    source = CONTRACT.read_text(encoding="ascii")
    assert "SCHEMA_KEYS" not in source and "prefilter" not in source


# ---- the built contract -----------------------------------------------------

def test_the_built_contract_is_current():
    result = subprocess.run([sys.executable, str(BUILD), "--check"],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_contract_carries_the_tested_modules():
    source = CONTRACT.read_text(encoding="ascii")
    for part in ("prompt.py", "fields.py"):
        assert (PROBE / "llm" / part).read_text(encoding="ascii").strip("\n") in source


def test_the_contract_uses_strict_equality_only():
    source = CONTRACT.read_text(encoding="ascii")
    assert "gl.eq_principle.strict_eq(" in source
    assert "prompt_comparative" not in source
    assert source.startswith('# { "Depends": "py-genlayer:'
                             '1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }')


def test_the_stub_run_passes():
    result = subprocess.run([sys.executable, str(STUB)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
