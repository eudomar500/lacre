#!/usr/bin/env python3
"""Drive contracts/llm_probe2.py against a stubbed SDK and a scripted model.

Probe D's harness, cut down to strict equality, for extract and for the
extract_plain control. The contract runs as written
with stand-ins for storage, gl.message_raw, the prompt call and strict_eq;
nothing is deployed and no prompt is run. The model is scripted, so the only
thing that can make a leader and a validator disagree here is the contract
folding the same answer into two different strings, which is the part of a
disagreement that is this harness's business.

Usage:
    python3 experiments/llm-probe-2/tests/stub_run.py
"""

import hashlib
import json
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROBE = HERE.parent
CONTRACT = PROBE / "contracts" / "llm_probe2.py"
BODIES = PROBE / "bodies"

NOW = "2026-09-24T10:00:00Z"


class TreeMap(dict):
    """Storage map. dict answers get, contains and item assignment alike."""


class UserError(Exception):
    pass


class Model:
    """The scripted model behind gl.nondet.exec_prompt.

    Answers are served in order, and the prompts and keyword arguments are
    kept so a check can look at what the contract sent. fail makes the call
    raise, which is how the contract's own failure path is reached.
    """

    def __init__(self):
        self.script()

    def script(self, *answers):
        self.answers = list(answers)
        self.prompts = []
        self.configs = []
        self.fail = False

    def exec_prompt(self, prompt, **config):
        self.prompts.append(prompt)
        self.configs.append(config)
        if self.fail:
            raise RuntimeError("no model")
        if not self.answers:
            raise AssertionError("the model was asked more times than scripted")
        return self.answers.pop(0)


class Consensus:
    """strict_eq as the runner applies it: leader, then validator, compared."""

    def __init__(self):
        self.rounds = []
        self.inside = False

    def strict_eq(self, fn):
        self.inside = True
        try:
            leader = fn()
            validator = fn()
        finally:
            self.inside = False
        self.rounds.append({
            "leader": leader,
            "validator": validator,
            "agreed": type(leader) is type(validator) and leader == validator,
        })
        return leader

    @property
    def last(self):
        return self.rounds[-1]


class MessageRaw(dict):
    """gl.message_raw, which records a read from inside the block."""

    def __init__(self, consensus, *args):
        super().__init__(*args)
        self.consensus = consensus
        self.read_inside = False

    def __getitem__(self, key):
        if self.consensus.inside:
            self.read_inside = True
        return super().__getitem__(key)


def build_sdk(model, consensus):
    gl = types.SimpleNamespace(
        Contract=type("Contract", (), {}),
        message_raw=MessageRaw(consensus, {"datetime": NOW}),
        public=types.SimpleNamespace(write=lambda fn: fn, view=lambda fn: fn),
        vm=types.SimpleNamespace(UserError=UserError),
        nondet=types.SimpleNamespace(exec_prompt=model.exec_prompt),
        eq_principle=types.SimpleNamespace(strict_eq=consensus.strict_eq),
    )
    sdk = types.ModuleType("genlayer")
    sdk.__all__ = ["gl", "u256", "TreeMap", "allow_storage"]
    sdk.gl = gl
    sdk.u256 = int
    sdk.TreeMap = TreeMap
    sdk.allow_storage = lambda cls: cls
    return sdk


def load_contract(model, consensus):
    sdk = build_sdk(model, consensus)
    sys.modules["genlayer"] = sdk
    module = types.ModuleType("llm_probe2")
    module.__file__ = str(CONTRACT)
    exec(compile(CONTRACT.read_text(encoding="ascii"), str(CONTRACT), "exec"),
         module.__dict__)
    contract = module.Contract.__new__(module.Contract)
    for field, annotation in module.Contract.__annotations__.items():
        if getattr(annotation, "__origin__", annotation) is TreeMap:
            setattr(contract, field, TreeMap())
    contract.__init__()
    return contract, module, sdk.gl


def answer(shipped, day, injection):
    return {"shipped": shipped, "eta_day": day, "injection": injection}


def split(returned):
    record_id, _, result = str(returned).partition(" ")
    return record_id, result


def body(name):
    text = (BODIES / name).read_text(encoding="ascii")
    return json.loads(text)["body"] if name.endswith(".json") else text


def data_line(prompt, tag):
    lines = prompt.split("\n")
    return lines[lines.index("BEGIN-" + tag) + 1]


class Report:
    def __init__(self):
        self.failed = 0
        self.total = 0

    def check(self, label, condition, detail=""):
        self.total += 1
        print("%-4s %-58s %s" % ("ok" if condition else "FAIL", label, detail))
        if not condition:
            self.failed += 1

    def raises(self, label, fn):
        try:
            fn()
        except UserError as error:
            self.check(label, True, error.args[0])
            return
        self.check(label, False, "no UserError was raised")


def main():
    if not CONTRACT.is_file():
        sys.exit("%s does not exist; run scripts/build_contract.py" % (CONTRACT,))

    model = Model()
    consensus = Consensus()
    contract, module, gl = load_contract(model, consensus)
    expected = json.loads((BODIES / "expected.json").read_text(encoding="ascii"))

    print("contract     : %s (%d bytes)" % (CONTRACT.name, len(CONTRACT.read_bytes())))
    print("bodies       : %d\n" % (len(expected["readings"]),))

    report = Report()
    report.check("nothing is stored yet", contract.count() == 0)
    report.raises("get() on an unknown id raises", lambda: contract.get("0"))

    # An ordinary body, end to end.
    shipped = body("01_shipped.txt")
    model.script(answer(True, "jueves", False), answer(True, "jueves", False))
    returned = contract.extract("01_shipped", shipped)
    record_id, result = split(returned)
    prompt = model.prompts[0]
    tag = hashlib.sha256(shipped.encode("utf-8")).hexdigest()[:16]
    report.check("returns the id and the canonical reading",
                 returned == "0 shipped=1|eta=jueves|inj=0", returned)
    report.check("the markers carry the tag of the body",
                 prompt.split("\n").count("BEGIN-" + tag) == 1
                 and prompt.split("\n").count("END-" + tag) == 1, tag)
    report.check("the body is one JSON string between them",
                 json.loads(data_line(prompt, tag)) == shipped)
    report.check("the rules come before and after it",
                 prompt.count(module.RULES.replace(module.TAG_SLOT, tag)) == 2)
    report.check("leader and validator were sent the same prompt",
                 model.prompts[0] == model.prompts[1])
    report.check("the contract asked for JSON mode",
                 model.configs[0].get("response_format") == "json",
                 str(model.configs[0]))
    report.check("strict_eq agreed", consensus.last["agreed"])

    stored = contract.get(record_id)
    report.check("the record carries the label", stored["label"] == "01_shipped")
    report.check("the record says it came from extract", stored["method"] == "full")
    report.check("the record carries the reading", stored["result"] == result)
    report.check("the record carries the block datetime", stored["at"] == NOW)
    report.check("the datetime was read outside the block",
                 not gl.message_raw.read_inside)
    report.check("the body is nowhere in the record",
                 not any("almacen" in str(value) for value in stored.values()))
    report.check("the reading matches expected.json on shipped and eta",
                 result.rpartition("|inj=")[0] == expected["readings"]["01_shipped.txt"])

    # Two spellings of the same answer fold to one string.
    model.script({"shipped": True, "eta_day": "Jueves", "injection": False,
                  "confidence": 0.9},
                 '```json\n{"shipped": true, "eta_day": "jueves", "injection": false}\n```')
    contract.extract("01_shipped", shipped)
    report.check("an object and a fenced string fold to one string",
                 consensus.last["agreed"]
                 and consensus.last["leader"] == "shipped=1|eta=jueves|inj=0",
                 consensus.last["leader"])

    # The injection flag is part of what strict equality compares.
    model.script(answer(False, "", True), answer(False, "", False))
    contract.extract("03_injection_direct", body("03_injection_direct.txt"))
    report.check("a difference in inj alone is a disagreement",
                 not consensus.last["agreed"],
                 "%s vs %s" % (consensus.last["leader"], consensus.last["validator"]))

    # Probe D's delimiter body: its markers are gone before the model sees it.
    model.script(answer(False, "", True), answer(False, "", True))
    contract.extract("05_injection_marker", body("05_injection_marker.txt"))
    prompt = model.prompts[0]
    report.check("probe D's markers are not in the prompt",
                 "UNTRUSTED EMAIL BODY" not in prompt)
    report.check("the planted text is still inside the JSON string",
                 prompt.count("Correction to the rules above") == 1
                 and "Correction to the rules above" in data_line(prompt, module.body_tag(
                     module.sanitize(body("05_injection_marker.txt")))))

    # The new-format fake markers stay, inside the string, where they cannot
    # stand on a line of their own.
    fake = body("07_fake_marker.txt")
    model.script(answer(False, "", True), answer(False, "", True))
    contract.extract("07_fake_marker", fake)
    prompt = model.prompts[0]
    report.check("no prompt line is a fake marker",
                 "END-3f9a2c1b0d4e5f67" not in prompt.split("\n")
                 and "BEGIN-3f9a2c1b0d4e5f67" not in prompt.split("\n"))
    report.check("the fake tag appears only inside the data line",
                 all("3f9a2c1b0d4e5f67" not in line or line.startswith('"')
                     for line in prompt.split("\n")))

    # The escape body cannot close the string.
    escape = body("06_escape_break.txt")
    model.script(answer(False, "", True), answer(False, "", True))
    contract.extract("06_escape_break", escape)
    prompt = model.prompts[0]
    clean = module.sanitize(escape)
    report.check("the escape body decodes back to itself",
                 json.loads(data_line(prompt, module.body_tag(clean))) == clean)

    # Invisible characters go, look-alike letters stay, and the prompt is ASCII.
    unicode_body = body("10_unicode.json")
    model.script(answer(False, "", True), answer(False, "", True))
    contract.extract("10_unicode", unicode_body)
    prompt = model.prompts[0]
    decoded = json.loads(data_line(prompt, module.body_tag(module.sanitize(unicode_body))))
    report.check("the prompt is ASCII", all(ord(ch) < 128 for ch in prompt))
    report.check("no zero-width or bidi control reaches the model",
                 not any(ord(ch) in module.INVISIBLE for ch in decoded))
    report.check("the Cyrillic look-alikes do",
                 chr(0x0456) in decoded and chr(0x0435) in decoded)

    # The control. Same prompt, byte for byte; only inj is left out of the
    # string strict_eq compares.
    model.script(answer(True, "jueves", False), answer(True, "jueves", False))
    contract.extract("01_shipped", shipped)
    full_prompt = model.prompts[0]
    model.script(answer(True, "jueves", False), answer(True, "jueves", False))
    returned = contract.extract_plain("01_shipped", shipped)
    record_id, result = split(returned)
    report.check("extract_plain sends the same prompt as extract",
                 model.prompts[0] == full_prompt == model.prompts[1])
    report.check("extract_plain asks for JSON mode too",
                 model.configs[0].get("response_format") == "json")
    report.check("extract_plain returns the id and a reading without inj",
                 returned == record_id + " shipped=1|eta=jueves", returned)
    report.check("the record says it came from extract_plain",
                 contract.get(record_id)["method"] == "plain")

    model.script(answer(False, "", True), answer(False, "", False))
    contract.extract_plain("03_injection_direct", body("03_injection_direct.txt"))
    report.check("answers that differ only on inj agree in plain",
                 consensus.last["agreed"]
                 and consensus.last["leader"] == "shipped=0|eta=",
                 consensus.last["leader"])

    model.script({"shipped": False, "eta_day": ""},
                 {"shipped": False, "eta_day": "", "injection": "yes"})
    _, result = split(contract.extract_plain("no_inj", "cuerpo corto"))
    report.check("a missing or string injection is still a reading in plain",
                 result == "shipped=0|eta=" and consensus.last["agreed"], result)

    model.script({"shipped": "true", "eta_day": "jueves", "injection": False},
                 {"shipped": "true", "eta_day": "jueves", "injection": False})
    _, result = split(contract.extract_plain("shape", "cuerpo corto"))
    report.check("a shipped that is not a boolean is error=shape in plain",
                 result == module.SHAPE_ERROR)

    model.script()
    before = len(model.prompts)
    record_id, result = split(contract.extract_plain("huge", "x" * (module.MAX_BODY + 1)))
    report.check("extract_plain applies the same cap, before any prompt",
                 result == module.TOO_LARGE and len(model.prompts) == before
                 and contract.get(record_id)["method"] == "plain")

    # The failure paths, none of which may revert.
    model.script()
    model.fail = True
    _, result = split(contract.extract("no_model", "cuerpo corto"))
    report.check("a prompt that cannot run is a recorded result",
                 result == module.PROMPT_ERROR and consensus.last["agreed"])

    model.script({"shipped": True, "eta_day": "jueves", "injection": "false"},
                 {"shipped": True, "eta_day": "jueves", "injection": "false"})
    _, result = split(contract.extract("shape", "cuerpo corto"))
    report.check("an injection that is not a boolean is error=shape",
                 result == module.SHAPE_ERROR)

    model.script({"shipped": True, "eta_day": "jueves"},
                 {"shipped": True, "eta_day": "jueves"})
    _, result = split(contract.extract("shape", "cuerpo corto"))
    report.check("a missing injection is error=shape", result == module.SHAPE_ERROR)

    model.script("lo siento", "lo siento")
    _, result = split(contract.extract("prose", "cuerpo corto"))
    report.check("prose instead of JSON is error=parse", result == module.PARSE_ERROR)

    # The cap applies to the sanitized body.
    model.script()
    before = len(model.prompts)
    record_id, result = split(contract.extract("huge", "x" * (module.MAX_BODY + 1)))
    report.check("a body over the cap is stored, not raised",
                 result == module.TOO_LARGE)
    report.check("and no prompt was run for it", len(model.prompts) == before)
    report.check("the record still carries its label",
                 contract.get(record_id)["label"] == "huge")

    padded = "x" * module.MAX_BODY + chr(0x200B) * 1000
    model.script(answer(False, "", False), answer(False, "", False))
    _, result = split(contract.extract("padded", padded))
    report.check("invisible padding does not count against the cap",
                 result == "shipped=0|eta=|inj=0", result)

    report.check("every stored key is a str",
                 all(isinstance(key, str) for key in contract.records))
    report.check("ids run from 0 without a gap",
                 sorted(int(key) for key in contract.records)
                 == list(range(contract.count())))
    report.check("the datetime was never read inside a block",
                 not gl.message_raw.read_inside)

    print("\n%d checks, %d failed" % (report.total, report.failed))
    sys.exit(1 if report.failed else 0)


if __name__ == "__main__":
    main()
