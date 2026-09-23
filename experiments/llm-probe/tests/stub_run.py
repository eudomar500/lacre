#!/usr/bin/env python3
"""Drive contracts/llm_probe.py against a stubbed SDK and a scripted model.

The contract is executed as written, with stand-ins for the parts of the
runner it touches: storage, gl.message_raw, the prompt call and both
equivalence principles. Nothing is deployed, no prompt is run and no gas is
spent.

The model is scripted rather than sampled, which is the point. A validator
disagreeing with a leader on Bradbury has two possible causes, the model
reading the body differently and the contract folding the same reading into a
different string, and only the second one is this harness's business. So the
stub hands the leader and the validator answers chosen by the test, runs both
sides of the principle the way the runner does, and reports which of them
agreed.

The two principles are stubbed apart, because which one is used is half of
what this probe asks. strict_eq compares the two results byte for byte, the
way the runner does. prompt_comparative is recorded with the principle text
it was given and then judged by the same byte comparison, because PRINCIPLE
asks for exactly that and no model here can be asked.

Usage:
    python3 experiments/llm-probe/tests/stub_run.py
"""

import json
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROBE = HERE.parent
CONTRACT = PROBE / "contracts" / "llm_probe.py"
BODIES = PROBE / "bodies"

NOW = "2026-09-23T10:00:00Z"


class TreeMap(dict):
    """Storage map. dict answers get, contains and item assignment alike."""


class UserError(Exception):
    pass


class Model:
    """The scripted model behind gl.nondet.exec_prompt.

    Answers are served in order and the prompts and the keyword arguments
    are kept, so a test can assert what the contract actually sent as well as
    what it made of what came back. An answer may be a dict, which is what
    the host hands back in JSON mode, or a str, which is the text mode shape
    normalize_answer still accepts. An empty script means the call raises,
    which is how the contract's own failure path is reached.
    """

    def __init__(self):
        self.answers = []
        self.prompts = []
        self.configs = []
        self.fail = False

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
    """The two equivalence principles, as the runner applies them.

    Each call runs the leader's function once and the validator's function
    once, in that order, and records whether the validator agreed. The result
    the contract goes on to store is the leader's, which is also what the
    runner does: a validator that disagrees does not replace the answer, it
    rejects it.
    """

    def __init__(self):
        self.rounds = []

    def strict_eq(self, fn):
        leader = fn()
        validator = fn()
        self.rounds.append({
            "mode": "strict",
            "leader": leader,
            "validator": validator,
            "agreed": type(leader) is type(validator) and leader == validator,
            "principle": None,
        })
        return leader

    def prompt_comparative(self, fn, principle):
        leader = fn()
        validator = fn()
        self.rounds.append({
            "mode": "comparative",
            "leader": leader,
            "validator": validator,
            "agreed": leader == validator,
            "principle": principle,
        })
        return leader

    @property
    def last(self):
        return self.rounds[-1]


def build_sdk(model, consensus):
    """A genlayer module with the names the contract imports."""
    gl = types.SimpleNamespace(
        Contract=type("Contract", (), {}),
        message_raw={"datetime": NOW},
        public=types.SimpleNamespace(write=lambda fn: fn, view=lambda fn: fn),
        vm=types.SimpleNamespace(UserError=UserError),
        nondet=types.SimpleNamespace(exec_prompt=model.exec_prompt),
        eq_principle=types.SimpleNamespace(
            strict_eq=consensus.strict_eq,
            prompt_comparative=consensus.prompt_comparative,
        ),
    )

    sdk = types.ModuleType("genlayer")
    sdk.__all__ = ["gl", "u256", "TreeMap", "allow_storage"]
    sdk.gl = gl
    sdk.u256 = int
    sdk.TreeMap = TreeMap
    sdk.allow_storage = lambda cls: cls
    return sdk


def load_contract(model, consensus):
    sys.modules["genlayer"] = build_sdk(model, consensus)
    module = types.ModuleType("llm_probe")
    module.__file__ = str(CONTRACT)
    exec(compile(CONTRACT.read_text(encoding="ascii"), str(CONTRACT), "exec"),
         module.__dict__)

    contract = module.Contract.__new__(module.Contract)
    for name, annotation in module.Contract.__annotations__.items():
        if getattr(annotation, "__origin__", annotation) is TreeMap:
            setattr(contract, name, TreeMap())
    contract.__init__()
    return contract, module


def answer(shipped, day):
    """A JSON mode answer, decoded by the host before the contract sees it."""
    return {"shipped": shipped, "eta_day": day}


def text_answer(shipped, day):
    """The same answer as text mode would deliver it."""
    return json.dumps({"shipped": shipped, "eta_day": day})


def split(returned):
    """The contract's "<id> <reading>" return value, taken apart."""
    record_id, _, result = str(returned).partition(" ")
    return record_id, result


class Report:
    def __init__(self):
        self.failed = 0
        self.total = 0

    def check(self, label, condition, detail=""):
        self.total += 1
        print("%-4s %-54s %s" % ("ok" if condition else "FAIL", label, detail))
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
    contract, module = load_contract(model, consensus)
    expected = json.loads((BODIES / "expected.json").read_text(encoding="ascii"))
    shipped_body = (BODIES / "01_shipped.txt").read_text(encoding="ascii")
    injected_body = (BODIES / "03_injection_direct.txt").read_text(encoding="ascii")
    marker_body = (BODIES / "05_injection_marker.txt").read_text(encoding="ascii")

    print("contract     : %s (%d bytes)"
          % (CONTRACT.name, len(CONTRACT.read_bytes())))
    print("bodies       : %d\n" % (len(expected),))

    report = Report()
    report.check("nothing is stored yet", contract.count() == 0)
    report.raises("get() on an unknown id raises", lambda: contract.get("0"))

    # The prompt, as the body sees it.
    model.script(answer(True, "jueves"), answer(True, "jueves"))
    returned = contract.extract_strict("01_shipped", shipped_body)
    record_id, result = split(returned)
    prompt = model.prompts[0]
    report.check("the body is quoted inside the prompt",
                 shipped_body.strip() in prompt)
    report.check("it is between the two markers",
                 prompt.index("BEGIN UNTRUSTED EMAIL BODY")
                 < prompt.index(shipped_body.strip())
                 < prompt.index("END UNTRUSTED EMAIL BODY"))
    report.check("the marker itself is gone",
                 module.BODY_MARKER not in prompt)
    report.check("leader and validator were sent the same prompt",
                 model.prompts[0] == model.prompts[1])
    report.check("the contract asked for JSON mode",
                 model.configs[0].get("response_format") == "json",
                 str(model.configs[0]))

    # The return value: the id and the reading, one space apart, which is
    # what the consensus receipt shows at ACCEPTED.
    stored = contract.get(record_id)
    report.check("extract_strict returns the id and the reading",
                 returned == "0 " + expected["01_shipped.txt"], returned)
    report.check("the reading half is the one it stored",
                 result == stored["result"])
    report.check("a decoded object is read without a parse step",
                 result == "shipped=1|eta=jueves")
    report.check("count() counts it", contract.count() == 1)
    report.check("the record carries the label", stored["label"] == "01_shipped")
    report.check("the record carries the mode", stored["mode"] == "strict")
    report.check("the record carries the block datetime", stored["at"] == NOW)
    report.check("the record carries the canonical string",
                 stored["result"] == expected["01_shipped.txt"], stored["result"])
    report.check("the body is nowhere in the record",
                 not any("almacen" in str(value) for value in stored.values()))
    report.check("strict_eq was the principle used",
                 consensus.last["mode"] == "strict" and consensus.last["agreed"])

    # The same reading, delivered in three different shapes: a decoded object
    # with an accented day and a key nobody asked for, and a fenced string.
    # This is the case strict equality exists to survive and normalization
    # exists to make possible.
    model.script({"shipped": True, "eta_day": "Jueves", "confidence": 0.9},
                 '```json\n' + text_answer(True, "jueves") + '\n```')
    contract.extract_strict("01_shipped", shipped_body)
    report.check("an object and a fenced string fold to one string",
                 consensus.last["agreed"]
                 and consensus.last["leader"] == expected["01_shipped.txt"],
                 consensus.last["leader"])

    # Two different readings do not.
    model.script(answer(True, "jueves"), answer(True, "viernes"))
    contract.extract_strict("01_shipped", shipped_body)
    report.check("two different days do not agree",
                 not consensus.last["agreed"],
                 "%s vs %s" % (consensus.last["leader"], consensus.last["validator"]))

    # The comparative path, on decoded objects.
    model.script(answer(False, ""), answer(False, ""))
    returned = contract.extract_comparative("02_pending_trap", "cuerpo corto")
    record_id, result = split(returned)
    report.check("extract_comparative returns the id and the reading",
                 result == "shipped=0|eta=", returned)
    report.check("extract_comparative stores its own mode",
                 contract.get(record_id)["mode"] == "comparative")
    report.check("it asked for JSON mode too",
                 all(config.get("response_format") == "json"
                     for config in model.configs), str(model.configs))
    report.check("it used the comparative principle",
                 consensus.last["mode"] == "comparative")
    report.check("the principle asks for both fields",
                 "both fields are identical" in consensus.last["principle"])
    report.check("the principle text is the contract's constant",
                 consensus.last["principle"] == module.PRINCIPLE)

    # A model that followed the injection instead of the body. The contract
    # has no way to tell and stores what it was told; the probe's answer is
    # the comparison with expected.json, not a guard in the contract.
    model.script(answer(True, "miercoles"), answer(True, "miercoles"))
    _, result = split(contract.extract_strict("03_injection_direct", injected_body))
    report.check("an obeyed injection is stored as what the model said",
                 result == "shipped=1|eta=miercoles")
    report.check("and it does not match expected.json",
                 result != expected["03_injection_direct.txt"])

    # The marker body goes into the prompt exactly as it arrived. The contract
    # escapes nothing, on purpose: whether the prompt survives a body that
    # closes the quoted region is the question body 05 is there to ask, and an
    # escape here would answer it before the network could.
    model.script(answer(False, ""), answer(False, ""))
    contract.extract_strict("05_injection_marker", marker_body)
    prompt = model.prompts[0]
    report.check("the marker body is quoted unescaped",
                 marker_body.strip() in prompt)
    report.check("so the prompt carries two of each marker",
                 prompt.count("-----END UNTRUSTED EMAIL BODY-----") == 2
                 and prompt.count("-----BEGIN UNTRUSTED EMAIL BODY-----") == 2,
                 "begin %d, end %d"
                 % (prompt.count("-----BEGIN UNTRUSTED EMAIL BODY-----"),
                    prompt.count("-----END UNTRUSTED EMAIL BODY-----")))

    # The failure paths, none of which may revert.
    model.script()
    model.fail = True
    record_id, result = split(contract.extract_strict("no_model", "cuerpo corto"))
    report.check("a prompt that cannot run is a recorded result",
                 result == module.PROMPT_ERROR)
    report.check("and both sides recorded the same one",
                 consensus.last["agreed"])

    # In JSON mode the host decodes the answer, so text never arrives. The
    # string path stays covered anyway, because normalize_answer keeps it and
    # a switch back to text mode would depend on it.
    model.script("lo siento, no puedo ayudarte con eso",
                 "lo siento, no puedo ayudarte con eso")
    _, result = split(contract.extract_strict("prose", "cuerpo corto"))
    report.check("prose instead of JSON is a recorded result",
                 result == module.PARSE_ERROR)

    model.script({"shipped": 1, "eta_day": "jueves"},
                 {"shipped": 1, "eta_day": "jueves"})
    _, result = split(contract.extract_strict("shape", "cuerpo corto"))
    report.check("an object whose shipped is not a boolean is a result",
                 result == module.SHAPE_ERROR)

    model.script({"shipped": True, "eta_day": "manana"},
                 {"shipped": True, "eta_day": 7})
    contract.extract_strict("day", "cuerpo corto")
    report.check("an unknown day and a wrong typed one are both no day",
                 consensus.last["agreed"]
                 and consensus.last["leader"] == "shipped=1|eta=",
                 consensus.last["leader"])

    # The size limit, which is checked before anything is asked.
    model.script()
    before = len(model.prompts)
    record_id, result = split(contract.extract_strict("huge",
                                                      "x" * (module.MAX_BODY + 1)))
    report.check("a body over the cap is stored, not raised",
                 result == module.TOO_LARGE)
    report.check("and no prompt was run for it", len(model.prompts) == before)
    report.check("the record still carries its label and mode",
                 contract.get(record_id)["label"] == "huge"
                 and contract.get(record_id)["mode"] == "strict")

    model.script(answer(False, ""), answer(False, ""))
    _, result = split(contract.extract_strict("exact", "x" * module.MAX_BODY))
    report.check("a body exactly at the cap is asked about",
                 result == "shipped=0|eta=")

    # Storage keys are strings, on the write and on the read.
    report.check("every stored key is a str",
                 all(isinstance(key, str) for key in contract.records))
    report.check("ids run from 0 without a gap",
                 sorted(int(key) for key in contract.records)
                 == list(range(contract.count())))

    print("\n%d checks, %d failed" % (report.total, report.failed))
    sys.exit(1 if report.failed else 0)


if __name__ == "__main__":
    main()
