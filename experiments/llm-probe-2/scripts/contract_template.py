# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

# Built by scripts/build_contract.py from llm/prompt.py and llm/fields.py;
# edit those, not this file. Probe D2: does a hardened prompt resist an
# instruction planted in an email body? Strict equality only. The body never
# reaches storage, a return value or a log.

from genlayer import *
from dataclasses import dataclass

# @@PROMPT@@

# @@FIELDS@@


def ask_once(clean, plain):
    # Never raises. plain changes the folding only, never the prompt.
    try:
        raw = gl.nondet.exec_prompt(build_prompt(clean), response_format="json")
    except Exception:
        return PROMPT_ERROR
    return normalize_answer(raw, plain)


@allow_storage
@dataclass
class ProbeRecord:
    record_id: str
    label: str
    method: str
    result: str
    at: str


class Contract(gl.Contract):
    records: TreeMap[str, ProbeRecord]
    next_id: u256

    def __init__(self):
        self.next_id = u256(0)

    @gl.public.write
    def extract(self, label: str, body: str) -> str:
        return self._extract(label, body, False)

    # The control: same prompt, consensus on shipped and eta alone, so a
    # disagreement on inj can be told apart from one on the reading.
    @gl.public.write
    def extract_plain(self, label: str, body: str) -> str:
        return self._extract(label, body, True)

    def _extract(self, label, body, plain):
        name = scrub(str(label), MAX_LABEL)
        method = "plain" if plain else "full"
        # Outside the block, so it is the transaction's time and not a value
        # validators would have to agree on.
        at = str(gl.message_raw["datetime"])
        # Sanitized before the size check: the cap is on what the model is
        # asked to read.
        clean = sanitize(str(body))
        if oversized(clean):
            return self._store(name, method, TOO_LARGE, at)

        # Nothing reached through self, which would be pickled with it.
        def probe() -> str:
            return ask_once(clean, plain)

        return self._store(name, method, str(gl.eq_principle.strict_eq(probe)), at)

    def _store(self, label, method, result, at):
        record_id = str(int(self.next_id))
        text = str(result)[:64]
        self.records[record_id] = ProbeRecord(
            record_id=record_id, label=label, method=method, result=text, at=at)
        self.next_id += u256(1)
        return record_id + " " + text

    @gl.public.view
    def count(self) -> int:
        return int(self.next_id)

    @gl.public.view
    def get(self, record_id: str) -> dict:
        key = str(record_id)
        if key not in self.records:
            raise gl.vm.UserError("[EXPECTED] no such record")
        record = self.records[key]
        return {
            "id": str(record.record_id),
            "label": str(record.label),
            "method": str(record.method),
            "result": str(record.result),
            "at": str(record.at),
        }
