"""send.py, run.py and collect.py, without a network.

The eqBlocksOutputs fixtures ROW_0, ROW_2 and DEPLOY are probe D's recorded
Bradbury bytes. Probe D2's readings carry a third field, so the one fixture
in that shape is built here with the same encoder the chain uses and says so.
The getTransactionData tuples and the log are constructed in the shapes the
ABI and run.py define; no D2 transaction exists to record yet.
"""

import importlib.util
import json
from pathlib import Path

import pytest
import rlp
from genlayer_py.abi import calldata
from genlayer_py.chains import testnet_bradbury

PROBE = Path(__file__).resolve().parents[1]
BODIES = PROBE / "bodies"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


send = load(PROBE / "send.py", "probe2_send")
run = load(PROBE / "run.py", "probe2_run")
collect = load(PROBE / "collect.py", "probe2_collect")
chainread = collect.chainread
expected = json.loads((BODIES / "expected.json").read_text(encoding="ascii"))

# Recorded on Bradbury by probe D.
ROW_0 = bytes.fromhex("df9700a401736869707065643d317c6574613d6a756576657386706164646564")
ROW_2 = bytes.fromhex("d8900074736869707065643d307c6574613d86706164646564")
DEPLOY = bytes.fromhex("c786706164646564")

# Constructed: a D2 reading, encoded as a return (code 0) followed by the
# padding sentinel, which is the layout of the recorded rows above.
D2_READING = "shipped=0|eta=|inj=1"
D2_ROW = rlp.encode([b"\x00" + bytes(calldata.encode(D2_READING)), b"padded"])

TX_A = "0x" + "a1" * 32
TX_B = "0x" + "b2" * 32
L2_A = "0x" + "c3" * 32
ADDRESS = "0x" + "d4" * 20


ABI = testnet_bradbury.consensus_data_contract["abi"]
TX_FIELDS = chainread.fields(ABI, "getTransactionData")


def _last_round_fields():
    for item in ABI:
        if item.get("name") == "getTransactionData":
            for component in item["outputs"][0]["components"]:
                if component["name"] == "lastRound":
                    return [c["name"] for c in component["components"]]
    raise KeyError("lastRound")


ROUND_FIELDS = _last_round_fields()


def by_name(names, values):
    """A tuple in ABI order, filled by field name; every other field is None.

    Built from the ABI rather than from collect.py's positions, so a wrong
    position in collect.py reads the wrong field here and fails a test.
    """
    unknown = set(values) - set(names)
    assert not unknown, unknown
    return tuple(values.get(field) for field in names)


def transaction(eq_outputs, status=7, result=1, rounds=0, initial=3, left=3,
                votes=(1, 1, 1, 1, 1), recipient=ADDRESS):
    """A getTransactionData tuple in the V06 shape, as web3 hands it back."""
    last_round = by_name(ROUND_FIELDS, {
        "round": 0, "leaderIndex": 0, "votesCommitted": len(votes),
        "votesRevealed": len(votes), "appealBond": 0, "rotationsLeft": left,
        "result": result, "roundValidators": ["0x" + "00" * 20] * len(votes),
        "validatorVotes": list(votes), "validatorVotesHash": [],
        "validatorResultHash": [],
    })
    # txId sits right after status, and consumedValidators right after
    # lastRound: the two fields the first version read by mistake. Giving
    # them values of the wrong type makes an off-by-one fail loudly.
    return by_name(TX_FIELDS, {
        "recipient": recipient, "initialRotations": initial, "result": result,
        "eqBlocksOutputs": eq_outputs, "status": status, "txId": b"\xab" * 32,
        "numOfRounds": rounds, "lastRound": last_round,
        "consumedValidators": ["0x" + "11" * 20],
    })


# ---- send.py ------------------------------------------------------------------

def test_probe_ds_recorded_rows_still_decode():
    assert send.eq_block_values(ROW_0) == ["shipped=1|eta=jueves"]
    assert send.eq_block_values(ROW_2) == ["shipped=0|eta="]
    assert send.eq_block_values(DEPLOY) == []


def test_a_d2_reading_decodes():
    assert send.eq_block_values(D2_ROW) == [D2_READING]


@pytest.mark.parametrize("blob", [None, b"", b"\xff\xff\xff", bytes.fromhex("c4830041ff"),
                                  bytes.fromhex("c68501" + b"boom".hex())])
def test_nothing_readable_is_an_empty_list(blob):
    assert send.eq_block_values(blob) == []


def test_a_json_body_is_sent_decoded():
    text = send.read_body(BODIES / "10_unicode.json")
    assert text == json.loads((BODIES / "10_unicode.json").read_text())["body"]
    assert any(ord(ch) > 127 for ch in text)


def test_a_txt_body_is_sent_as_it_is():
    path = BODIES / "01_shipped.txt"
    assert send.read_body(path) == path.read_text(encoding="utf-8")


@pytest.mark.parametrize("arguments,method,rest", [
    (["0xabc", "b.txt"], "extract", ["0xabc", "b.txt"]),
    (["0xabc", "b.txt", "--plain"], "extract_plain", ["0xabc", "b.txt"]),
    (["--plain", "0xabc", "b.txt"], "extract_plain", ["0xabc", "b.txt"]),
])
def test_plain_picks_the_control_method(arguments, method, rest):
    assert send.take_method(arguments) == (method, rest)


def test_send_leaves_the_key_to_tools_chain():
    source = (PROBE / "send.py").read_text(encoding="ascii")
    assert "os.environ" not in source and "argv" in source


# ---- run.py -------------------------------------------------------------------

def test_the_default_plan_is_three_full_rounds_then_one_plain_round():
    order = run.plan()
    assert len(order) == 40
    names = [path.name for _, _, _, path in order]
    assert names[:10] == sorted(expected["readings"])
    assert names[:10] == names[10:20] == names[20:30] == names[30:]
    assert [seq for seq, _, _, _ in order] == list(range(1, 41))
    assert [number for _, number, _, _ in order] == sum(([n] * 10 for n in range(1, 5)), [])
    assert [method for _, _, method, _ in order] == ["extract"] * 30 + ["extract_plain"] * 10


def test_the_round_counts_can_be_changed():
    assert len(run.plan(1, 0)) == 10
    assert {method for _, _, method, _ in run.plan(0, 2)} == {"extract_plain"}


def test_run_writes_what_collect_parses():
    path = BODIES / "01_shipped.txt"
    text = (run.header(1, 1, "extract", path)
            + "L2 TX HASH   : %s\n" % (L2_A,)
            + "CONSENSUS TX : %s\n" % (TX_A,)
            + "returned     : shipped=1|eta=jueves|inj=0\n"
            + run.footer(1, 0))
    [parsed] = collect.parse_log(text)
    assert parsed["body"] == "01_shipped.txt"
    assert (parsed["tx"], parsed["l2_hash"], parsed["exit"]) == (TX_A, L2_A, 0)
    assert parsed["logged"] == "shipped=1|eta=jueves|inj=0"
    assert parsed["method"] == "full"


def test_a_plain_call_is_parsed_as_plain():
    text = run.header(31, 4, "extract_plain", BODIES / "01_shipped.txt") + run.footer(31, 0)
    [parsed] = collect.parse_log(text)
    assert (parsed["method"], parsed["round"], parsed["seq"]) == ("plain", 4, 31)


# ---- collect.py: the log ------------------------------------------------------

LOG = """=== probe d2 run of 3 on %(address)s start 2026-09-24T10:00:00+00:00
=== run 1 round 1 body 01_shipped.txt start 2026-09-24T10:00:00+00:00
network      : bradbury (chain id 4221)
L2 TX HASH   : %(l2)s
CONSENSUS TX : %(tx_a)s
returned     : shipped=1|eta=jueves|inj=0
%(tx_a)s
https://explorer-bradbury.genlayer.com/tx/%(tx_a)s
=== end 1 exit 0 at 2026-09-24T10:01:00+00:00
=== run 2 round 1 method extract body 02_pending_trap.txt start 2026-09-24T10:01:00+00:00
error: broadcast refused: nonce too low
=== end 2 exit 1 at 2026-09-24T10:01:05+00:00
=== run 3 round 1 body 03_injection_direct.txt start 2026-09-24T10:01:05+00:00
CONSENSUS TX : %(tx_b)s
""" % {"address": ADDRESS, "l2": L2_A, "tx_a": TX_A, "tx_b": TX_B}


def test_the_log_yields_one_entry_per_call():
    runs = collect.parse_log(LOG)
    assert [entry["seq"] for entry in runs] == [1, 2, 3]
    assert runs[0]["tx"] == TX_A and runs[0]["l2_hash"] == L2_A and runs[0]["exit"] == 0


def test_a_header_without_a_method_is_a_full_call():
    assert collect.parse_log(LOG)[0]["method"] == "full"


def test_a_failed_call_is_kept_without_a_hash():
    entry = collect.parse_log(LOG)[1]
    assert entry["body"] == "02_pending_trap.txt"
    assert entry["tx"] is None and entry["exit"] == 1


def test_an_interrupted_call_is_kept_with_no_exit():
    entry = collect.parse_log(LOG)[2]
    assert entry["tx"] == TX_B and entry["exit"] is None


def test_a_malformed_hash_is_not_taken():
    text = run.header(1, 1, "extract", BODIES / "01_shipped.txt") + "CONSENSUS TX : 0x1234\n"
    assert collect.parse_log(text)[0]["tx"] is None


# ---- collect.py: one transaction ----------------------------------------------

def test_a_clean_first_round():
    row = collect.decode_transaction(transaction(D2_ROW), send.eq_block_values)
    assert row["reading"] == D2_READING
    assert (row["status"], row["result"]) == ("FINALIZED", "AGREE")
    assert (row["num_of_rounds"], row["rotations"]) == (0, 0)
    assert row["votes"] == ["AGREE"] * 5
    assert collect.first_round(row)


def test_a_rotation_without_an_extra_round_is_not_first_round():
    """Probe D's row 0: num_of_rounds 0, rotations left 2 of 3."""
    row = collect.decode_transaction(
        transaction(ROW_0, left=2, votes=(1, 1, 1, 1, 3)), send.eq_block_values)
    assert row["rotations"] == 1
    assert collect.vote_summary(row["votes"]) == "4 AGREE, 1 TIMEOUT"
    assert not collect.first_round(row)


def test_an_extra_round_is_not_first_round():
    row = collect.decode_transaction(transaction(D2_ROW, rounds=2), send.eq_block_values)
    assert not collect.first_round(row)


def test_unknown_enum_values_are_named_not_raised():
    row = collect.decode_transaction(transaction(DEPLOY, status=99, result=42,
                                                 votes=(7,)), send.eq_block_values)
    assert row["status"] == "UNKNOWN_99" and row["result"] == "UNKNOWN_42"
    assert row["votes"] == ["UNKNOWN_7"] and row["reading"] is None


@pytest.mark.parametrize("reading,fields,inj", [
    ("shipped=0|eta=|inj=1", "shipped=0|eta=", "1"),
    ("shipped=1|eta=jueves|inj=0", "shipped=1|eta=jueves", "0"),
    ("error=prompt", "error=prompt", None),
    (None, None, None),
])
def test_split_reading(reading, fields, inj):
    assert collect.split_reading(reading) == (fields, inj)


# ---- collect.py: the table ----------------------------------------------------

def encoded(reading):
    """A return of reading followed by the padding sentinel, as on chain."""
    return rlp.encode([b"\x00" + bytes(calldata.encode(reading)), b"padded"])


def rows():
    made = []
    specs = [
        ("01_shipped.txt", "full", ROW_0, {}),
        ("02_pending_trap.txt", "full", D2_ROW, {"left": 2}),
        ("05_injection_marker.txt", "full", encoded("shipped=1|eta=miercoles|inj=0"), {}),
        # 03: full disagrees in the final round, plain agrees at once.
        ("03_injection_direct.txt", "full", encoded("shipped=0|eta=|inj=1"),
         {"votes": (1, 1, 1, 2, 2)}),
        ("03_injection_direct.txt", "plain", encoded("shipped=0|eta="), {}),
        # 02: plain on a body whose full call rotated but never disagreed.
        ("02_pending_trap.txt", "plain", encoded("shipped=0|eta="), {}),
        # A plain call whose reading carries inj is not a plain reading.
        ("04_injection_hidden.txt", "plain", encoded("shipped=0|eta=|inj=1"), {}),
    ]
    for seq, (body_name, method, blob, extra) in enumerate(specs, 1):
        row = {"seq": seq, "round": 1, "method": method, "body": body_name, "tx": TX_A,
               "l2_hash": L2_A, "exit": 0, "logged": None,
               "l2_gas": 1000000 + seq, "l2_status": "success"}
        row.update(collect.decode_transaction(transaction(blob, **extra),
                                              send.eq_block_values))
        made.append(collect.judge(row, expected))
    made.append(collect.judge({"seq": 8, "round": 1, "method": "full",
                               "body": "06_escape_break.txt",
                               "tx": None, "l2_hash": None, "exit": 1,
                               "logged": None}, expected))
    return made


def test_judging_compares_shipped_and_eta_only():
    table = rows()
    # Probe D's reading has no inj field, so it cannot be judged as a D2 one.
    assert not table[0]["correct"]
    assert table[1]["correct"] and table[1]["inj"] == "1"
    assert not table[2]["correct"]
    assert table[3]["correct"]
    assert table[4]["correct"] and table[4]["inj"] is None
    assert table[5]["correct"]
    assert not table[6]["correct"] and "reading shape is not plain" in table[6]["note"]
    assert not table[7]["correct"]


def test_the_summary_counts():
    summary = collect.summarize(rows(), expected)
    pending = summary["per_body"]["02_pending_trap.txt"]
    assert pending["full"]["correct"] == 1 and pending["plain"]["correct"] == 1
    assert pending["inj_1"] == 1
    assert summary["per_body"]["09_gift_message.txt"]["full"]["runs"] == 0
    full = summary["per_method"]["full"]
    plain = summary["per_method"]["plain"]
    assert (full["all"]["runs"], full["all"]["read"], full["all"]["first_round"]) == (5, 4, 3)
    assert (full["ordinary"]["first_round"], full["ordinary"]["read"]) == (1, 2)
    assert full["attacks"]["disagreed"] == 1
    assert (plain["all"]["runs"], plain["all"]["first_round"], plain["all"]["correct"]) == (3, 3, 2)
    assert full["votes"] == {"AGREE": 18, "DISAGREE": 2}
    assert plain["votes"] == {"AGREE": 15}
    assert summary["unread"] == 1


def test_a_full_disagreement_with_a_plain_agreement_is_singled_out():
    per_body = collect.summarize(rows(), expected)["per_body"]
    assert per_body["03_injection_direct.txt"]["full_disagreed_plain_agreed"]
    # A rotation is not a final-round disagreement.
    assert not per_body["02_pending_trap.txt"]["full_disagreed_plain_agreed"]
    assert per_body["02_pending_trap.txt"]["full"]["disagreed"] == 0


def test_a_disagreement_is_a_vote_or_a_result_not_a_timeout():
    assert collect.disagreed({"votes": ["AGREE", "DISAGREE"], "result": "AGREE"})
    assert collect.disagreed({"votes": [], "result": "NO_MAJORITY"})
    assert not collect.disagreed({"votes": ["AGREE", "TIMEOUT"], "result": "AGREE"})


def test_the_markdown_has_a_row_per_call_and_a_row_per_body():
    table = rows()
    markdown = collect.render(table, collect.summarize(table, expected), expected,
                              "https://explorer-bradbury.genlayer.com")
    lines = markdown.splitlines()
    assert sum(1 for line in lines if line.startswith("| 1 | ")) == 1
    for name in expected["readings"]:
        assert sum(1 for line in lines if line.startswith("| `%s` |" % (name,))) == 1
    assert "`shipped=0\\|eta=\\|inj=1`" in markdown
    assert "  - first-round agreement, ordinary bodies (01, 02): 1 of 2" in markdown
    assert "- plain: 3 calls, 2 correct" in markdown
    assert ("- `03_injection_direct.txt`: first round full 1/1, plain 1/1; "
            "full-mode disagreement, plain agreed in the first round") in markdown
    assert "| 5 | `03_injection_direct.txt` | plain | 1 |" in markdown
    markdown.encode("ascii")


# ---- collect.py: the network, without one -------------------------------------

def test_a_dropped_connection_is_retried():
    calls = []
    pauses = []

    def flaky():
        calls.append(1)
        if len(calls) < 3:
            raise ConnectionResetError("dropped")
        return "ok"

    assert collect.retry(flaky, "test", sleep=pauses.append) == "ok"
    assert len(calls) == 3 and pauses == [2.0, 4.0]


def test_retrying_gives_up_in_the_end():
    def dead():
        raise TimeoutError("gone")

    with pytest.raises(TimeoutError):
        collect.retry(dead, "test", attempts=3, sleep=lambda _: None)


def test_other_errors_are_not_retried():
    calls = []

    def broken():
        calls.append(1)
        raise ValueError("revert")

    with pytest.raises(ValueError):
        collect.retry(broken, "test", sleep=lambda _: None)
    assert len(calls) == 1


from genlayer_py.exceptions import GenLayerError


@pytest.mark.parametrize("message", [
    "Request to https://rpc-bradbury.genlayer.com failed: (\"Connection broken: "
    "InvalidChunkLength(got length b'', 0 bytes read)\")",
    "eth_chainId returned invalid JSON: Expecting value: line 1 column 1 (char 0)",
])
def test_the_sdks_wrapped_connection_errors_are_retried(message):
    calls = []

    def flaky():
        calls.append(1)
        if len(calls) < 2:
            raise GenLayerError(message)
        return "ok"

    assert collect.retry(flaky, "test", sleep=lambda _: None) == "ok"
    assert len(calls) == 2


def test_a_revert_wrapped_by_the_sdk_is_not_retried():
    calls = []

    def reverted():
        calls.append(1)
        raise GenLayerError("eth_call failed (code=3): execution reverted")

    with pytest.raises(GenLayerError):
        collect.retry(reverted, "test", sleep=lambda _: None)
    assert len(calls) == 1


# ---- collect.py: positions, read from the ABI ---------------------------------

@pytest.mark.parametrize("constant,field", [
    ("TX_RECIPIENT", "recipient"), ("TX_INITIAL_ROTATIONS", "initialRotations"),
    ("TX_RESULT", "result"), ("TX_EQ_OUTPUTS", "eqBlocksOutputs"),
    ("TX_STATUS", "status"), ("TX_NUM_OF_ROUNDS", "numOfRounds"),
    ("TX_LAST_ROUND", "lastRound"),
])
def test_every_transaction_position_is_the_abis(constant, field):
    assert getattr(collect, constant) == TX_FIELDS.index(field)


@pytest.mark.parametrize("constant,field", [
    ("ROUND_ROTATIONS_LEFT", "rotationsLeft"), ("ROUND_VOTES", "validatorVotes"),
])
def test_every_round_position_is_the_abis(constant, field):
    assert getattr(collect, constant) == ROUND_FIELDS.index(field)


def test_the_first_versions_positions_misread_an_abi_built_tuple(monkeypatch):
    """18, 21 and 22 were txId, lastRound and consumedValidators."""
    monkeypatch.setattr(collect, "TX_STATUS", 18)
    monkeypatch.setattr(collect, "TX_NUM_OF_ROUNDS", 21)
    monkeypatch.setattr(collect, "TX_LAST_ROUND", 22)
    with pytest.raises((TypeError, ValueError, IndexError)):
        collect.decode_transaction(transaction(D2_ROW), send.eq_block_values)


# ---- collect.py: outcomes ---------------------------------------------------

def test_undetermined_is_its_own_outcome():
    row = collect.decode_transaction(
        transaction(encoded("error=shape"), status=6, result=5, rounds=2, left=0,
                    votes=(1, 3, 4, 4, 4)), send.eq_block_values)
    row.update({"seq": 1, "round": 1, "method": "full", "body": "04_injection_hidden.txt"})
    assert collect.undetermined(row)
    assert collect.disagreed(row)
    assert collect.violations(row) == 3
    summary = collect.summarize([collect.judge(row, expected)], expected)
    assert summary["per_method"]["full"]["all"]["undetermined"] == 1
    assert summary["per_method"]["full"]["all"]["violations"] == 3


def test_a_deterministic_violation_vote_is_a_disagreement():
    row = {"votes": ["AGREE", "AGREE", "AGREE", "TIMEOUT", "DETERMINISTIC_VIOLATION"],
           "result": "AGREE"}
    assert collect.disagreed(row)
    assert collect.violations(row) == 1


def test_the_violations_column_is_rendered():
    row = collect.decode_transaction(
        transaction(D2_ROW, votes=(1, 1, 1, 3, 4)), send.eq_block_values)
    row.update({"seq": 1, "round": 1, "method": "full",
                "body": "09_gift_message.txt", "tx": TX_A})
    table = [collect.judge(row, expected)]
    markdown = collect.render(table, collect.summarize(table, expected), expected, "x")
    header = [line for line in markdown.splitlines() if line.startswith("| # |")][0]
    cells = [cell.strip() for cell in header.split("|")]
    line = [line for line in markdown.splitlines() if line.startswith("| 1 |")][0]
    values = [cell.strip() for cell in line.split("|")]
    assert values[cells.index("det. violations")] == "1"
    assert "DETERMINISTIC_VIOLATION votes in final rounds: 1" in markdown


# ---- collect.py: the stored status wins over the timestamped view --------------

class FakeCall:
    def __init__(self, value):
        self.value = value

    def call(self):
        return self.value


class FakeFunctions:
    def __init__(self, data):
        self.data = data

    def getTransactionData(self, tx_id, timestamp):
        return FakeCall(self.data)


class FakeClient:
    def __init__(self, data):
        functions = FakeFunctions(data)
        contract = type("Contract", (), {"functions": functions})()

        class Eth:
            @staticmethod
            def contract(address, abi):
                return contract

            @staticmethod
            def get_transaction_receipt(l2):
                return {"gasUsed": 1000, "status": 1}

        self.w3 = type("W3", (), {"eth": Eth})()
        self.chain = type("Chain", (), {"consensus_data_contract": {
            "address": "0x" + "00" * 20, "abi": ABI}})()


def test_a_queued_transaction_the_view_calls_canceled_is_shown_as_stored(monkeypatch):
    monkeypatch.setattr(chainread, "stored_status", lambda client, tx_id: "PENDING")
    run_entry = {"seq": 17, "round": 2, "method": "full", "body": "07_fake_marker.txt",
                 "tx": TX_A, "l2_hash": L2_A, "exit": 1, "logged": None, "started": "t"}
    row = collect.read_row(FakeClient(transaction(b"", status=8, result=0, votes=())),
                           run_entry, ADDRESS, send.eq_block_values)
    assert row["status"] == "PENDING"
    assert row["status_view"] == "CANCELED"
    assert "the timestamped view says CANCELED" in row["note"]


def test_a_status_whose_number_is_unconfirmed_is_marked_in_the_table():
    table = rows()
    table[0]["status"] = "VALIDATORS_TIMEOUT"
    table[1]["status"] = "LEADER_TIMEOUT"
    markdown = collect.render(table, collect.summarize(table, expected), expected,
                              "https://explorer-bradbury.genlayer.com")
    lines = markdown.splitlines()
    first = [line for line in lines if line.startswith("| 1 | ")][0]
    second = [line for line in lines if line.startswith("| 2 | ")][0]
    assert "| VALIDATORS_TIMEOUT (number unconfirmed) |" in first
    assert "| LEADER_TIMEOUT |" in second
    assert "A status marked (number unconfirmed) is 11 or 12" in markdown


def test_an_unconfirmed_view_status_is_marked_in_the_note(monkeypatch):
    monkeypatch.setattr(chainread, "stored_status", lambda client, tx_id: "FINALIZED")
    run_entry = {"seq": 1, "round": 1, "method": "full", "body": "01_shipped.txt",
                 "tx": TX_A, "l2_hash": L2_A, "exit": 0, "logged": None, "started": "t"}
    row = collect.read_row(FakeClient(transaction(b"", status=11, result=1, votes=())),
                           run_entry, ADDRESS, send.eq_block_values)
    assert "the timestamped view says READY_TO_FINALIZE (number unconfirmed)" in row["note"]


def test_collect_needs_no_key():
    source = (PROBE / "collect.py").read_text(encoding="ascii")
    assert "PROBE_PK" not in source
    assert "chain.connect(" not in source
