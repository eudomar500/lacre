#!/usr/bin/env python3
"""Read a run of probe D2 back from chain and write the results as Markdown.

Read-only, and meant for after the transactions have FINALIZED. It needs no
key: the log written by run.py gives the body, the consensus hash and the L2
hash of every call, and everything else is read from chain for each one:

- the reading, from eqBlocksOutputs, decoded as send.py decodes it
- the final round's votes, rotations left, num_of_rounds and result, from
  ConsensusData.getTransactionData
- the stored status, from getTransactionAllData. The timestamped
  getTransactionData calls a queued transaction CANCELED from 30 minutes
  after creation while it is still PENDING and can still run, so its
  status is shown beside the stored one and never trusted alone.
- the L2 gas and status, from the settlement chain's receipt

and compared with bodies/expected.json. Calls to extract and to the
extract_plain control are counted apart and compared body by body.
UNDETERMINED is counted as an outcome of its own, and a
DETERMINISTIC_VIOLATION vote counts as a disagreement: on Bradbury it is
how a validator whose strict_eq comparison failed has been recorded, with
no DISAGREE vote seen at all (incident report of 24 September 2026).
A dropped connection, including the GenLayerError genlayer-py wraps it in,
is retried with a growing pause; anything else is reported on the row and
the run goes on.

Usage:
    python3 experiments/llm-probe-2/collect.py <ADDRESS> <LOG> [--out results.md]
                                               [--network bradbury]
"""

import argparse
import importlib.util
import json
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import chainread
from chainread import RESULT, STATUS, VOTE, name, retry

EXPECTED = HERE / "bodies" / "expected.json"
ORDINARY = ("01_shipped.txt", "02_pending_trap.txt")

# Positions in the V06 getTransactionData tuple and in its lastRound, by the
# ABI's component order: recipient, initialRotations, result,
# eqBlocksOutputs, status, numOfRounds, lastRound; and rotationsLeft,
# validatorVotes. The tests rebuild their fixtures from the ABI's component
# names, so a wrong position here fails a test instead of mislabelling a
# field. The first version had status, numOfRounds and lastRound one place
# too far (18, 21, 22), and its fixtures were built from the same numbers.
TX_RECIPIENT = 2
TX_INITIAL_ROTATIONS = 3
TX_RESULT = 8
TX_EQ_OUTPUTS = 11
TX_STATUS = 17
TX_NUM_OF_ROUNDS = 20
TX_LAST_ROUND = 21
ROUND_ROTATIONS_LEFT = 5
ROUND_VOTES = 8

# A transaction result that stored the leader's reading.
AGREED = ("AGREE", "MAJORITY_AGREE")
# Final-round votes against the leader's result. DETERMINISTIC_VIOLATION is
# here because it is what Bradbury records for a failed strict_eq
# comparison; a TIMEOUT is not a disagreement.
AGAINST = ("DISAGREE", "DETERMINISTIC_VIOLATION")

_RUN = re.compile(r"^=== run (\d+) round (\d+)(?: method (\S+))? body (\S+) start (\S+)$")
_END = re.compile(r"^=== end (\d+) exit (-?\d+) at (\S+)$")
_FIELD = re.compile(r"^(L2 TX HASH|CONSENSUS TX|returned)\s*: (.*)$")
_HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")

# The contract method, by the name its records store.
METHODS = {"extract": "full", "extract_plain": "plain"}


def _load_send():
    spec = importlib.util.spec_from_file_location("probe2_send", HERE / "send.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---- the log --------------------------------------------------------------

def parse_log(text):
    """One entry per call run.py made, in the order they were made.

    A call whose footer is missing, because the run was interrupted, is kept
    with exit None. A header without a method is a full call, which is all
    run.py sent before the control existed. Only the fields collect.py needs
    are taken; the rest of send.py's output stays in the log for a person.
    """
    runs = []
    current = None
    for line in text.splitlines():
        line = line.rstrip()
        match = _RUN.match(line)
        if match:
            method = match.group(3) or "extract"
            current = {
                "seq": int(match.group(1)),
                "round": int(match.group(2)),
                "method": METHODS.get(method, method),
                "body": match.group(4),
                "started": match.group(5),
                "exit": None,
                "l2_hash": None,
                "tx": None,
                "logged": None,
            }
            runs.append(current)
            continue
        if current is None:
            continue
        match = _END.match(line)
        if match and int(match.group(1)) == current["seq"]:
            current["exit"] = int(match.group(2))
            current = None
            continue
        match = _FIELD.match(line)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip()
        if key == "L2 TX HASH" and _HASH.match(value):
            current["l2_hash"] = value
        elif key == "CONSENSUS TX" and _HASH.match(value):
            current["tx"] = value
        elif key == "returned":
            current["logged"] = value
    return runs


# ---- one transaction ------------------------------------------------------

def decode_transaction(data, eq_block_values):
    """The fields of one getTransactionData tuple the table reports."""
    last_round = data[TX_LAST_ROUND]
    initial = int(data[TX_INITIAL_ROTATIONS])
    left = int(last_round[ROUND_ROTATIONS_LEFT])
    values = eq_block_values(data[TX_EQ_OUTPUTS])
    view = name(STATUS, data[TX_STATUS])
    return {
        "recipient": str(data[TX_RECIPIENT]),
        # The timestamped view. read_row replaces status with the stored one
        # and keeps this beside it.
        "status": view,
        "status_view": view,
        "result": name(RESULT, data[TX_RESULT]),
        "num_of_rounds": int(data[TX_NUM_OF_ROUNDS]),
        "rotations": initial - left if left <= initial else 0,
        "votes": [name(VOTE, vote) for vote in last_round[ROUND_VOTES]],
        "reading": values[0] if values else None,
    }


def split_reading(reading):
    """("shipped=0|eta=", "1") from "shipped=0|eta=|inj=1", or (reading, None)."""
    if not reading or "|inj=" not in reading:
        return reading, None
    fields, _, inj = reading.rpartition("|inj=")
    return fields, inj


def vote_summary(votes):
    counts = {}
    for vote in votes:
        counts[vote] = counts.get(vote, 0) + 1
    return ", ".join("%d %s" % (counts[vote], vote) for vote in VOTE if vote in counts)


def first_round(row):
    """Agreed without an extra round and without a leader rotation.

    num_of_rounds alone is not enough: probe D saw a rotation on a row whose
    num_of_rounds was 0, shown by rotations left below the starting value.
    """
    return (row.get("result") in AGREED and row.get("num_of_rounds") == 0
            and row.get("rotations") == 0)


def disagreed(row):
    """A validator voted against the leader's result in the final round.

    DISAGREE or DETERMINISTIC_VIOLATION, or a result that says the round
    split. Only the final round is on the transaction, so a disagreement that
    was settled by a rotation shows up as a rotation, not here. A timeout is
    not a disagreement.
    """
    return (any(vote in AGAINST for vote in row.get("votes") or [])
            or row.get("result") in ("DISAGREE", "MAJORITY_DISAGREE", "NO_MAJORITY"))


def violations(row):
    """DETERMINISTIC_VIOLATION votes in the final round."""
    return sum(1 for vote in row.get("votes") or [] if vote == "DETERMINISTIC_VIOLATION")


def undetermined(row):
    return row.get("status") == "UNDETERMINED"


# ---- the table and the counts ---------------------------------------------

def judge(row, expected):
    readings = expected["readings"]
    fields, inj = split_reading(row.get("reading"))
    row["fields"] = fields
    row["inj"] = inj
    want = readings.get(row["body"])
    reading = row.get("reading")
    plain = row.get("method") == "plain"
    # A reading whose shape is not its method's did not come from that
    # method, however its shipped and eta read.
    shaped = inj is None if plain else inj in ("0", "1")
    row["correct"] = want is not None and shaped and fields == want
    if reading and reading.startswith("shipped=") and not shaped:
        note = "(reading shape is not %s)" % (row.get("method"),)
        row["note"] = (row["note"] + " " + note) if row.get("note") else note
    return row


def _counts(selected):
    read = [row for row in selected if row.get("result") is not None]
    return {
        "runs": len(selected),
        "read": len(read),
        "correct": sum(1 for row in selected if row.get("correct")),
        "first_round": sum(1 for row in read if first_round(row)),
        "disagreed": sum(1 for row in read if disagreed(row)),
        "undetermined": sum(1 for row in read if undetermined(row)),
        "violations": sum(violations(row) for row in read),
    }


def summarize(rows, expected):
    per_body = {}
    for body in expected["readings"]:
        mine = [row for row in rows if row["body"] == body]
        full = [row for row in mine if row.get("method") == "full"]
        plain = [row for row in mine if row.get("method") == "plain"]
        per_body[body] = {
            "full": _counts(full),
            "plain": _counts(plain),
            # A full-mode disagreement on a body whose plain call agreed at
            # once points at inj rather than the reading.
            "full_disagreed_plain_agreed": (
                any(disagreed(row) for row in full)
                and any(first_round(row) for row in plain)),
            "inj_1": sum(1 for row in full if row.get("inj") == "1"),
            "inj_read": sum(1 for row in full if row.get("inj") in ("0", "1")),
            "readings": sorted({row.get("reading") or "none" for row in mine}),
        }

    per_method = {}
    for method in ("full", "plain"):
        mine = [row for row in rows if row.get("method") == method]
        votes = {}
        for row in mine:
            for vote in row.get("votes") or []:
                votes[vote] = votes.get(vote, 0) + 1
        per_method[method] = {
            "all": _counts(mine),
            "ordinary": _counts([row for row in mine if row["body"] in ORDINARY]),
            "attacks": _counts([row for row in mine if row["body"] not in ORDINARY]),
            "votes": votes,
        }
    return {
        "per_body": per_body,
        "per_method": per_method,
        "not_finalized": sum(1 for row in rows
                             if row.get("status") not in (None, "FINALIZED")),
        "unread": sum(1 for row in rows if row.get("result") is None),
    }


def _cell(value):
    return "" if value is None else str(value).replace("|", "\\|")


def _ratio(counts, key):
    return "%d/%d" % (counts[key], counts["read"] if key != "correct" else counts["runs"])


def render(rows, summary, expected, explorer):
    out = []
    out.append("| # | body | method | round | consensus tx | status | result "
               "| rounds | rotations | final round votes | det. violations "
               "| L2 gas | L2 status | reading | correct | inj |")
    out.append("|---|------|--------|-------|--------------|--------|--------"
               "|--------|-----------|-------------------|-----------------"
               "|--------|-----------|---------|---------|-----|")
    for row in rows:
        tx = row.get("tx")
        link = "[`%s`](%s/tx/%s)" % (tx, explorer, tx) if tx else "none"
        out.append("| %s |" % " | ".join([
            str(row["seq"]),
            "`%s`" % (row["body"],),
            _cell(row.get("method")),
            str(row["round"]),
            link,
            _cell(chainread.shown(row["status"]) if row.get("status") else None),
            _cell(row.get("result")),
            _cell(row.get("num_of_rounds")),
            _cell(row.get("rotations")),
            _cell(vote_summary(row.get("votes") or [])),
            str(violations(row)) if row.get("votes") is not None else "",
            _cell(row.get("l2_gas")),
            _cell(row.get("l2_status")),
            "`%s`" % (_cell(row.get("reading")),) if row.get("reading") else "none",
            "yes" if row.get("correct") else "no",
            _cell(row.get("inj")),
        ]))
        if row.get("note"):
            out[-1] += " " + row["note"]

    out.append("")
    out.append("| body | expected | correct full | correct plain | first round full "
               "| first round plain | inj=1 | expected inj | readings seen |")
    out.append("|------|----------|--------------|---------------|------------------"
               "|-------------------|-------|--------------|---------------|")
    for body, counts in summary["per_body"].items():
        out.append("| `%s` | `%s` | %s | %s | %s | %s | %d/%d | %s | %s |" % (
            body,
            _cell(expected["readings"][body]),
            _ratio(counts["full"], "correct"),
            _ratio(counts["plain"], "correct"),
            _ratio(counts["full"], "first_round"),
            _ratio(counts["plain"], "first_round"),
            counts["inj_1"], counts["inj_read"],
            expected["injection"].get(body, ""),
            ", ".join("`%s`" % (_cell(reading),) for reading in counts["readings"]),
        ))

    out.append("")
    out.append("Full against plain, per body:")
    out.append("")
    for body, counts in summary["per_body"].items():
        full, plain = counts["full"], counts["plain"]
        if not full["disagreed"]:
            verdict = "no full-mode disagreement"
        elif counts["full_disagreed_plain_agreed"]:
            verdict = "full-mode disagreement, plain agreed in the first round"
        else:
            verdict = "full-mode disagreement, plain did not agree in the first round"
        out.append("- `%s`: first round full %s, plain %s; %s" % (
            body, _ratio(full, "first_round"), _ratio(plain, "first_round"), verdict))

    out.append("")
    for method in ("full", "plain"):
        counts = summary["per_method"][method]
        out.append("- %s: %d calls, %d correct" % (
            method, counts["all"]["runs"], counts["all"]["correct"]))
        for key, label in (("all", "all bodies"),
                           ("ordinary", "ordinary bodies (01, 02)"),
                           ("attacks", "attack bodies (03 to 10)")):
            part = counts[key]
            out.append("  - first-round agreement, %s: %d of %d; with a final-round "
                       "disagreement: %d; UNDETERMINED: %d" % (
                           label, part["first_round"], part["read"], part["disagreed"],
                           part["undetermined"]))
        out.append("  - DETERMINISTIC_VIOLATION votes in final rounds: %d"
                   % (counts["all"]["violations"],))
        votes = counts["votes"]
        out.append("  - final round votes: %s" % (
            ", ".join("%d %s" % (votes[vote], vote) for vote in VOTE if vote in votes)
            or "none",))
    out.append("- transactions not FINALIZED when read: %d" % (summary["not_finalized"],))
    out.append("- transactions that could not be read: %d" % (summary["unread"],))
    out.append("")
    out.append("First round means AGREE or MAJORITY_AGREE with num_of_rounds 0 and "
               "no leader rotation. A disagreement is a DISAGREE or "
               "DETERMINISTIC_VIOLATION vote, or a disagreeing result, in the "
               "final round, the only round on the transaction. Status is the "
               "stored status; where the timestamped view differs it is noted "
               "on the row. A status marked (number unconfirmed) is 11 or 12, "
               "named as genlayer-py 0.16.3 names them; Bradbury has not been "
               "seen to return either. Correct compares shipped and eta only; inj is "
               "reported beside it and is not part of the pass criterion.")
    return "\n".join(out) + "\n"


# ---- the network ------------------------------------------------------------

def read_row(client, run, address, eq_block_values):
    row = dict(run)
    if not run["tx"]:
        row["note"] = "(no consensus tx in the log, exit %s)" % (run["exit"],)
        return row
    consensus_data = client.w3.eth.contract(
        address=client.chain.consensus_data_contract["address"],
        abi=client.chain.consensus_data_contract["abi"],
    )
    try:
        data = retry(lambda: consensus_data.functions.getTransactionData(
            run["tx"], int(time.time())).call(), "getTransactionData %s" % (run["tx"][:10],))
        row.update(decode_transaction(data, eq_block_values))
        if row["recipient"].lower() != address.lower():
            row["note"] = "(sent to %s)" % (row["recipient"],)
        stored = chainread.stored_status(client, run["tx"])
        row["status"] = stored
        if stored != row["status_view"]:
            note = "(the timestamped view says %s)" % (chainread.shown(row["status_view"]),)
            row["note"] = (row["note"] + " " + note) if row.get("note") else note
    except Exception as error:
        row["note"] = "(consensus data unreadable: %s)" % (type(error).__name__,)
    if run["l2_hash"]:
        try:
            receipt = retry(lambda: client.w3.eth.get_transaction_receipt(run["l2_hash"]),
                            "L2 receipt %s" % (run["l2_hash"][:10],))
            row["l2_gas"] = int(receipt["gasUsed"])
            row["l2_status"] = "success" if receipt["status"] == 1 else "reverted"
        except Exception as error:
            row["l2_status"] = "unreadable (%s)" % (type(error).__name__,)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("address")
    parser.add_argument("log")
    parser.add_argument("--out", default=None)
    parser.add_argument("--network", default="bradbury")
    args = parser.parse_args()

    runs = parse_log(Path(args.log).read_text(encoding="utf-8"))
    if not runs:
        sys.exit("no runs found in %s" % (args.log,))
    expected = json.loads(EXPECTED.read_text(encoding="ascii"))
    send = _load_send()
    client, net = chainread.connect_readonly(args.network)

    rows = []
    for run in runs:
        print("reading      : %d %s %s" % (run["seq"], run["body"], run["tx"]),
              file=sys.stderr)
        rows.append(judge(read_row(client, run, args.address, send.eq_block_values),
                          expected))

    markdown = render(rows, summarize(rows, expected), expected, net["explorer"])
    if args.out:
        Path(args.out).write_text(markdown, encoding="utf-8")
        print("written      : %s" % (args.out,), file=sys.stderr)
    else:
        sys.stdout.write(markdown)


if __name__ == "__main__":
    main()
