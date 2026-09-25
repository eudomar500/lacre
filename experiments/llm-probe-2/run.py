#!/usr/bin/env python3
"""Send the probe D2 plan to a deployed llm_probe2, one decided call at a time.

The plan is 40 calls: three rounds of extract over the ten bodies in file
name order, then one round of extract_plain over the same ten. Rounds go one
after another, so the repeats of one body are spread across the run, and the
control round comes last so it does not change the conditions of the three
it is compared with.

A run is a window of the plan: --batch calls (default 10) starting at call
--start (default 1), so the 40 calls can go in four windows of ten.

Call N+1 is never sent until call N's GenLayer transaction is decided, by
its stored status (ACCEPTED, UNDETERMINED, FINALIZED, CANCELED,
LEADER_TIMEOUT or VALIDATORS_TIMEOUT). The first run, on 24 September
2026, sent the next call as soon as send.py exited; one dropped connection
and an event send.py did not recognise put 21 transactions in the
contract's queue in three minutes and filled it.

The window stops at the first unexpected condition, before sending anything
else:
- a send that went on chain without a consensus tx id, or whose L2
  transaction reverted,
- a PendingQueueFull revert,
- a broadcast whose outcome tools/chain.py could not establish, a refusal
  no retry changes (insufficient funds, a spent nonce), or a pinned nonce
  the account has already moved past,
- any exit that is not a clean, decided result (after waiting, read-only,
  for the transaction it did create, if any), except a non-zero exit whose
  transaction is then stored as ACCEPTED or FINALIZED, which is logged as
  decided despite the exit and goes on,
- before a call: an undecided transaction to the contract in the log, an
  L2 hash in the log without a consensus tx id that is pending or succeeded
  on chain, or a chain that cannot be read to check either.
The pre-call checks read every consensus tx id and every such L2 hash in
the log, from this window and any earlier one appended to the same file.
Only FINALIZED and CANCELED are cached: any other decided status can be
appealed. ConsensusData has no view that lists a contract's queue, so a
transaction sent by anything other than this script is not seen.

"Sent" means the broadcast went through: send.py got past "broadcasting
..." to the wait for the L2 receipt. The L2 hash is computed before the
broadcast, so it is printed even when the node refuses the transaction.
tools/chain.py sends the same signed bytes again after a -32005 refusal or
after no answer at all (the gateway 522 of 24 September), and when it runs
out of attempts it looks the hash up: "not sent" means the node does not
know it. Such a call is run again in place after a pause, up to
REFUSED_RETRIES times, once every hash of its attempts is confirmed absent,
and with --nonce pinned to the first attempt's nonce, so that attempt
landing late makes the repeat fail instead of sending the call twice.

Everything send.py prints is appended to the log, between a header and a
footer that collect.py parses. PROBE_PK is passed to send.py in the
environment and is never written to the log. The status checks are
read-only and need no key.

Usage:
    export PROBE_PK=0x<64 hex chars>
    python3 experiments/llm-probe-2/run.py <ADDRESS> <LOG>
        [--start 1] [--batch 10] [--repeat 3] [--plain-rounds 1]
        [--network bradbury]
"""

import argparse
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import chainread

BODIES = HERE / "bodies"
SEND = HERE / "send.py"

FULL = "extract"
PLAIN = "extract_plain"

_TX = re.compile(r"^CONSENSUS TX : (0x[0-9a-fA-F]{64})", re.M)
_L2 = re.compile(r"^L2 TX HASH\s*: (0x[0-9a-fA-F]{64})", re.M)
_DECIDED = re.compile(r"^decided      : (\S+)", re.M)

# What tools/chain.py prints. The first once the broadcast was accepted.
# "not sent" once it has looked the hash up and the node does not know it;
# before tools/chain.py retried a refusal itself it printed the -32005
# refusal as "broadcast refused", which means the same. "outcome unknown"
# when the lookup got no answer either. Any other "broadcast refused" is a
# refusal that no retry will change: insufficient funds, a spent nonce.
_BROADCAST_DONE = re.compile(r"^(waiting for the L2 receipt|L2 status\s*:)", re.M)
_NOT_SENT = re.compile(r"^error: not sent:"
                       r"|^error: broadcast refused: .*(-32005|retry in)", re.M)
_OUTCOME_UNKNOWN = re.compile(r"^error: broadcast outcome unknown:", re.M)
_REFUSED = re.compile(r"^error: broadcast refused: (.*)$", re.M)
_REVERTED = re.compile(r"^error: the L2 transaction reverted", re.M)
_NONCE_MOVED = re.compile(r"^error: (nonce \d+ is (already used|ahead of the account).*)$",
                          re.M)
_NONCE = re.compile(r"^nonce\s*: (\d+)$", re.M)

OK = "ok"
NOT_SENT = "broadcast refused, not sent"

# Stored statuses that no later event changes. Every other decided status
# can be appealed and run again: on probe D, 0x94fe739d... went to
# LEADER_TIMEOUT, was appealed and is FINALIZED now, with previousStatus 13.
FINAL = ("FINALIZED", "CANCELED")

# The stored statuses that make a call whose send.py exited non-zero OK.
# UNDETERMINED, CANCELED and the timeouts still stop the window.
DECIDED_DESPITE_EXIT = ("ACCEPTED", "FINALIZED")

# A refused call is run again this many times, the pause growing by
# REFUSED_PAUSE_S each time, before the window stops.
REFUSED_RETRIES = 3
REFUSED_PAUSE_S = 30


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def body_files():
    return sorted(path for path in BODIES.iterdir()
                  if path.suffix in (".txt", ".json") and path.name != "expected.json")


def plan(repeat=3, plain_rounds=1):
    """(sequence number, round, method, body path) in the order they are sent."""
    methods = [FULL] * repeat + [PLAIN] * plain_rounds
    order = []
    for round_number, method in enumerate(methods, 1):
        for path in body_files():
            order.append((len(order) + 1, round_number, method, path))
    return order


def window(order, start, batch):
    """The calls a run sends: batch of them, from sequence number start."""
    return [entry for entry in order if start <= entry[0] < start + batch]


def header(sequence, round_number, method, path):
    return "=== run %d round %d method %s body %s start %s\n" % (
        sequence, round_number, method, path.name, now())


def footer(sequence, code):
    return "=== end %d exit %d at %s\n" % (sequence, code, now())


def logged_transactions(text):
    """Every consensus tx id a log records, in order, without repeats."""
    seen = []
    for tx_id in _TX.findall(text):
        if tx_id not in seen:
            seen.append(tx_id)
    return seen


def classify(output, code, stored=None):
    """(verdict, tx id or None) for one send.py run.

    From its output alone, unless stored, the stored status run.py read
    after the run, is given. OK for a clean exit whose transaction send.py
    saw decided, and for a non-zero exit whose transaction is stored as
    ACCEPTED or FINALIZED: on 24 September send.py died on a status number
    genlayer-py could not name while the transaction was already accepted.
    NOT_SENT for a broadcast the node refused, which the caller may retry.
    Every other verdict stops the window.
    """
    tx = _TX.search(output)
    tx_id = tx.group(1) if tx else None
    if chainread.PENDING_QUEUE_FULL in output:
        return "pending queue full (PendingQueueFull)", tx_id
    moved = _NONCE_MOVED.search(output)
    if moved and not tx_id:
        return moved.group(1), None
    if _L2.search(output) and not tx_id:
        if _NOT_SENT.search(output):
            return NOT_SENT, None
        if _OUTCOME_UNKNOWN.search(output):
            return "broadcast outcome unknown, the transaction may be on chain", None
        refused = _REFUSED.search(output)
        if refused:
            return "broadcast refused: %s" % (refused.group(1),), None
        if _REVERTED.search(output):
            return "the L2 transaction reverted; nothing reached consensus", None
        if _BROADCAST_DONE.search(output):
            return "sent on chain without a consensus tx id", None
    if code != 0:
        if tx_id and stored in DECIDED_DESPITE_EXIT:
            return OK, tx_id
        return "send.py exited %d" % (code,), tx_id
    decided = _DECIDED.search(output)
    if not tx_id or not decided:
        return "send.py exited 0 without a decided transaction", tx_id
    if decided.group(1) not in chainread.DECIDED:
        return "send.py reported %s, which is not decided" % (decided.group(1),), tx_id
    return OK, tx_id


def undecided(client, tx_ids, known):
    """The first tx id among tx_ids whose stored status is not decided.

    known caches the ids whose status is FINAL. Any other decided status is
    read again before every call, since an appeal can take it back.
    """
    for tx_id in tx_ids:
        if tx_id in known:
            continue
        status = chainread.stored_status(client, tx_id)
        if status not in chainread.DECIDED:
            return tx_id, status
        if status in FINAL:
            known.add(tx_id)
    return None


def unaccounted_l2(text):
    """Every L2 hash in a log whose send printed no consensus tx id after it.

    A send that died, was refused or was not sent, as far as send.py could
    tell. Each is looked up before every call: one that reached the chain
    after all would have made a consensus transaction the log does not know.
    """
    hashes = []
    for chunk in re.split(r"(?m)^(?=L2 TX HASH\s*:)", text):
        found = _L2.match(chunk)
        if found and not _TX.search(chunk) and found.group(1) not in hashes:
            hashes.append(found.group(1))
    return hashes


def l2_state(client, l2_hash):
    """"absent", "pending", "reverted" or "succeeded", read-only."""
    from web3.exceptions import TransactionNotFound

    try:
        transaction = chainread.retry(lambda: client.w3.eth.get_transaction(l2_hash),
                                      "eth_getTransactionByHash %s" % (l2_hash[:10],))
    except TransactionNotFound:
        return "absent"
    if transaction.get("blockNumber") is None:
        return "pending"
    receipt = chainread.retry(lambda: client.w3.eth.get_transaction_receipt(l2_hash),
                              "eth_getTransactionReceipt %s" % (l2_hash[:10],))
    return "succeeded" if receipt["status"] == 1 else "reverted"


def stray(client, l2_hashes, settled):
    """(hash, state) of the first unaccounted L2 hash that is not harmless.

    Absent is harmless for now and is looked up again next time. Reverted
    made nothing and is cached in settled. Pending or succeeded means a
    transaction the log has no consensus tx id for.
    """
    for l2_hash in l2_hashes:
        if l2_hash in settled:
            continue
        state = l2_state(client, l2_hash)
        if state == "reverted":
            settled.add(l2_hash)
        elif state != "absent":
            return l2_hash, state
    return None


def pre_call_check(client, text, known, settled):
    """Why the next call must not be sent, or None. Read-only."""
    try:
        pending = undecided(client, logged_transactions(text), known)
        if pending:
            return "transaction %s in the log is still %s" % pending
        loose = stray(client, unaccounted_l2(text), settled)
        if loose:
            return ("L2 transaction %s is %s, and the log has no consensus tx id for it"
                    % loose)
    except Exception as error:
        return "the pre-call check could not read the chain (%s: %s)" % (
            type(error).__name__, str(error)[:200])
    return None


def run_send(command, environment, log):
    """Run send.py, streaming its output into the log; (exit code, output)."""
    lines = []
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, env=environment,
                                   text=True)
    except OSError as error:
        message = "run.py could not start send.py: %s\n" % (error,)
        log.write(message)
        return -1, message
    for line in process.stdout:
        log.write(line)
        log.flush()
        lines.append(line)
    return process.wait(), "".join(lines)


def on_chain(client, l2_hash):
    """Whether the settlement chain knows an L2 transaction, read-only."""
    from web3.exceptions import TransactionNotFound

    try:
        chainread.retry(lambda: client.w3.eth.get_transaction(l2_hash),
                        "eth_getTransactionByHash %s" % (l2_hash[:10],))
    except TransactionNotFound:
        return False
    return True


def send_call(command, environment, log, client, sleep=None):
    """One call of the plan: (exit code, output, verdict, tx id).

    A refused broadcast is run again in place, only after the refused hash
    is confirmed absent from the chain. The verdict is that of the last
    attempt.
    """
    sleep = sleep or time.sleep
    attempt = 0
    hashes = []
    nonce = None
    repeat = list(command)
    while True:
        attempt += 1
        code, output = run_send(repeat, environment, log)
        verdict, tx_id = classify(output, code)
        if verdict != NOT_SENT:
            return code, output, verdict, tx_id
        hashes += [found for found in _L2.findall(output) if found not in hashes]
        # Every attempt's hash, not only the last: an earlier "not sent"
        # that reached the chain late would be this call sent twice.
        for l2_hash in hashes:
            try:
                present = on_chain(client, l2_hash)
            except Exception as error:
                return code, output, "could not check whether %s is on chain (%s)" % (
                    l2_hash, type(error).__name__), None
            if present:
                return code, output, "refused broadcast %s is on chain" % (l2_hash,), None
        if attempt > REFUSED_RETRIES:
            return code, output, "%s %d times" % (NOT_SENT, attempt), None
        # The repeat must use the first attempt's nonce: if that attempt
        # lands after all, the repeat is refused instead of sent twice.
        if nonce is None:
            used = _NONCE.search(output)
            nonce = used.group(1) if used else None
            if nonce is not None:
                repeat = list(command) + ["--nonce", nonce]
        pause = REFUSED_PAUSE_S * attempt
        message = ("run.py       : not sent, and %s not on chain; running the same call "
                   "again in %d s%s (retry %d of %d)"
                   % (", ".join(hashes) if hashes else "no hash", pause,
                      " with nonce %s" % (nonce,) if nonce is not None else "",
                      attempt, REFUSED_RETRIES))
        log.write(message + "\n")
        log.flush()
        print(message, flush=True)
        sleep(pause)


def stop(log, sequence, reason, next_start):
    message = "run.py       : STOPPED at call %d: %s" % (sequence, reason)
    hint = "resume with  : --start %d, once the cause is understood" % (next_start,)
    log.write(message + "\n" + hint + "\n")
    print(message)
    print(hint)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("address")
    parser.add_argument("log")
    parser.add_argument("--start", type=int, default=1,
                        help="sequence number of the first call to send (default 1)")
    parser.add_argument("--batch", type=int, default=10,
                        help="calls to send in this run (default 10)")
    parser.add_argument("--repeat", type=int, default=3,
                        help="rounds of extract in the plan (default 3)")
    parser.add_argument("--plain-rounds", type=int, default=1,
                        help="rounds of extract_plain after them (default 1)")
    parser.add_argument("--network", default="bradbury")
    args = parser.parse_args()
    if args.repeat < 0 or args.plain_rounds < 0 or args.repeat + args.plain_rounds < 1:
        parser.error("at least one round is needed and neither count can be negative")
    if args.batch < 1 or args.start < 1:
        parser.error("--start and --batch must be at least 1")

    order = plan(args.repeat, args.plain_rounds)
    calls = window(order, args.start, args.batch)
    if not calls:
        parser.error("--start %d is past the end of a %d call plan" % (args.start, len(order)))
    # Unbuffered, so send.py's stdout and stderr reach the log in order.
    environment = dict(os.environ, PYTHONUNBUFFERED="1")
    extra = ["--network", args.network]

    client, _ = chainread.connect_readonly(args.network)
    known = set()
    settled = set()
    log_path = Path(args.log)

    started = now()
    print("start        : %s" % (started,))
    print("window       : calls %d to %d of %d"
          % (calls[0][0], calls[-1][0], len(order)))
    sent = 0
    with log_path.open("a", encoding="utf-8") as log:
        log.write("=== probe d2 window calls %d-%d of %d on %s start %s\n"
                  % (calls[0][0], calls[-1][0], len(order), args.address, started))
        log.flush()
        for sequence, round_number, method, path in calls:
            blocked = pre_call_check(client, log_path.read_text(encoding="utf-8"),
                                     known, settled)
            if blocked:
                stop(log, sequence, blocked, sequence)
                break
            print("%3d/%d  %-13s %s" % (sequence, len(order), method, path.name),
                  flush=True)
            log.write(header(sequence, round_number, method, path))
            log.flush()
            flags = ["--plain"] if method == PLAIN else []
            code, output, verdict, tx_id = send_call(
                [sys.executable, str(SEND), args.address, str(path)] + flags + extra,
                environment, log, client)
            sent += 1
            if verdict != OK and tx_id:
                # Whatever went wrong, the transaction it created is waited
                # on, read-only, so the log ends on its stored status.
                log.write("run.py       : waiting for %s to be decided\n" % (tx_id,))
                log.flush()
                try:
                    stored = chainread.wait_decided(client, tx_id, log=log)
                except Exception as error:
                    stored = None
                    log.write("run.py       : the stored status could not be read (%s)\n"
                              % (type(error).__name__,))
                verdict, tx_id = classify(output, code, stored)
                if verdict == OK:
                    log.write("run.py       : decided despite send.py exit %d\n" % (code,))
            log.write("run.py       : verdict %s\n" % (verdict,))
            log.write(footer(sequence, code))
            log.flush()
            if verdict != OK:
                # A call with no consensus transaction is resumed at itself;
                # if its L2 transaction reached the chain after all, the
                # pre-call check stops that resume. On 24 September call 2
                # was not sent and the hint said --start 3.
                stop(log, sequence, verdict, sequence if tx_id is None else sequence + 1)
                break
        finished = now()
        log.write("=== probe d2 window end %s, %d sent\n" % (finished, sent))

    print("end          : %s" % (finished,))
    print("sent         : %d of %d in the window" % (sent, len(calls)))


if __name__ == "__main__":
    main()
