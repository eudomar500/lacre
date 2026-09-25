#!/usr/bin/env python3
"""Attest one DKIM signature through the Verifier and confirm the record.

This is the reference client for attest and attest_inline. It sends the
call, waits for consensus, and does not report success until the record is
read back from the Verifier and its requester is the sender. The rules it
follows are in docs/interfaces.md, section 5.

Usage:
    export PROBE_PK=0x<64 hex chars>
    python3 tools/attest.py (--url HTTPS_URL | --inline FILE) DOMAIN SELECTOR
        [--network bradbury] [--verifier ADDRESS] [--value WEI]
        [--until accepted|finalized] [--attempts N] [--log FILE]

--verifier defaults to the "verifier" entry of deployments.json for the
network. --value defaults to the Verifier's fee(). --until finalized, the
default, waits for the stored status FINALIZED or CANCELED and reads the
record in LATEST_FINAL state; --until accepted stops at the first decision
and reads it in LATEST_NONFINAL state, which is provisional: an ACCEPTED
transaction can still be appealed. --attempts (default 3) bounds how many
transactions one attestation may take. --log appends everything printed to
a file.

The protocol, one attempt at a time:
  a) send the call through tools/chain.py. A broadcast the node refused and
     does not know is sent again with the nonce of the first try pinned,
     only after every earlier try's L2 hash is confirmed absent from chain.
  b) wait for a decision on the stored status, through RPC failures and
     status numbers genlayer-py cannot name.
  c) with --until finalized, keep waiting for FINALIZED or CANCELED, up to
     FINAL_BOUND_S, with a progress line every PROGRESS_S.
  d) read the stored result and execution result, and the outcome.
  e) judge it: recorded, refused, not executed (send again), or stop.

The Verifier's return value, a record id or a reason, is on no field of the
consensus transaction: eqBlocksOutputs holds the output of the
non-deterministic block only, and attest_inline has none. So the outcome is
read from the Verifier itself. The record is the one at or after count()
before the first attempt whose requester, domain, selector, source and
fee_paid are this call's. A refusal writes nothing; with value attached it
leaves a refund message to the sender on the transaction, and its reason is
found by running the Verifier's own checks, read-only and in its order.

A transaction that finalizes with a result other than AGREE, such as
TIMEOUT, NO_MAJORITY or UNDETERMINED, wrote nothing, and on Bradbury the
protocol refunds its value to the sender at finalization; only L2 gas is
lost. Such an attestation is sent again as a new transaction. In the worst
case, a first transaction whose record was in fact written but could not be
read, that makes two records for one attestation. Consumers key on record
ids, not on attestation attempts, so both are valid records; the tool lists
every matching record it finds.

Exit codes:
  0  recorded: the record was read back and its requester is the sender
  1  usage or setup error, or nothing was sent
  2  refused by the Verifier (a reason); sending again would be refused too
  3  every attempt finalized without executing
  4  stopped: an outcome the tool cannot judge (undecided at the bound,
     CANCELED, an appeal in progress, a read failure, a send whose outcome
     is unknown). Nothing is sent again in that state; the consensus tx ids
     printed are where to resume by hand.

The private key is read only from PROBE_PK, by tools/chain.py, and is never
printed or logged.
"""

import argparse
import json
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import chain
import txstate
from genlayer_py.types import TransactionHashVariant

ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENTS = ROOT / "deployments.json"

EXIT_RECORDED = 0
EXIT_ERROR = 1
EXIT_REFUSED = 2
EXIT_NOT_EXECUTED = 3
EXIT_STOPPED = 4

RECORDED = "recorded"
REFUSED = "refused"
RESEND = "send again"
STOP = "stop"

# Limits of Verifier v1.1, contracts/verifier/verifier.py.
MAX_DOMAIN = 253
MAX_LABEL = 63
MAX_BLOB = 16384
MAX_URL = 512

# Bradbury has taken 20-25 minutes to accept, a queued transaction was
# activated after 80, and the appeal window follows acceptance; an appeal
# adds rounds on top.
FINAL_BOUND_S = 4 * 3600
FINAL_POLL_S = 30
PROGRESS_S = 300

# A broadcast that was not sent is tried again this many times, the pause
# growing by REFUSED_PAUSE_S each time, as experiments/llm-probe-2/run.py does.
REFUSED_RETRIES = 3
REFUSED_PAUSE_S = 30

# More new records than this since the first attempt is not a scan to run
# blind.
MAX_SCAN = 500

FINAL = TransactionHashVariant.LATEST_FINAL
NONFINAL = TransactionHashVariant.LATEST_NONFINAL


class Stop(Exception):
    """An outcome the tool cannot judge. Nothing is sent after one."""


class NothingSent(Exception):
    """This attempt failed before anything could reach the chain."""


def normalize(value, limit):
    """The Verifier's normalize(): trimmed, lowercased, outer dots removed."""
    text = str(value).strip().lower().strip(".")
    return text if len(text) <= limit else ""


def as_number(value):
    text = str(value).strip()
    return int(text) if text.isascii() and text.isdigit() else 0


def refusal(view, verifier, method, payload, domain, selector, value):
    """The reason the Verifier would refuse this call now, or None.

    The checks _attest runs before any work, in its order. view(address,
    method, args, variant) returns chain.UNKNOWN when a read fails, which
    stops the tool rather than guess.
    """
    def read(address, name, args, variant):
        answer = view(address, name, args, variant)
        if answer is chain.UNKNOWN:
            raise Stop("could not read %s() on %s" % (name, address))
        return answer

    if method == "attest":
        url = str(payload).strip()
        if not url.startswith("https://") or len(url) > MAX_URL:
            return "url not allowed"
    elif len(str(payload).encode("utf-8")) > MAX_BLOB:
        return "blob too large"
    if value < int(read(verifier, "fee", [], NONFINAL)):
        return "fee not paid"
    name, label = normalize(domain, MAX_DOMAIN), normalize(selector, MAX_LABEL)
    if not name or not label:
        return "bad domain or selector"
    registry = read(verifier, "registry", [], NONFINAL)
    # The Verifier reads the key at LATEST_FINAL, so this does too.
    key = read(registry, "get_key", [name, label], FINAL)
    try:
        modulus = int(key.get("n_hex", ""), 16) if key else 0
    except ValueError:
        modulus = 0
    if (not key or key.get("retired") or modulus <= 1
            or as_number(key.get("e", "")) <= 2):
        return "key not registered"
    return None


def ours(record, call):
    """Whether a record is one this call could have written."""
    return (bool(record)
            and str(record.get("requester", "")).lower() == call["sender"].lower()
            and record.get("domain") == normalize(call["domain"], MAX_DOMAIN)
            and record.get("selector") == normalize(call["selector"], MAX_LABEL)
            and record.get("source") == ("url" if call["method"] == "attest" else "inline")
            and str(record.get("fee_paid")) == str(call["value"]))


def locate(view, call, start, variant):
    """[(record id, record)] for every record from id start that matches call."""
    count = view(call["verifier"], "count", [], variant)
    if count is chain.UNKNOWN:
        raise Stop("could not read count() on the Verifier")
    count = int(count)
    if count - start > MAX_SCAN:
        raise Stop("%d records were written since the first attempt; not scanning them"
                   % (count - start,))
    found = []
    for index in range(start, count):
        record = view(call["verifier"], "get", [str(index)], variant)
        if record is chain.UNKNOWN:
            raise Stop("could not read record %d" % (index,))
        if ours(record, call):
            found.append((str(index), record))
    return found


def refunded(messages, call):
    """Whether the transaction pays the whole value back to the sender."""
    return call["value"] > 0 and any(
        message["recipient"].lower() == call["sender"].lower()
        and message["value"] == call["value"] for message in messages)


def outcome(view, messages, state, call, start):
    """What an executed call returned, as far as the chain shows it.

    {"records": [(id, record), ...], "reason": str or None}. Raises Stop
    when a read fails.
    """
    variant = FINAL if state["status"] == "FINALIZED" else NONFINAL
    records = locate(view, call, start, variant)
    if records:
        return {"records": records, "reason": None}
    # With a URL, the non-deterministic block runs only after every refusal
    # check has passed, so an output there rules a refusal out.
    if call["method"] == "attest" and txstate.eq_block_values(state["eq_outputs"]):
        return {"records": [], "reason": None}
    reason = refusal(view, call["verifier"], call["method"], call["payload"],
                     call["domain"], call["selector"], call["value"])
    if reason is None and refunded(messages(), call):
        reason = ("refused, with the value refunded; the reason is not stored on chain "
                  "and the Verifier's checks pass now")
    return {"records": [], "reason": reason}


def judge(state, until, found, sender):
    """(verdict, message) for one attempt.

    found is outcome()'s answer, or None when the call did not execute.
    """
    status = state["status"]
    if status == "CANCELED":
        return STOP, "the transaction was CANCELED"
    if status in txstate.APPEAL:
        return STOP, "an appeal is in progress (stored status %s)" % (status,)
    if until == "finalized" and status != "FINALIZED":
        return STOP, "not FINALIZED at the bound: the stored status is %s" % (status,)
    if until == "accepted" and status not in txstate.DECIDED:
        return STOP, "still undecided at the bound: the stored status is %s" % (status,)
    if not txstate.executed(state):
        if status == "FINALIZED":
            return RESEND, ("FINALIZED with result %s and execution %s: nothing was written. "
                            "The protocol refunds the value, %d wei, to the sender at "
                            "finalization; only L2 gas is lost"
                            % (state["result"], state["execution"], state["value"]))
        return STOP, ("decided %s with result %s but not final: it can still be appealed "
                      "and run, and its value is not refunded until it finalizes"
                      % (status, state["result"]))
    if found is None:
        return STOP, "the outcome of an executed call was not read"
    for record_id, record in found["records"]:
        if str(record.get("requester", "")).lower() == sender.lower():
            return RECORDED, "record %s, requester %s" % (record_id, record["requester"])
    if found["reason"] is not None:
        return REFUSED, "the Verifier refused the call: %s" % (found["reason"],)
    if status == "FINALIZED":
        return RESEND, ("the call executed and FINALIZED but no record it wrote can be read "
                        "at LATEST_FINAL")
    return STOP, "the call executed and is ACCEPTED but no record it wrote can be read yet"


def show_record(record_id, record):
    print("RECORD       : %s" % (record_id,))
    for key in record:
        print("  %-18s %s" % (key, record[key]))


class Session:
    """The chain side of the protocol, so the protocol can be tested without it."""

    def __init__(self, net, client, account, encoded, call, sleep=None):
        self.net = net
        self.client = client
        self.account = account
        self.encoded = encoded
        self.call = call
        self.sleep = sleep or time.sleep

    def view(self, address, method, args, variant):
        try:
            return chain.read(self.net, self.client, address, method, args, variant)
        except Exception as error:
            print("note         : %s() on %s failed (%s)" % (method, address,
                                                            type(error).__name__))
            return chain.UNKNOWN

    def messages(self, tx_id):
        return lambda: txstate.messages(self.client, tx_id, sleep=self.sleep)

    def start(self):
        count = self.view(self.call["verifier"], "count", [], FINAL)
        if count is chain.UNKNOWN:
            chain.die("could not read count() on the Verifier; nothing was sent")
        return int(count)

    def send(self):
        """One transaction: its consensus tx id.

        A broadcast that was not sent is repeated with the first try's nonce,
        and only after every earlier try's hash is confirmed absent.
        """
        try:
            gas = chain.estimate(self.net, self.client, self.account, self.encoded,
                                 final=False, value=self.call["value"])
        except SystemExit:
            raise NothingSent("the gas estimate failed")
        hashes = []
        nonce = None
        for tried in range(1, REFUSED_RETRIES + 2):
            for l2_hash in hashes:
                known = chain.l2_known(self.net, l2_hash, sleep=self.sleep)
                if known is None:
                    raise Stop("could not check whether %s is on chain" % (l2_hash,))
                if known:
                    raise Stop("the refused broadcast %s is on chain after all" % (l2_hash,))
            try:
                tx_id, _ = chain.send(self.net, self.client, self.account, self.encoded,
                                      gas, value=self.call["value"], nonce=nonce)
                return tx_id
            except chain.SendFailed as failure:
                if failure.kind == chain.REFUSED and not hashes:
                    raise NothingSent(failure.message)
                if failure.kind != chain.NOT_SENT:
                    raise Stop(failure.message)
                if failure.l2_hash and failure.l2_hash not in hashes:
                    hashes.append(failure.l2_hash)
                if nonce is None:
                    nonce = failure.nonce
            except SystemExit:
                raise Stop("the send failed after the broadcast; see the error above")
            if tried > REFUSED_RETRIES:
                break
            pause = REFUSED_PAUSE_S * tried
            print("retry        : not sent, and %s not on chain; sending again in %d s with "
                  "nonce %s (retry %d of %d)" % (", ".join(hashes) or "no hash", pause,
                                                 nonce, tried, REFUSED_RETRIES))
            self.sleep(pause)
        raise Stop("not sent %d times; %s were not on chain when last checked"
                   % (REFUSED_RETRIES + 1, ", ".join(hashes)))

    def wait(self, tx_id, until):
        """The stored state once the wait for until is over, reached or not."""
        try:
            txstate.wait_for_decision(self.client, tx_id, sleep=self.sleep)
        except RuntimeError as error:
            print("note         : %s" % (error,))
        if until == "finalized":
            print("waiting for FINALIZED (up to %d minutes) ..." % (FINAL_BOUND_S // 60,))
            return txstate.wait_stored(self.client, tx_id, statuses=txstate.FINAL,
                                       budget=FINAL_BOUND_S, interval=FINAL_POLL_S,
                                       progress=PROGRESS_S, sleep=self.sleep)
        return txstate.stored(self.client, tx_id, sleep=self.sleep)

    def outcome(self, state, tx_id, start):
        return outcome(self.view, self.messages(tx_id), state, self.call, start)


def show_state(state):
    print("status       : %s (previous %s)" % (state["status"], state["previous"]))
    print("result       : %s" % (state["result"],))
    print("execution    : %s" % (state["execution"],))
    print("rounds       : %d" % (state["rounds"],))
    print("value        : %d wei" % (state["value"],))
    for value in txstate.eq_block_values(state["eq_outputs"]):
        print("eq output    : %s" % (value,))


def summary(sent, explorer):
    for number, tx_id in enumerate(sent, 1):
        print("attempt %-5d: %s  %s/tx/%s" % (number, tx_id, explorer, tx_id))


def protocol(session, attempts, until, explorer):
    """Run the attestation to a verdict; the exit code."""
    start = session.start()
    print("records from : id %d (count() at LATEST_FINAL before the first attempt)" % (start,))
    sent = []
    for attempt in range(1, attempts + 1):
        print("\n--- attempt %d of %d ---" % (attempt, attempts))
        try:
            tx_id = session.send()
        except NothingSent as error:
            print("NOT SENT     : %s" % (error,))
            if not sent:
                return EXIT_ERROR
            summary(sent, explorer)
            return EXIT_STOPPED
        except Stop as error:
            print("STOPPED      : %s; nothing more is sent" % (error,))
            summary(sent, explorer)
            return EXIT_STOPPED
        sent.append(tx_id)
        print("CONSENSUS TX : %s" % (tx_id,))
        print("explorer     : %s/tx/%s" % (explorer, tx_id))
        try:
            state = session.wait(tx_id, until)
            show_state(state)
            found = None
            if txstate.executed(state) and (until == "accepted"
                                            or state["status"] == "FINALIZED"):
                found = session.outcome(state, tx_id, start)
        except Exception as error:
            print("STOPPED      : reading %s failed (%s: %s); nothing more is sent"
                  % (tx_id, type(error).__name__, str(error)[:200]))
            summary(sent, explorer)
            return EXIT_STOPPED
        verdict, message = judge(state, until, found, session.call["sender"])
        print("verdict      : %s: %s" % (verdict, message))
        if verdict == RECORDED:
            record_id, record = found["records"][0]
            show_record(record_id, record)
            if len(found["records"]) > 1:
                print("note         : %d records match this attestation: %s. Each is a "
                      "valid record; consumers key on record ids"
                      % (len(found["records"]), ", ".join(rid for rid, _ in found["records"])))
            if until == "accepted" and state["status"] != "FINALIZED":
                print("note         : provisional until FINALIZED; an ACCEPTED transaction "
                      "can still be appealed")
            summary(sent, explorer)
            return EXIT_RECORDED
        if verdict == REFUSED:
            print("not sent again: the same call would be refused the same way")
            summary(sent, explorer)
            return EXIT_REFUSED
        if verdict == STOP:
            print("STOPPED      : nothing more is sent; resume by hand from the tx ids below")
            summary(sent, explorer)
            return EXIT_STOPPED
        if attempt < attempts:
            print("sending the same attestation again as a new transaction")
    print("\nNOT EXECUTED : %d attempts, none executed" % (attempts,))
    summary(sent, explorer)
    return EXIT_NOT_EXECUTED


def verifier_address(network):
    try:
        entry = json.loads(DEPLOYMENTS.read_text())[network]["verifier"]
        return entry["address"]
    except (OSError, ValueError, KeyError, TypeError):
        chain.die("no verifier for %s in %s; pass --verifier" % (network, DEPLOYMENTS.name))


def log_to(path):
    """Copy everything printed from here on to path, appended."""
    handle = open(path, "a", encoding="utf-8")

    class Tee:
        def __init__(self, stream):
            self.stream = stream

        def write(self, text):
            self.stream.write(text)
            handle.write(text)
            handle.flush()
            return len(text)

        def flush(self):
            self.stream.flush()

    sys.stdout = Tee(sys.stdout)
    sys.stderr = Tee(sys.stderr)


def parse(argv):
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog="exit codes: 0 recorded, 1 error or nothing sent, 2 refused, "
               "3 attempts exhausted without executing, 4 stopped")
    parser.add_argument("domain")
    parser.add_argument("selector")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--url", help="HTTPS URL serving the signed headers")
    source.add_argument("--inline", metavar="FILE", help="file holding the signed headers")
    parser.add_argument("--network", default=chain.DEFAULT_NETWORK, choices=sorted(chain.NETWORKS))
    parser.add_argument("--verifier", help="Verifier address (default: deployments.json)")
    parser.add_argument("--value", type=int, help="wei to attach (default: fee())")
    parser.add_argument("--until", choices=("accepted", "finalized"), default="finalized")
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--log", metavar="FILE")
    args = parser.parse_args(argv)
    if args.attempts < 1:
        parser.error("--attempts must be at least 1")
    if args.value is not None and args.value < 0:
        parser.error("--value cannot be negative")
    return args


def main(argv=None):
    args = parse(sys.argv[1:] if argv is None else argv)
    if args.log:
        log_to(args.log)
    # The SDK calls requests without a timeout; a stalled connection has to
    # fail so a wait can resume.
    socket.setdefaulttimeout(txstate.SOCKET_TIMEOUT)

    if args.url is not None:
        method, payload = "attest", args.url
    else:
        try:
            payload = Path(args.inline).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            chain.die("cannot read %s: %s" % (args.inline, error))
        method = "attest_inline"
    verifier = args.verifier or verifier_address(args.network)

    account, client, net = chain.connect(args.network)
    call = {"verifier": verifier, "method": method, "payload": payload,
            "domain": args.domain, "selector": args.selector,
            "sender": account.address, "value": args.value}
    session = Session(net, client, account, None, call)
    if call["value"] is None:
        fee = session.view(verifier, "fee", [], NONFINAL)
        if fee is chain.UNKNOWN:
            chain.die("could not read fee() on the Verifier; pass --value")
        call["value"] = int(fee)

    print("network      : %s (chain id %d)" % (args.network, net["chain_id"]))
    print("verifier     : %s" % (verifier,))
    print("method       : %s" % (method,))
    print("source       : %s" % (payload if method == "attest"
                                 else "%s, %d bytes" % (args.inline,
                                                        len(payload.encode("utf-8"))),))
    print("domain       : %s" % (args.domain,))
    print("selector     : %s" % (args.selector,))
    print("sender       : %s" % (account.address,))
    print("value        : %d wei" % (call["value"],))
    print("until        : %s, up to %d attempts" % (args.until, args.attempts))

    try:
        reason = refusal(session.view, verifier, method, payload, args.domain,
                         args.selector, call["value"])
    except Stop as error:
        chain.die("%s; nothing was sent" % (error,))
    if reason is not None:
        print("REFUSED      : the Verifier would refuse this call now: %s; nothing was sent"
              % (reason,))
        sys.exit(EXIT_REFUSED)

    session.encoded = chain.write_calldata(client, account, verifier, method,
                                           [payload, args.domain, args.selector])
    sys.exit(protocol(session, args.attempts, args.until, net["explorer"]))


if __name__ == "__main__":
    main()
