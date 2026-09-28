#!/usr/bin/env python3
"""Extract fields from a signed body through an Extractor and confirm the record.

This is the reference client for extract. It follows the confirmation
protocol of tools/attest.py, whose functions it runs: send, wait for a
decision and for FINALIZED on the stored status, and report success only once
the record is read back from the Extractor and its requester is the sender.
The rules are in docs/interfaces.md, section 5, and the Extractor's own in
docs/extractor.md.

The Extractor and the Verifier are both resolved through the Router at
LATEST_FINAL, which is how the Extractor finds the Verifier on every call;
the Extractor must name the same Router in router(). Before anything is sent,
the checks the Extractor runs first are run here, read-only and in its
order: the fee, the Verifier record (it has to exist, be valid and aligned,
and carry a body canonicalization of simple or relaxed), a patterns document
for the record's domain, and the URL. A call that would be refused is not
sent.

There are two lanes, each its own contract behind its own Router name:
--lane patterns (the default) calls the pattern Extractor, resolve("extractor"),
and --lane llm the LLM Extractor, resolve("extractor_llm"), which reads
senders that have no patterns (docs/llmextractor.md). The LLM Extractor
takes any sender domain, so the patterns check is skipped for it; everything
else, the protocol and the exit codes included, is the same for both.

The outcome is read from the Extractor's views: records_of(sender) and
last_refusal(sender) before the first attempt and after each one. The record
is an id records_of lists afterwards that it did not list then, whose
record_id and fee_paid are this call's. A record with match false is a
record, and exits 0: the validators agreed the body served at the URL is not
the signed one, or could not be read, and the fee is kept.

Usage:
    export PROBE_PK=0x<64 hex chars>
    python3 tools/extract.py RECORD_ID --url HTTPS_URL
        [--lane patterns|llm] [--network bradbury] [--router ADDRESS] [--value WEI]
        [--until accepted|finalized] [--attempts N] [--log FILE]

RECORD_ID is the id of a Verifier record, on the Verifier the Router
resolves now. The options are the ones tools/attest.py takes and mean the
same.

Exit codes, as tools/attest.py:
  0  recorded: the record was read back and its requester is the sender
  1  usage or setup error, or nothing was sent
  2  refused by the Extractor (a reason); sending again would be refused too
  3  every attempt finalized without executing
  4  stopped: an outcome the tool cannot judge; nothing is sent again

The private key is read only from PROBE_PK, by tools/chain.py, and is never
printed or logged.
"""

import argparse
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import attest
import chain
import txstate
from attest import FINAL, NONFINAL, Stop, must_read

# Limits of contracts/extractor/extractor.py, shared by
# contracts/llmextractor/llmextractor.py.
MAX_URL = 512
CANONS = ("simple", "relaxed")
# The Router name of each lane's contract.
LANES = {"patterns": "extractor", "llm": "extractor_llm"}


def refusal(view, extractor, verifier, record_id, url, value, lane="patterns"):
    """The reason the Extractor would refuse this call now, or None.

    The checks extract runs before any work, in its order. verifier is what
    the Router resolves "verifier" to, "" when it resolves nothing. The llm
    lane has no patterns and refuses no domain.
    """
    if value < int(must_read(view, extractor, "fee", [], NONFINAL)):
        return "fee not paid"
    if not verifier:
        return "router resolves no verifier"
    # The Extractor reads the Verifier at LATEST_FINAL, so this does too.
    record = must_read(view, verifier, "get", [str(record_id).strip()], FINAL)
    if not isinstance(record, dict):
        return "verifier unreadable"
    if not record:
        return "record not found"
    if record.get("valid") is not True:
        return "record not valid"
    if record.get("aligned") is not True:
        return "record not aligned"
    if record.get("body_canon") not in CANONS:
        return "body canonicalization not supported"
    if lane == "patterns" and not must_read(view, extractor, "patterns",
                                             [str(record.get("domain", ""))], NONFINAL):
        return "no patterns for domain"
    url = str(url).strip()
    if not url.startswith("https://") or len(url) > MAX_URL:
        return "url not allowed"
    return None


def ours(record, call):
    """Whether an Extractor record is one this call could have written."""
    return (bool(record)
            and str(record.get("requester", "")).lower() == call["sender"].lower()
            and record.get("record_id") == str(call["record_id"]).strip()
            and str(record.get("fee_paid")) == str(call["value"]))


class Session(attest.Session):
    """attest.Session with the Extractor's record view and matching rule.

    call["verifier"] holds the Extractor's address: it is the contract whose
    records_of and last_refusal the protocol reads.
    """

    def outcome(self, state, tx_id, before):
        return attest.outcome(self.view, self.messages(tx_id), state, self.call, before,
                              getter="get_record", matches=ours, contract="Extractor")


def resolve(view, router, name="extractor"):
    """(extractor, verifier) as the Router resolves them at LATEST_FINAL.

    name is the lane's Router name, "extractor" or "extractor_llm".

    An Extractor that resolves its Verifier through another Router would be
    checked against the wrong Verifier here, so that stops the tool.
    """
    extractor = str(must_read(view, router, "resolve", [name], FINAL))
    if not extractor:
        raise Stop("the Router %s resolves no %s" % (router, name))
    named = str(must_read(view, extractor, "router", [], FINAL))
    if named.lower() != str(router).lower():
        raise Stop("the Extractor %s resolves its Verifier through the Router %s, not %s"
                   % (extractor, named, router))
    verifier = str(must_read(view, router, "resolve", ["verifier"], FINAL))
    return extractor, verifier


def parse(argv):
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog="exit codes: 0 recorded, 1 error or nothing sent, 2 refused, "
               "3 attempts exhausted without executing, 4 stopped")
    parser.add_argument("record_id", help="id of a Verifier record")
    parser.add_argument("--url", required=True, help="HTTPS URL serving the message body")
    parser.add_argument("--lane", choices=sorted(LANES), default="patterns",
                        help="patterns (resolve extractor) or llm (resolve extractor_llm)")
    parser.add_argument("--network", default=chain.DEFAULT_NETWORK, choices=sorted(chain.NETWORKS))
    parser.add_argument("--router", help="Router address (default: deployments.json)")
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
        attest.log_to(args.log)
    socket.setdefaulttimeout(txstate.SOCKET_TIMEOUT)
    router = args.router or attest.router_address(args.network)

    account, client, net = chain.connect(args.network)
    call = {"verifier": None, "record_id": args.record_id, "sender": account.address,
            "value": args.value}
    session = Session(net, client, account, None, call)
    try:
        extractor, verifier = resolve(session.view, router, LANES[args.lane])
    except Stop as error:
        chain.die("%s; nothing was sent" % (error,))
    call["verifier"] = extractor
    if call["value"] is None:
        fee = session.view(extractor, "fee", [], NONFINAL)
        if fee is chain.UNKNOWN:
            chain.die("could not read fee() on the Extractor; pass --value")
        call["value"] = int(fee)

    print("network      : %s (chain id %d)" % (args.network, net["chain_id"]))
    print("router       : %s" % (router,))
    print("lane         : %s" % (args.lane,))
    print("extractor    : %s (resolve(\"%s\") at LATEST_FINAL)" % (extractor, LANES[args.lane]))
    print("verifier     : %s (resolve(\"verifier\") at LATEST_FINAL)" % (verifier or "none",))
    print("record_id    : %s" % (args.record_id,))
    print("body url     : %s" % (args.url,))
    print("sender       : %s" % (account.address,))
    print("value        : %d wei" % (call["value"],))
    print("until        : %s, up to %d attempts" % (args.until, args.attempts))

    try:
        reason = refusal(session.view, extractor, verifier, args.record_id, args.url,
                         call["value"], args.lane)
    except Stop as error:
        chain.die("%s; nothing was sent" % (error,))
    if reason is not None:
        print("REFUSED      : the Extractor would refuse this call now: %s; nothing was sent"
              % (reason,))
        sys.exit(attest.EXIT_REFUSED)

    session.encoded = chain.write_calldata(client, account, extractor, "extract",
                                           [args.record_id, args.url])
    sys.exit(attest.protocol(session, args.attempts, args.until, net["explorer"]))


if __name__ == "__main__":
    main()
