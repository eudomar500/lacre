#!/usr/bin/env python3
"""Check that what runs on chain is the source the repository says it is.

A contract is deployed as source, and the source travels in the deploy
transaction's calldata: the stored consensus transaction keeps it as
txCalldata, RLP [code, constructor calldata, leader_only]. This reads that
back from ConsensusData with a keyless client, hashes the code, and compares
it with what deployments.json recorded for the contract:

- address: the deploy transaction created the recorded address.
- recorded hash and size: source_sha256 and source_size.
- artifact at the commit: the file at source_path in the recorded commit.
- build at the commit: what build.py beside source_path produces from that
  commit's tree, when there is one.
- modules at the commit: every recorded lacre/ module hash against the file
  in that commit.

An entry written before deploy.py recorded these has no commit, or one set to
null where it is known to be unknown. Every check that needs a missing field
is listed as one that cannot be made, and the chain bytes are compared with
the current build instead: source_path when recorded, --source when given,
or contracts/<name>/<name>.py, or experiments/*/contracts/<name>.py.

Read-only: nothing is signed or sent and PROBE_PK is never read.

Exit status: 0 when every check that could be made matched, 1 on any
mismatch.

Usage:
    python3 tools/verify_deploy.py registry
    python3 tools/verify_deploy.py verifier --network bradbury
    python3 tools/verify_deploy.py 0x9821cfa5fe33a24f9d1D3Cca15885f1a2781EA1d
    python3 tools/verify_deploy.py verifier_v1 --source contracts/verifier/verifier.py
"""

import json
import sys
from pathlib import Path

import rlp

sys.path.insert(0, str(Path(__file__).resolve().parent))

import chain
import provenance
import txstate

ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENTS = ROOT / "deployments.json"

MATCH = "match"
MISMATCH = "MISMATCH"
CANNOT = "cannot check"


def resolve(deployments, network, target):
    """(name, entry) for a contract name or an address on network."""
    entries = deployments.get(network) or {}
    if target in entries:
        return target, entries[target]
    for name, entry in entries.items():
        if str(entry.get("address", "")).lower() == target.lower():
            return name, entry
    chain.die("%s is neither a contract name nor an address recorded for %s in %s"
              % (target, network, DEPLOYMENTS.name))


def stored_calldata(client, tx_id):
    """(recipient, txCalldata) of a stored consensus transaction.

    The stored view, not the timestamped one: getTransactionData reports an
    old transaction by the clock, and only the stored record is believed
    (see txstate).
    """
    abi = client.chain.consensus_data_contract["abi"]
    data = chain.resilient(
        lambda: txstate.consensus_data(client).functions.getTransactionAllData(tx_id).call(),
        "reading %s" % (tx_id,))
    transaction = dict(zip(txstate.fields(abi, "getTransactionAllData", 0), data[0]))
    return str(transaction["recipient"]), bytes(transaction["txCalldata"])


def deployed_code(calldata):
    """The contract source out of a deploy's txCalldata."""
    items = rlp.decode(calldata)
    if len(items) != 3:
        chain.die("the transaction is not a deploy: its data has %d fields, a deploy has 3"
                  % (len(items),))
    return bytes(items[0])


def guess_source(root, name):
    candidates = [root / "contracts" / name / ("%s.py" % (name,))]
    candidates += sorted(root.glob("experiments/*/contracts/%s.py" % (name,)))
    for candidate in candidates:
        if candidate.is_file():
            return candidate.relative_to(root).as_posix()
    return None


def compare(label, expected, actual, what):
    return (MATCH if expected == actual else MISMATCH, label, what)


def against_commit(root, entry, digest):
    """The checks against the recorded commit, or why they cannot be made."""
    commit = entry.get("commit")
    source_path = entry.get("source_path")
    if "commit" not in entry:
        return [(CANNOT, "commit", "no commit recorded for this entry")]
    if commit is None:
        return [(CANNOT, "commit", "the commit is recorded as unknown: %s"
                 % (entry.get("provenance") or "no reason given",))]
    if not source_path:
        return [(CANNOT, "commit", "commit %s is recorded without a source_path" % (commit,))]

    short = commit[:7]
    try:
        with provenance.tree_at(root, commit) as tree:
            results = []
            artifact = tree / source_path
            if artifact.is_file():
                results.append(compare("artifact at %s" % (short,), digest,
                                       provenance.sha256(artifact.read_bytes()), source_path))
            else:
                results.append((MISMATCH, "artifact at %s" % (short,),
                                "%s is not in that commit" % (source_path,)))
            built, _ = provenance.build_of(tree, source_path) if artifact.is_file() else (None, {})
            if built is None:
                results.append((CANNOT, "build at %s" % (short,),
                                "no build.py writes %s there" % (source_path,)))
            else:
                results.append(compare("build at %s" % (short,), digest,
                                       provenance.sha256(built), "build.py beside it"))
            recorded = entry.get("inlined_modules")
            if recorded is None:
                results.append((CANNOT, "modules at %s" % (short,), "no module hashes recorded"))
            for module, expected in sorted((recorded or {}).items()):
                path = tree / "lacre" / module
                actual = provenance.sha256(path.read_bytes()) if path.is_file() else "absent"
                results.append(compare("lacre/%s at %s" % (module, short), expected, actual,
                                       "recorded %s" % (expected[:16],)))
            return results
    except provenance.GitError as error:
        return [(MISMATCH, "commit", "commit %s cannot be read: %s" % (commit, error))]


def against_current(root, name, entry, digest, source_override):
    """Chain bytes against the build in the working tree."""
    source_path = source_override or entry.get("source_path")
    how = "given" if source_override else "recorded"
    if not source_path:
        source_path, how = guess_source(root, name), "assumed from the name"
    if not source_path or not (root / source_path).is_file():
        return [(CANNOT, "current build", "no source file for %s; pass --source" % (name,))]
    built, _ = provenance.build_of(root, source_path)
    if built is None:
        built, via = (root / source_path).read_bytes(), "the file itself, no build.py"
    else:
        via = "rebuilt by its build.py"
    return [compare("current build", digest, provenance.sha256(built),
                    "%s (%s), %s" % (source_path, how, via))]


def checks(root, name, entry, recipient, code, source_override=None):
    digest = provenance.sha256(code)
    results = [compare("address", str(entry.get("address", "")).lower(), recipient.lower(),
                       "the deploy transaction created %s" % (recipient,))]
    if "source_sha256" in entry:
        results.append(compare("recorded hash", entry["source_sha256"], digest,
                               "recorded %s" % (entry["source_sha256"],)))
    else:
        results.append((CANNOT, "recorded hash", "no source_sha256 recorded"))
    if "source_size" in entry:
        results.append(compare("recorded size", entry["source_size"], len(code),
                               "recorded %s bytes" % (entry["source_size"],)))
    else:
        results.append((CANNOT, "recorded size", "no source_size recorded"))
    results += against_commit(root, entry, digest)
    if not entry.get("commit"):
        results += against_current(root, name, entry, digest, source_override)
    return results


def main():
    network, arguments = chain.take_network(sys.argv[1:])
    source_override = None
    if "--source" in arguments:
        at = arguments.index("--source")
        if at + 1 >= len(arguments):
            chain.die("--source needs a path")
        source_override = provenance.relative(ROOT, arguments[at + 1])
        if source_override is None:
            chain.die("%s is not inside the repository" % (arguments[at + 1],))
        del arguments[at:at + 2]
    if len(arguments) != 1:
        print(__doc__)
        sys.exit(1)

    deployments = json.loads(DEPLOYMENTS.read_text())
    name, entry = resolve(deployments, network, arguments[0])
    if not entry.get("consensus_tx"):
        chain.die("%s has no consensus_tx recorded; there is no deploy to read" % (name,))

    client, net = txstate.connect_readonly(network)
    recipient, calldata = stored_calldata(client, entry["consensus_tx"])
    code = deployed_code(calldata)

    print("network      : %s (chain id %d)" % (network, net["chain_id"]))
    print("contract     : %s %s" % (name, entry.get("address")))
    print("consensus tx : %s" % (entry["consensus_tx"],))
    print("chain sha256 : %s" % (provenance.sha256(code),))
    print("chain size   : %d bytes" % (len(code),))
    if entry.get("commit"):
        print("commit       : %s" % (entry["commit"],))
    if entry.get("commit_dirty"):
        print("note         : the entry says the tree was dirty at deploy; the commit "
              "alone may not reproduce these bytes")
    if entry.get("provenance"):
        print("provenance   : %s" % (entry["provenance"],))
    print()

    results = checks(ROOT, name, entry, recipient, code, source_override)
    for status, label, what in results:
        print("%-13s %-30s %s" % (status, label, what))
    counts = {status: sum(1 for result in results if result[0] == status)
              for status in (MATCH, MISMATCH, CANNOT)}
    print("\nresult       : %d match, %d mismatch, %d cannot check"
          % (counts[MATCH], counts[MISMATCH], counts[CANNOT]))
    if counts[MISMATCH]:
        sys.exit(1)


if __name__ == "__main__":
    main()
