# Lacre

Lacre is signed evidence for Intelligent Contracts on GenLayer. An email that
a domain has DKIM-signed is already a statement that domain will stand behind:
the signature covers the headers, the public key is published in DNS, and
anyone can check it. Lacre puts that check inside a contract. Validators read
the signed headers, take the sender's key from the KeyCache, where it was
recorded from DNS by validator consensus, verify the RSA signature
independently, and agree on a small record: the signing domain, the selector,
the body hash the signature claimed, a SHA-256 of the Message-ID, the key
size, the verdict and a reason. Other contracts and agents read that record.
No message body reaches calldata or storage, and storage holds only the
record: no address, To or Subject, and of the From header only its domain.
Calldata is public: `attest_inline` puts every header in the blob in calldata
permanently, and `attest` puts the blob's URL there, so anyone can fetch the
headers while they are served. The Verifier checks the headers only; the
Extractor checks a body against the `bh` of a Verifier record and reads a few
fields out of it. See [docs/interfaces.md](docs/interfaces.md), sections 6
and 10.

The repository holds three things. The DKIM probes are the evidence that the
check itself works. `experiments/dkim-probe/` is the off-chain verifier: pure
Python RFC 6376, no third party crypto, with its test suite and a tool that
cuts the minimum blob a signature can be checked from. Next to it,
`experiments/dkim-onchain-probe/` is the same verifier reduced to fit a
contract, with the numbers measured on Testnet Bradbury: a 14 649 byte
contract deployed for 11 580 459 gas, an attestation costing about 0.9 M gas
and reaching consensus in 13 to 27 seconds with 5 of 5 validators agreeing,
and a live 1024 bit RSA signature from a large sender verified on chain. It
also records what does not work: validators refuse a plain HTTP URL to a raw
IP before the request leaves the node. A third, `experiments/dkim-body-probe/`,
binds the body served at a URL to the body hash the same signature already
committed to and parses fields out of it with no RSA on chain. The value
probes, `experiments/value-probe/` and `experiments/value-probe-2/`, answer
whether a contract can be paid in GEN and pay out again: it can, as long as
the payout uses the external message path and settles on finalization, because
the internal message path moves zero wei to a wallet and reports no error.

The production layer on Bradbury was redeployed on 2026-09-26. Its public
address is the Router in `contracts/router/`, at
`0xEf37cb72C3A9dD6bCE2f3575B75c94C555F9c8d9`, which resolves `verifier`,
`keycache` and `extractor` to the current contracts and puts a 48 hour delay
on any later change. The KeyCache in `contracts/keycache/`, at
`0x2b2e13E4aFAAD1AFE1247085D01c56Aeb425e251`, holds the DKIM keys and makes
each new one wait out a 24 hour quarantine before it can be used; the
amazon.com key was registered there on 2026-09-26 and has been active since
`confirm_key` on 2026-09-27. Verifier v1.2 in `contracts/verifier/`, at
`0x50fc4fD7183c9e0C8Bb2ABD21E55581cE16F59ed`, turns a DKIM signature into the
record described above, reads its keys from the KeyCache through the Router,
and only attests against an active key. The pattern Extractor in
`contracts/extractor/`, at `0x35bcC4867301c35A27BE44Fb7d3C53862e8464E5`,
deployed on 2026-09-28 and resolved by the Router as `extractor`, takes a
Verifier record and the URL of the message body, checks the body against the
record's `bh`, and stores what the sender's patterns read in it: whether it
shipped, the weekday it arrives, a date when the text carries one, and
whether an order number is present, never the number itself. See
[docs/extractor.md](docs/extractor.md). A second lane for senders with no
patterns, the LLM Extractor in `contracts/llmextractor/`, has each
validator's model read the same body through the prompt probe D2 measured;
it is built and tested and not deployed. See
[docs/llmextractor.md](docs/llmextractor.md).

The previous versions stay live. Registry v1, at
`0x1E1380B71F1C9c622C432B6FD6fa56097B1E4Ddc`, holds the amazon.com key and
still points at Verifier v1.1, at
`0x9821cfa5fe33a24f9d1D3Cca15885f1a2781EA1d`, where refused calls were
measured to answer and refund in full at finalization. Registry v0, at
`0xd9C6a6A0942490880BfF1405d8746AFC3e55d85e`, is retired and nothing points
at it. Verifier v1, at `0x74AfE3a7E6D2601bdC9BCC6265d8314F1a74807a`, is
retired because it reverted on an underpaid call, and a reverting call on
this chain keeps the value it carried. Every address and deploy transaction
is in [docs/interfaces.md](docs/interfaces.md), section 2. See also
[docs/router.md](docs/router.md), [docs/keycache.md](docs/keycache.md),
[docs/verifier.md](docs/verifier.md), [docs/registry.md](docs/registry.md),
[experiments/dkim-onchain-probe/README.md](experiments/dkim-onchain-probe/README.md)
and
[experiments/value-probe-2/README.md](experiments/value-probe-2/README.md).

The interface of every layer, for integrators and reviewers, is in [docs/interfaces.md](docs/interfaces.md).

## Tools

`tools/` holds the production scripts: `deploy.py`, `call.py`, `read.py`,
which needs no key, and `attest.py`, the reference client for the Verifier.
`attest.py` finds Verifier v1.2 and the KeyCache through the Router, does not
send a call for a key that is not active, and confirms the outcome through
the Verifier's `records_of` and `last_refusal` views. It exits 0 only once
the attesting transaction is FINALIZED with an
AGREE result and FINISHED_WITH_RETURN, and the record has been read back at
`LATEST_FINAL` with the sender as its requester. A refusal is reported with
its reason and not sent again. A transaction that finalized without
executing, whose value the protocol refunds, is sent again as a new one, up
to `--attempts`; anything it cannot judge, such as an appeal in progress or
a failed read, stops it with the consensus tx id and nothing more is sent.
Each outcome has its own exit code, listed in the script. The rules it
follows are in [docs/interfaces.md](docs/interfaces.md), section 5.

Status: research probes plus the Router, the KeyCache, the Verifier and the
Extractor on a testnet, with the previous Registry and Verifier still live
beside them. The amazon.com key is active on the KeyCache, and Verifier v1.2
holds its first record, written on 2026-09-27 and finalized. The Extractor is
deployed with the amazon.com patterns set, and holds its first record that
matched a signed body, record 2, written against that Verifier record on
2026-09-28 and finalized; records 0 and 1 before it are charged records of a
body URL that answered 404.
