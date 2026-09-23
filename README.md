# Lacre

Lacre is signed evidence for Intelligent Contracts on GenLayer. An email that
a domain has DKIM-signed is already a statement that domain will stand behind:
the signature covers the headers, the public key is published in DNS, and
anyone can check it. Lacre puts that check inside a contract. Validators fetch
the signed headers and the sender's DNS key, verify the RSA signature
independently, and agree on a small record: the signing domain, the selector,
the body hash the signature claimed, a SHA-256 of the Message-ID, the key
size, the verdict and a reason. Other contracts and agents read that record.
No header value, address, subject or message body ever reaches calldata or
storage, so a shipping confirmation or a payment receipt can be used as
evidence on chain without publishing the message it came from.

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
the internal message path moves zero wei to a wallet and reports no error. The
first production contract is the Registry in `contracts/registry/`, which
holds the DKIM keys and the version pointers everything else resolves through.
It is live on Bradbury at `0xd9C6a6A0942490880BfF1405d8746AFC3e55d85e`, with
the amazon.com key registered and readable. See
[docs/registry.md](docs/registry.md),
[experiments/dkim-onchain-probe/README.md](experiments/dkim-onchain-probe/README.md)
and
[experiments/value-probe-2/README.md](experiments/value-probe-2/README.md).

Status: research probes plus a first production contract on a testnet.
