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

What is in the repository today is the evidence that this works, not a library
to build on. `experiments/dkim-probe/` is the off-chain probe: a pure Python
RFC 6376 verifier with no third party crypto, its test suite, and a tool that
cuts the minimum blob a signature can be checked from. Next to it,
`experiments/dkim-onchain-probe/` holds the same verifier reduced to fit a
GenLayer contract, with the build, deploy and call tooling, and the results
measured on Testnet Bradbury: a 14 649 byte contract deployed for 11 580 459
gas, an attestation costing about 0.9 M gas and reaching consensus in 13 to 27
seconds with 5 of 5 validators agreeing, and a live 1024 bit RSA signature
from a large sender verified on chain. It also records what does not work:
validators refuse a plain HTTP URL to a raw IP before the request leaves the
node. A second probe, `experiments/dkim-body-probe/`, binds the body served at
a URL to the body hash the same signature already committed to and extracts
fields from it with no RSA on chain: a 116 KB body was hashed, matched and
parsed on chain for about 0.9 M gas with 5 of 5 validators agreeing. See
[experiments/dkim-probe/README.md](experiments/dkim-probe/README.md)
and
[experiments/dkim-onchain-probe/README.md](experiments/dkim-onchain-probe/README.md).

Status: research probes on a testnet, not a product.
