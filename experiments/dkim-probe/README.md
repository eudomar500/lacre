# dkim-probe

A local DKIM verifier written the way a GenLayer Intelligent Contract has to be
written: pure Python over ints, bytes and hashlib, no ssl, no native crypto, and
every network call behind one function. The point of the probe is to find out,
before any contract work starts, whether a real message from a real sender
verifies under those restrictions and what it costs.

## What it measures

For one DKIM-Signature on one message:

- which header fields the signature covers, in the order the `h=` tag lists them
- whether an `l=` tag is present (a partial body signature is not worth trusting)
- the key size and public exponent published in DNS
- whether the header signature verifies under RSA PKCS#1 v1.5 with SHA-256
- whether the body hash matches `bh=`, and which line ending convention was
  needed to get there: `as-is` for a downloaded `.eml`, `crlf` for a body that
  has been through a client that rewrote CRLF to LF
- wall time for the RSA verification and for the body hash, separately, because
  in a contract these land in different places: the header check is cheap and
  deterministic, the body hash scales with message size
- that a one byte change to the body and a one byte change to the Subject are
  both rejected

The report never contains the message body, and no header value other than the
DKIM-Signature tags.

## Layout

    dkim/rfc6376.py   verification core, standard library only, no network
    dkim/dns_doh.py   the only module that opens a socket
    probe.py          CLI and report
    tests/            pytest suite, runs offline

`rfc6376.py` never imports `dns_doh.py`. That split is the one that matters for
the port: the key fetch becomes a `web.get` under an equivalence principle and
everything else stays deterministic.

The two entry points mirror the future contract methods:

    verify_headers(raw_headers_bytes, selector, domain, pubkey_n, pubkey_e) -> dict
    body_hash(raw_body_bytes, line_ending_mode="as-is") -> str

They are independent. `verify_headers` never touches the body, so a contract can
accept the headers and the `bh=` claim in one transaction and the body in
another, or not at all.

## Running it

    python3 -m venv .venv && . .venv/bin/activate
    pip install -r requirements.txt

    python probe.py samples/amazon-shipped.eml --domain amazon.com
    python -m pytest -q

`--selector` picks a specific `s=` when a domain signs with more than one.
`--timeout` bounds the DNS over HTTPS lookup. `--crosscheck` runs dkimpy as a
second opinion if it happens to be installed; it is not a requirement and the
core never imports it.

Exit codes: 0 for PASS, 1 for a message that failed to verify, 2 for a setup
problem such as no matching signature or an unreachable resolver.

The test suite generates its own RSA key pair, so it passes with no network and
with no sample message present. The two live tests skip themselves instead.

## Results

| message | domain | selector | key bits | body bytes | line endings | bh match | header sig | rsa ms | body hash ms | result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
|  |  |  |  |  |  |  |  |  |  |  |
|  |  |  |  |  |  |  |  |  |  |  |
|  |  |  |  |  |  |  |  |  |  |  |

## Notes on the RFC

- Section 3.7 says the DKIM-Signature field is hashed with the `b=` value and
  the whitespace around it deleted, and without a trailing CRLF. Both are easy
  to get almost right and produce a signature that fails for no visible reason.
- Section 5.4.2 orders duplicate field names from the bottom of the header block
  upward. A name in `h=` with no matching field is not an error; signers list
  extra names on purpose so that adding such a field breaks the signature.
- `simple` body canonicalization turns an empty body into a single CRLF;
  `relaxed` turns it into nothing at all. The two published SHA-256 constants in
  sections 3.4.3 and 3.4.4 differ for that reason.
