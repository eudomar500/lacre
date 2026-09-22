# DKIM body probe (Testnet Bradbury feasibility experiment)

## What this measures

The header probe in `experiments/dkim-onchain-probe/` verifies an RSA
signature over a message's headers and stores the `bh=` tag exactly as the
signature claimed it, without ever recomputing it. That is a real limit: an
attestation from it says "these headers were signed by this domain", not "this
body is the one that was signed". This probe closes that gap from the other
side, and asks a narrower question:

**Can a Bradbury validator set agree that the body served at a URL is the body
a DKIM signature already committed to, and read structured fields out of it?**

There is no RSA here and there is no DNS lookup. The contract is handed a URL
and a `bh=` value, hashes what it fetches, compares, and then parses. Three
things have to hold:

1. **The hash survives the trip.** `bh=` is a SHA-256 over the body's octets
   after one canonicalization step, so a single byte rewritten anywhere
   between the mailbox and the validator changes it. The body is fetched as
   bytes and hashed as bytes; there is no text path, because decoding to a
   string and back is exactly the transformation that would break it.
2. **A 116 KB fetch is agreeable.** The header probe moved under 1 KB per
   attestation. This one moves the whole body to every validator, and
   consensus is still `gl.eq_principle.strict_eq` over one short canonical
   string, so the bytes are never compared, only the verdict derived from
   them. The open question is gas and wall time, not correctness.
3. **The extraction is stable enough to agree on.** Every validator runs the
   same regexes over the same decoded text part. A field that is present for
   one and absent for another is a consensus failure, not a soft result, so
   the patterns are conservative: an order id has to match one shape exactly,
   a weekday has to be one of seven words, and anything else is empty.

## What never leaves the machine that holds the message

The same privacy rule as the header probe, with one addition that matters
more: **the body carries the recipient's name and address, so it is more
sensitive than the headers, not less.**

- The contract's arguments are a URL and a base64 hash. Nothing else.
- The body behind the URL is read inside the non-deterministic block and
  discarded there.
- What leaves that block is a single pipe-separated string:
  `bh_claimed|bh_computed|match|body_bytes|order_id_found|eta_day|shipped|reason`.
- **The order id is matched and counted, never returned.** `order_id_found` is
  a boolean. The number itself does not reach the canonical string, calldata,
  storage or a log. Binding an attestation to a particular order needs a
  salted commitment, which is a product concern and deliberately not this
  probe's.
- `eta_day` is one of seven lowercase ASCII weekday words or empty. The
  template is Spanish, so accented characters are folded to ASCII before any
  pattern sees them and the canonical string stays ASCII.
- `make_body.py` prints a byte count and a hash. Nothing else.
- The tunnel that serves the body comes down as soon as the write is
  ACCEPTED. See `serve.md`.

## Layout

```
contracts/body_probe.py        built file, do not edit
scripts/contract_template.py   the contract, with a marker where body.py goes
scripts/build_contract.py      splices body.py in, prints the size, enforces the limit
scripts/bradbury.py            shared RPC, gas and receipt handling
scripts/deploy_bradbury.py     deploy
scripts/attest_bradbury.py     one attest_body write, then read the new record
scripts/read_bradbury.py       read a stored record
serve.md                       publishing the body for the length of one test
```

The hashing and extraction logic lives in `../dkim-probe/dkim/body.py` and
nowhere else. It is the same file `make_body.py` and the test suite use,
spliced into the contract at build time, so the deployed source cannot drift
from the tested source. Edit `body.py`; never edit `contracts/body_probe.py`.

`scripts/bradbury.py` is a verbatim copy of the header probe's file. It is
copied rather than imported so this directory stands on its own; if the RPC or
gas handling ever needs to change, change it there and copy it again.

## Build

```bash
cd experiments/dkim-body-probe
python3 scripts/build_contract.py
```

It prints the template size, the `body.py` size, the contract size and the
headroom, and exits non-zero if the result is non-ASCII, unparseable, missing
its runner header, or over 12 000 bytes.

`python3 scripts/build_contract.py --check` verifies the committed file is
current without writing it; use it after touching `body.py`.

Check the result before spending anything:

```bash
python3 -m pytest -q ../dkim-probe          # body.py against the sample
genvm-lint contracts/body_probe.py          # AST safety checks
export PROBE_PK=0x<64 hex chars>
python3 scripts/deploy_bradbury.py --estimate-only
```

`--estimate-only` builds the exact addTransaction calldata, calls
`eth_estimateGas` and stops. It sends nothing and needs no funds, so a
throwaway key is enough for it.

## Deploy

```bash
export PROBE_PK=0x<64 hex chars>
python3 scripts/deploy_bradbury.py
```

The key is read only from `PROBE_PK`, never from a file or an argument, and is
never printed. Fund the address the script prints at
https://testnet-faucet.genlayer.foundation if the balance is zero.

## Call

Cut the body and get its hash first, on the machine that holds the message:

```bash
cd ../dkim-probe
python3 make_body.py samples/amazon-shipped.eml
```

It prints the byte count and the simple canonicalized body hash. That hash
must equal the `bh=` tag of the signature you are attesting against; if it
does not, stop, because the contract will only record the mismatch you already
know about. Publish the file as `serve.md` describes, then:

```bash
cd ../dkim-body-probe
python3 scripts/attest_bradbury.py <CONTRACT_ADDRESS> <BODY_URL> <BH_CLAIMED>
```

It prints the L2 hash, waits for the L2 receipt, waits for ACCEPTED, prints
the receipt status, the execution result, the gas used and the wall time, and
then reads back the record it created. **Tear the tunnel down the moment that
returns.**

A body that does not match is a result, not a failure: the record is stored
with `match=false` and a reason, and the transaction does not revert. The
write only fails on a malformed URL, an empty `bh_claimed`, or consensus
itself.

```bash
python3 scripts/read_bradbury.py <CONTRACT_ADDRESS> 0
python3 scripts/read_bradbury.py <CONTRACT_ADDRESS> all
genlayer receipt <CONSENSUS_TX> --stderr
```

## Results

Run of 2026-09-22 on Testnet Bradbury, GenVM v0.2.11, contract source 10 979
bytes. One deploy and one attestation, against the reference message whose
amazon.com signature carries `c=relaxed/simple` and no `l=` tag.

| network | contract | deploy tx | gas used deploy | attest tx | gas used attest | body bytes | bh match | order_id_found | eta_day | shipped | wall time to ACCEPTED | notes |
|---------|----------|-----------|-----------------|-----------|-----------------|------------|----------|----------------|---------|---------|-----------------------|-------|
| bradbury | `0x36d56F13Ee6A13b530B6bd44fBF510f4837f7E6f` | `0x54c516b59484e4735a95fb1c23fc2e1e1106b01257ff9ddbff70a935837a8861` | 8 933 381 | `0xc41a6361ad1aecf3352ad66193c6cff0d6a034b0ba2e32101e1c23881490b482` | 919 471 | 116 564 | true | true | miercoles | true | 12 s | record 0. Body served over HTTPS through a cloudflared quick tunnel. `body hash matches bh=`, 5 of 5 AGREE, FINALIZED pending at the time of writing |

`bh_claimed` and `bh_computed` are both
`s++GIS95947DFm6Pyd1o2v947XK/Et+PaGMB12Y4cL0=`, which is the `bh=` tag of the
amazon.com signature over that message, recomputed from bytes the validators
fetched themselves.

Deploy detail: L2 tx
`0xd4d121fa4e88dd720ad59f683dc1bce9377198609681a6749726b0a1c0f03e07`,
estimated 9 508 981 gas and used 8 933 381 for 0.0189 GEN. The 3x rule clamped
to the 2^24 cap, so it was signed at 1.76x the estimate. Consensus in 23 s
with 5 of 5 AGREE; FINALIZED 30 minutes after submission.

Attest detail: estimated 963 601 gas and used 919 471, about 5.5 percent of
the 2^24 per-transaction cap.

## Findings

1. **A body binds to a hash a signature already committed to, with no RSA on
   chain.** The contract carries SHA-256, one canonicalization step, a
   quoted-printable decoder and five regexes. It never touches a modulus and
   never asks DNS for a key, because the `bh=` it is handed was already
   covered by the header signature the other probe verifies. That splits
   cleanly: header verification and body verification can live in separate
   contracts, deployed and called independently, linked only by the `bh`
   string that appears in both records. A consumer that trusts both records
   for the same `bh` has the whole chain, from the signing domain to the
   fields, without either contract knowing about the other.
2. **A 116 KB body costs about what a signature verification costs.** The
   attestation used 919 471 gas for a fetch, a hash over 116 564 bytes, a MIME
   walk and five regexes. The header probe's best comparable used 866 250 for
   two web calls and a 1024 bit modular exponentiation over roughly 810 bytes.
   About 0.92 M against 0.87 M, both near 5 percent of the cap. Gas on this
   network is not paid by the byte fetched, so body size is not the constraint
   it looks like from the outside.
3. **No size cap was hit at 116 KB.** Every validator received the full
   116 564 bytes, so whatever limit the web module enforces is above that. The
   truncation guard, which compares the fetched length with `Content-Length`,
   did not fire and stays in as the detector for the day a limit does bind:
   a short read hashes to a perfectly well formed digest of the wrong thing.
4. **Extraction agreed across all five validators.** The first `text/plain`
   part was found by its boundary, decoded from quoted-printable and parsed
   identically on every node, and `strict_eq` accepted the canonical string
   5 of 5. The one thing that makes this work is folding accents to ASCII
   before any pattern runs: the weekday in the message carries an acute accent
   on its second vowel, and the stored value is the ASCII `miercoles`, so the
   canonical string every validator returns is ASCII. A field that is present
   for one validator and absent for another is a consensus failure rather than
   a soft result, so the patterns stay narrow and an unrecognized value is
   recorded as empty.

## Known before running

- **Deploy gas is comfortable here; the attestation was the open question.**
  At 10 979 bytes the deploy estimated 9 508 981 gas and used 8 933 381, well
  inside the ceiling the header probe found binding at roughly 20 KB of
  source. The attestation moves 116 KB per validator rather than 810 bytes,
  which is why it was worth measuring; it came back at 919 471 gas, close
  enough to the header probe's 866 250 that body size is not a planning
  concern on this network.
- **`gl.nondet.web.get` returns bytes, and that is load-bearing.** The pinned
  runner declares `Response(status: int, headers: dict[str, bytes], body:
  bytes | None)`, and `body` is the response payload untouched. Record 0
  confirms it end to end: a SHA-256 over the fetched octets reproduced the
  `bh=` the sender computed when it signed the message, which the local probe
  had already reproduced from the .eml the same day, and which no transcoding
  path could have survived. There is no encoding question to settle and no
  text fallback in the contract. If a future runner ever returns text, the
  right answer is to stop, not to guess a codec.
- **A truncated body would otherwise hash plausibly.** A size-capped or
  interrupted transfer produces a perfectly well formed SHA-256 of the wrong
  thing, and the only evidence is the length. The contract compares the
  fetched length with `Content-Length` when the header is present and records
  `body truncated: got N of M` rather than a hash mismatch, because the two
  failures want different fixes. A missing or unparseable `Content-Length` is
  treated as absent: the guard must never fire on a header it failed to read.
  It did not fire on record 0, so the path is untested on chain and stays in
  for the day a response limit does bind.
- **Only simple body canonicalization is carried.** Every signature this probe
  targets is `c=relaxed/simple`, and `l=` is absent, so the whole body is
  covered. A `c=.../relaxed` signature, or one with an `l=` tag that signs a
  prefix, will be recorded as `match=false`; that is a wrong answer for a
  right reason and a second canonicalization would be the fix.
- **The extraction patterns are this sender's template, not a standard.**
  `order_id` is three digits, a dash, seven digits, a dash, seven digits.
  `eta_day` is the word after "llega el", kept only when it is one of seven
  weekdays. `shipped` is a shipping phrase in the past tense. A different
  sender needs different patterns, and a wrong pattern shows up as an empty
  field rather than as a wrong value.
- **Validators do not fetch plain HTTP, a raw IP, or a non standard port.**
  Measured by the header probe, records 0 and 1: the URL is rejected inside
  the validator with `NondetException` before a request is issued. HTTPS on a
  domain name works. `serve.md` documents the route.
- **A contract cannot be read before it is FINALIZED.** The first attest after
  a deploy will fail its pre-read of `count()` and print the raw `gen_call`
  response. That is expected; the write goes ahead regardless.
- **Bradbury is not always slow, but plan for it.** This run saw 23 s to
  ACCEPTED on the deploy and 12 s on the attestation, with FINALIZED reached
  30 minutes after the deploy was submitted. The header probe saw 13 to 27
  seconds; an earlier probe on the same network saw 20 to 25 minutes per
  write. The scripts poll for 40 minutes because the slow case is the one that
  costs you the transaction, and here it also costs you a tunnel left standing
  over personal data.

## Status

The table above is the record this probe was built to produce, so the
directory stays. The contract is a feasibility probe on a testnet, not
something to build on: it stores every attestation without access control, its
record ids are sequential, nothing rate limits `attest_body`, and an
attestation proves only that some party served bytes matching a hash, not that
the party serving them was entitled to. Treat
`../dkim-probe/dkim/body.py` as the reusable part; everything around it exists
to measure one question.

What it leaves open for a product rather than a probe: binding a record to a
particular order without publishing the order id, which needs a salted
commitment; a second body canonicalization for `c=.../relaxed` signers; and an
extraction layer that is not one sender's template.
