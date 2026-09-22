# DKIM on-chain probe (Testnet Bradbury feasibility experiment)

## What this measures

The local probe in `experiments/dkim-probe/` already showed that a DKIM header
signature can be verified in pure Python, with no third party crypto, in about
one millisecond. It answered a question about arithmetic. This one answers a
question about GenLayer:

**Can a Bradbury validator set reach consensus on whether an email's DKIM
signature is valid, without ever seeing the email?**

Three separate things have to hold for the answer to be yes, and each of them
shows up as a distinct failure here:

1. **The verifier fits.** Bradbury caps a transaction at 2^24 gas, and a
   deploy costs roughly 850 gas per byte of contract source, comments
   included. `rfc6376.py` is 15.6 KB before the contract around it, so only a
   subset can go on chain. The build prints the size and refuses over 19 000
   bytes; a deploy that estimates above the cap is refused by the node before
   it is even signed.
2. **The validators can reach the data.** Two web calls per attestation: the
   blob, and `dns.google` for the selector's TXT record. The tracking probe in
   `genlayer-p2p-arena` found three of four carrier sites answering 403 or 418
   to a validator. DNS over HTTPS is a very different kind of endpoint, but it
   is still a fetch from inside the non-deterministic block.
3. **They agree.** Consensus is `gl.eq_principle.strict_eq` over one
   canonical string. The leader and each validator independently fetch the
   blob, fetch the key, verify the signature and build the same seven fields;
   the pinned SDK then compares the two return values for exact equality, same
   type and same string byte for byte, with no normalization. Nothing about
   the raw bytes is compared, so a differing TTL or a reordered header in the
   DoH JSON cannot break agreement; a genuinely different verdict can, and
   should.

The interesting outcome is not "it verified". It is the wall time to
FINALIZED, the gas, and whether the validators agreed.

## What never leaves the machine that holds the message

The privacy rule this probe is built around: **no header value, email address,
subject or message id ever reaches calldata, contract storage, a tracked file
or a log.**

- The contract's only argument is a URL.
- The blob behind it is one DKIM-Signature plus the headers that signature
  covers. It is read inside the non-deterministic block and discarded there.
- What leaves that block is a single pipe-separated string:
  `domain|selector|bh|sha256(message_id)|key_bits|valid|reason`. The
  Message-ID is present only as a SHA-256 hex digest, which is enough to prove
  two attestations are about the same message and not enough to read it.
- Nothing is printed. An exception is recorded by class name only, never by
  message, because an exception's text can echo the blob URL.
- `make_blob.py` prints a byte count and nothing else.

## Layout

```
contracts/dkim_probe.py        built file, do not edit
scripts/contract_template.py   the contract, with a marker where core.py goes
scripts/build_contract.py      splices core.py in, prints the size, enforces the limit
scripts/bradbury.py            shared RPC, gas and receipt handling
scripts/deploy_bradbury.py     deploy
scripts/attest_bradbury.py     one attest write, then read the new record
scripts/read_bradbury.py       read a stored record
serve.md                       publishing the blob for the length of one test
```

The verification logic lives in `../dkim-probe/dkim/core.py` and nowhere else.
It is the same file the off-chain probe and the test suite use, spliced into
the contract at build time, so the deployed source cannot drift from the
tested source. Edit `core.py`; never edit `contracts/dkim_probe.py`.

## Build

```bash
cd experiments/dkim-onchain-probe
python3 scripts/build_contract.py
```

It prints the template size, the core size, the contract size and the
headroom, and exits non-zero if the result is non-ASCII, unparseable, missing
its runner header, or over 19 000 bytes.

`python3 scripts/build_contract.py --check` verifies the committed file is
current without writing it; use it after touching `core.py`.

Check the result before spending anything:

```bash
python3 -m pytest -q ../dkim-probe          # core.py against the reference
genvm-lint contracts/dkim_probe.py          # AST safety checks
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

Every transaction is signed at three times the estimate, clamped to the
2^24 cap, and the L2 hash is printed before anything is awaited, so a
transaction that reverts can still be traced. At the current 14 649 byte
source the estimate is 73.4% of the cap, so the clamp binds and the deploy is
signed at 1.36x its estimate rather than 3x. That was enough: the deploy used
11 580 459 gas, well inside its own limit. Gas here is dominated by calldata
rather than by nested calls, which is why a thin margin survives. If a larger
contract ever does not, shorten the comments in `core.py` or the template and
rebuild; do not raise the limit.

## Call

Publish the blob first: see `serve.md`. Then, with the URL it gave you:

```bash
python3 scripts/attest_bradbury.py <CONTRACT_ADDRESS> <BLOB_URL>
```

It prints the L2 hash, waits for the L2 receipt, waits for ACCEPTED, prints
the receipt status, the execution result, the gas used and the wall time, and
then reads back the record it created. Tear the blob down as soon as that
returns; `serve.md` has the cleanup commands.

An invalid signature is a result, not a failure: the record is stored with
`valid=false` and a reason, and the transaction does not revert. The write
only fails on a malformed URL or on consensus itself.

```bash
python3 scripts/read_bradbury.py <CONTRACT_ADDRESS> 0
python3 scripts/read_bradbury.py <CONTRACT_ADDRESS> all
genlayer receipt <CONSENSUS_TX> --stderr
```

For FINALIZED rather than ACCEPTED, watch the transaction on
https://explorer-bradbury.genlayer.com and record when it flips.

## Results

Run of 2026-09-22 on Testnet Bradbury, GenVM v0.2.11, contract source 14 649
bytes. One deploy and three attestations against the same contract.

| network | contract | deploy tx | gas used deploy | attest tx | gas used attest | key bits | valid | wall time to FINALIZED | notes |
|---------|----------|-----------|-----------------|-----------|-----------------|----------|-------|------------------------|-------|
| bradbury | `0x6fD7FA3D49aBDC2CeB3686e4BE392CAdb595980c` | `0x41aad33ba35e006aa663d3c0db57d91ea3fcd2548ecb98cd95e66d6cc87837fc` | 11 580 459 | `0x096423aa39724441101bf4a765bb6ec757ea9185d46edf8c4f5347fb8dabf37d` | 860 457 | - | false | not timed | record 0. Plain HTTP to a raw IP on port 8765, truncated path. `blob fetch failed: NondetException` |
| bradbury | as above | as above | as above | `0x86f2aab7564eccaf6089f0b6dc74460551acd1ccf3c97ced1e7ae11bcb58b6da` | 843 465 | - | false | 13 s to ACCEPTED, not timed to FINALIZED | record 1. Same URL, correct path; an external `curl` got the full 810 byte blob. Same `NondetException` |
| bradbury | as above | as above | as above | `0x3719d430c6625fc94075837fbe3577fa9a744faf7b2c5f7a02e72a06a277f61a` | 866 250 | 1024 | true | 27 s to ACCEPTED, not timed to FINALIZED | record 2. Same blob over HTTPS through a cloudflared quick tunnel. `header signature verified`, d=amazon.com, 5 of 5 AGREE |

Deploy detail: L2 tx
`0xc6e26f618889764c4bcea78f15c1ed184bcf19e7d50301e319fc5c8350d75bd5`,
estimated 12 308 025 gas and used 11 580 459 for 0.0244 GEN. The 3x rule
clamped to the 2^24 cap, so it was signed at 1.36x the estimate. Consensus in
13 s with 5 of 5 AGREE; FINALIZED 30 minutes after submission.

## Findings

1. **Validators do not fetch plain HTTP, a raw IP, or a non standard port.**
   Records 0 and 1 both failed with `blob fetch failed: NondetException`.
   Record 0's path was truncated and would have drawn a 404 from the server;
   it produced the same reason as record 1, whose path was correct and served
   the full blob to an external `curl`. The URL is therefore rejected inside
   the validator before a request is issued, so the failure says nothing about
   the host. HTTPS on a domain name works: the identical blob verified through
   a cloudflared quick tunnel on `trycloudflare.com`. `serve.md` now documents
   that route first.
2. **An attestation costs about 0.9 M gas and settles in 13 to 27 seconds.**
   The three writes used 860 457, 843 465 and 866 250 gas, roughly 5 percent
   of the 2^24 per-transaction cap, and the successful one reached ACCEPTED in
   27 s. Two web calls and a 1024 bit modular exponentiation are cheap; the
   deploy, at 11 580 459 gas, is two orders of magnitude more expensive and is
   the only part that comes close to the cap.
3. **A failure is a record, not a rollback.** Every failed fetch stored a row
   with `valid=false` and a reason, and the validators agreed on it: 5 of 5
   AGREE on the failure rows as well as on the success. A blocked or missing
   blob therefore cannot stall a caller waiting on an attestation, and the
   reason string is specific enough to tell a network refusal from a bad
   signature.
4. **Key size is worth storing.** The signature that verified was 1024 bit
   RSA, from a large sender in 2026. A consumer of these attestations needs
   the modulus size to decide how much the signature is worth, so `key_bits`
   is part of the stored record rather than an implementation detail.
5. **Runtime facts confirmed on the pinned runner.** `hashlib`, `base64` and
   `re` all import; the SHA-256 implementation is present, so the path that
   would have stored `probe failed:` never fired. `gen_call` on this node
   answers with `{data, status, logs, metrics}` while genlayer-py 0.16.3
   expects `result` to be a bare hex string, so the read scripts decode the
   `data` field themselves. A freshly deployed contract cannot be read until
   it is FINALIZED, which is why the first attest reports an unknown record
   count and goes ahead with the write anyway.

## Known before running

- **Deploy gas is the binding constraint, not contract size.** Measured on
  2026-09-22: 14 649 bytes of source estimated at 12 308 025 gas, 73.4% of the
  2^24 cap, and used 11 580 459. The L2 also refuses contract code over about
  52 700 bytes with `BlockPubdataLimitReached`, but the gas cap binds first,
  at roughly 20 KB.
- **Only relaxed header canonicalization is carried on chain.** Every signer
  this probe targets publishes `c=relaxed/...`; a `c=simple/...` signature is
  recorded as `valid=false` with `unsupported header canonicalization` rather
  than silently failing the RSA check.
- **Only the header signature is checked.** The body hash `bh=` is stored as
  the signature claims it, and is never recomputed, because the body never
  leaves the machine that holds the message. An attestation therefore says
  "these headers were signed by this domain", not "this body is intact". Body
  coverage would need the body on chain, which the privacy rule forbids.
- **`hashlib` is required, and its absence would be a recorded result.**
  `core.py` imports `hashlib` at module level and has no fallback. The run
  above confirmed it imports and that SHA-256 is available, so this path was
  never exercised on chain. Had the module shipped without SHA-256 behind it,
  the call would raise inside the non-deterministic block, `attest_once` would
  catch it and store `valid=false, probe failed: <ExceptionClass>`, and the
  transaction would not revert. The one case that cannot be absorbed is the
  `hashlib` module being absent altogether, which fails at contract load and
  so shows up at deploy, before any record exists.
- **Bradbury is not always slow, but plan for it.** An earlier tracking probe
  on the same network saw leader timeouts or idleness strikes on every
  transaction, 20 to 25 minutes per write. This run saw none: consensus in 13
  to 27 s, with FINALIZED reached 30 minutes after the deploy was submitted.
  The scripts poll for 40 minutes because the slow case is still the one that
  costs you the transaction.
- **A contract cannot be read before it is FINALIZED.** The first attest after
  a deploy will fail its pre-read of `count()` and print the raw `gen_call`
  response. That is expected; the write goes ahead regardless.

## Status

The table above is the record this probe was built to produce, so the
directory stays. The contract is a feasibility probe on a testnet, not
something to build on: it stores every attestation without access control, its
record ids are sequential, and nothing rate limits `attest`. Treat
`experiments/dkim-probe/dkim/core.py` as the reusable part; everything around
it exists to measure one question.
