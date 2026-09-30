# Use the contracts directly

Lacre is a set of contracts on Testnet Bradbury that anyone can call from a
wallet or read from another contract. The gateway is one client of them, not
a requirement. This page is the path without it: how to find each contract,
how to attest and extract from your own wallet, and how a contract of yours
reads the results. The full interface is in [interfaces.md](interfaces.md).

> **The proof rule.** An attestation or an extraction exists only as a
> record read from its contract at `LATEST_FINAL`. A transaction status, the
> explorer's return value or an `eqBlocksOutputs` reading is not proof: a
> transaction can finalize and write nothing. Decide on the record, and read
> a missing record as "nothing happened", whatever the transaction shows.
> ([interfaces.md](interfaces.md), section 5, rule 10.)

## The one address

The Router is the only address to remember:

    0xEf37cb72C3A9dD6bCE2f3575B75c94C555F9c8d9   (Bradbury, chain id 4221)

Every other contract is found through it, by name:

| name | contract | read with |
|------|----------|-----------|
| `verifier` | Verifier v1.2, DKIM signature to record | `resolve("verifier")` |
| `keycache` | KeyCache, the DKIM keys and their state | `resolve("keycache")` |
| `extractor` | Extractor v1, the patterns lane | `resolve("extractor")` |
| `extractor_llm` | LLM Extractor v1, the model lane | `resolve("extractor_llm")` |

`resolve(name)` returns the current address, or `""` for a name it does not
hold. A change of address is announced by `pending(name)` 48 hours before it
takes effect. A consumer that has reviewed one version and wants to stay on
it reads `resolve_pinned(name, label)` instead: labels are `v1.2` for the
Verifier and `v1` for the other three, and a label never moves. Resolve
again rather than caching an address: that is how a replacement behind the
Router is followed without a new deployment of your own. See
[router.md](router.md).

From a shell, with no key:

```bash
python3 tools/read.py 0xEf37cb72C3A9dD6bCE2f3575B75c94C555F9c8d9 resolve verifier
```

## Attest from your own wallet: attest_inline

`attest_inline(headers_blob, domain, selector)` on the Verifier, payable. You
send the signed headers in the call itself, pay `fee()` in GEN (in wei, read
it first; it is 0 on v1.2 today), and nothing leaves your machine except the
transaction.

**The headers blob** is one DKIM-Signature field plus exactly the header
fields its `h=` tag lists, in the message's own order, CRLF line endings, as
UTF-8 text of at most 16 384 bytes. The Verifier picks the first
DKIM-Signature whose `d=` and `s=` equal the domain and selector you pass,
and hashes the fields `signed_data` in [lacre/dkimcore.py](../lacre/dkimcore.py)
selects: for each name in `h=`, the lowest unused instance of that name in
the blob, so a repeated name is taken bottom up. The blob therefore has to
hold the same instances the signer covered, and no more of any signed name
than `h=` lists, or the record is `valid` false with `duplicate signed
header`. Nothing else in the message is needed, the body included.

[tools/headers_blob.py](../tools/headers_blob.py) cuts that blob from an
.eml with the same functions:

```bash
python3 tools/headers_blob.py samples/message.eml amazon.com yg4mwqurec7fkhzutopddd3ytuaqrvuz > /tmp/blob.txt
python3 tools/headers_blob.py samples/message.eml amazon.com --digest
```

Keep messages in a gitignored directory such as `samples/`; the tool refuses
a file inside the repository that git would track. `--digest` prints the
blob's length and SHA-256 and nothing of the message.

Then send it, with the reference client, which runs the confirmation
protocol for you:

```bash
export PROBE_PK=0x<64 hex chars>
python3 tools/attest.py --inline /tmp/blob.txt amazon.com yg4mwqurec7fkhzutopddd3ytuaqrvuz
```

What the caller has to know:

- **The calldata is public and permanent.** Every header in the blob, To and
  Subject included, can be read by anyone, forever. In exchange anyone can
  re-check the signature from the calldata without trusting the validators.
- **Only an active key attests.** The KeyCache must hold the domain and
  selector in state `active` (`key_status(domain, selector)`); a new key is
  registered with `register_key` and becomes usable through `confirm_key`
  24 hours later. See [keycache.md](keycache.md).
- **About 35 minutes to FINALIZED.** Acceptance takes about a minute on a
  healthy network; finalization follows the appeal window. The first record
  on v1.2 was submitted at 23:12:18 and FINALIZED at 23:45:01. Nothing is
  final before that, and a front end that shows a result earlier shows it as
  provisional.
- **One call at a time per contract.** A second transaction to the same
  contract is queued until the first is decided, and the queue holds 20.
  Send the next call after the previous one is decided (rule 13).
- **The record is the proof.** The return value of a write cannot be read
  from the chain. Read `records_of(your address)` before and after: the new
  id is your record, and `get(id)` is the attestation. `tools/attest.py`
  does exactly this and exits 0 only when the record is read back at
  `LATEST_FINAL` with you as its requester.
- **Refusals refund.** A call the Verifier refuses before doing the work
  (fee, names, key state, blob size, an `l=` signature) stores nothing,
  records the reason in `last_refusal(your address)` and hands the whole
  value back by external message when the transaction FINALIZES. A record
  with `valid` false is not a refusal: it is paid for and kept.

## Attest from a URL you host: attest

`attest(headers_url, domain, selector)` takes the same blob served at an
`https://` URL on a domain name (a raw IP or plain HTTP is refused by the
validators before a request leaves them), at most 512 characters, answering
`text/plain`. Every validator fetches it and they must agree. Only the URL
goes into calldata, but the URL is public from the moment the transaction is
sent, so anyone can fetch the blob while it is served. Serve it until the
transaction is FINALIZED, then delete it; after that nobody can re-check the
signature, and what remains is the record. A quick way to serve it is in
[experiments/dkim-onchain-probe/serve.md](../experiments/dkim-onchain-probe/serve.md).

```bash
python3 tools/attest.py --url https://example.org/r4nd0m/blob.txt amazon.com yg4mwqurec7fkhzutopddd3ytuaqrvuz
```

Everything in the list above applies, except the calldata note.

## Extract from the body: extract

The Verifier checks headers only. What the body says comes from an
Extractor, `extract(record_id, body_url)`, payable, on either lane:
`resolve("extractor")` for senders with a patterns document (amazon.com
today), `resolve("extractor_llm")` for any sender. `record_id` is a record on
the Verifier the Router resolves now, and it must be `valid` and `aligned`.

The body is the raw octets after the first empty line of the message,
unchanged: it is hashed as received, and one transcoded byte changes the
hash. [experiments/dkim-probe/make_body.py](../experiments/dkim-probe/make_body.py)
cuts it and prints the byte count and body hash, so you can compare with the
record's `bh` before spending anything. Serve it at an `https://` URL, at
most 262 144 bytes, until the transaction is FINALIZED, or hand it to the
gateway, which hosts it for the length of the call. Then:

```bash
python3 tools/extract.py 0 --url https://example.org/r4nd0m/body.bin --lane patterns
```

The same four rules hold: about 35 minutes, one call at a time per
Extractor, the record is the proof (`records_of`, then `get_record`), and
refusals refund. A body that does not hash to `bh` is a record with `match`
false, paid for. A usable reading is `match` true with `reason` `extracted`.
See [extractor.md](extractor.md) and [llmextractor.md](llmextractor.md).

## Read the results from a contract

[integrations/consumer_example.py](../integrations/consumer_example.py) is a
minimal contract to copy. It keeps the Router address and nothing else,
resolves the Verifier and the Extractors on every use, and reads them at
`StorageType.LATEST_FINAL` only:

- `require_attestation(record_id, domain, min_key_bits)` is the Verifier's
  `check_for`: valid, aligned, that domain, at least that key size.
- `require_shipped(record_id, lane)` is true when the lane (`patterns` or
  `llm`) holds an extraction of that record, against the current Verifier,
  with `match` true, `reason` `extracted` and `shipped` true. The Extractors
  index records by requester, so it looks among the newest 32 extractions of
  the wallet that made the attestation.
- `mark_delivered(record_id, lane)` stores the Verifier and record id once
  both pass, and refuses a second record of the same signed message.

What a copy has to decide for itself: which requester it accepts (the
example accepts any; `requester` proves only who paid), and, if it releases
goods or money, reading `key_status` on the KeyCache at decision time and
requiring `active` (rule 8). `tests/consumer_stub_run.py` drives it against
a stubbed SDK.

## Direct wallet or gateway

| | your wallet, `attest_inline` | your wallet, `attest` | gateway |
|---|---|---|---|
| who pays | you, `fee()` in GEN plus gas | you, `fee()` in GEN plus gas | you pay the gateway in credits; its wallet pays GEN and gas |
| what leaves your machine | the signed headers, into public calldata for good | the signed headers, to your host and to anyone who fetches the URL while served | the headers, and the body for extraction, to the gateway |
| what you must host | nothing | the blob, and the body for extraction, at `https://` until FINALIZED | nothing |
| requester on the record | your address | your address | the gateway's wallet |
| what you must run | the confirmation protocol, or `tools/attest.py` | the same, plus the server | nothing; you read the record |

Whichever path wrote it, a record reads the same, and the proof rule above
decides for all three.
