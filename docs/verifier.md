# Verifier

The Verifier is the contract that turns a DKIM signature into a record other
contracts can read. It is handed the signed headers, either as a URL the
validators fetch or inline in the call, with a domain and a selector. The RSA
signature is verified independently and what is stored is one small record:
the body hash the signature claimed, how the body was canonicalized, a digest
of the Message-ID, the From domain and whether it aligns with the signer, the
key it was checked against, a verdict and a reason.

It resolves keys through the [Registry](registry.md) and never reads DNS
itself.

## What a record contains

| field | meaning |
|-------|---------|
| `domain` | the signing domain, lowercased, as the call named it |
| `selector` | the selector, lowercased |
| `bh` | the body hash the signature committed to, base64, as published |
| `body_canon` | the body canonicalization from the signature's `c=` tag |
| `message_id_sha256` | SHA-256 of the Message-ID, hex, empty if there was none |
| `key_bits` | the modulus size of the Registry's key |
| `key_sha256` | SHA-256 of the DER the domain published, from the Registry |
| `valid` | true only if the header signature verified and every rule below passed |
| `reason` | why, in a fixed phrase; see the list below |
| `from_domain` | the domain part of the signed From address, lowercased; empty if it could not be read unambiguously |
| `aligned` | true when `d=` and `from_domain` are equal or one is a subdomain of the other; see [Alignment](#alignment) |
| `signed_at` | the signature's `t=` tag as an integer, 0 when absent or malformed |
| `source` | `url` or `inline`, the method that wrote the record |
| `requester` | the address that sent the attestation transaction; it paid `fee_paid`, which is 0 while the fee is 0 |
| `attested_at` | the runner's transaction datetime, stored unmodified |
| `fee_paid` | the value that rode on the call, in wei |

`get(id) -> dict` returns that record with its `id`, or `{}` for an id that
was never written. `requester` comes back as a hex string. `count() -> int` is
how many records exist; ids are sequential and are strings, starting at
`"0"`, which is why the tools take them with the `str:` prefix that keeps a
digit a string.

The From address itself is never stored, only its domain part.

## What a record does not contain

On the `attest` path, no header value, address, subject, Message-ID or message
body reaches calldata, storage or a log. The call carries a URL, a domain and
a selector. The URL itself is public calldata, so anyone reading the chain can
fetch the headers behind it while they are served. The blob behind the URL is
read inside the non-deterministic block and discarded there, and the only thing that leaves that block is the
canonical string
`bh|body_canon|sha256(message_id)|valid|reason|from_domain|aligned|signed_at`.

`attest_inline` is the exception, by design: the blob is the call's argument,
so every signed header, To and Subject included, is in calldata permanently.
See [attest_inline](#attest_inline) for when that is the right trade.

The Message-ID is present as a SHA-256 digest and nothing else, not enough to
read it. It ties two attestations to the same message only when the signature
covers Message-ID, which the record does not say; an unsigned Message-ID is
whatever the blob carries. See [interfaces.md](interfaces.md), section 4.7.
An exception is recorded by its class name only, never by its text, because an
exception's text can echo the URL.

The consequence worth stating plainly: a record proves that some message
signed by that domain, with that body hash, verified, and when `aligned` is
true, that its From domain is that domain or related to it as a subdomain. It does not say what the message was, and it cannot be used to
recover it.

## What body_canon is for

A DKIM signature covers the headers, and one of those headers carries `bh`,
the hash of the canonicalized body. The `c=` tag is `header/body`: `c=
relaxed/simple` means the headers were canonicalized relaxed and the body
simple, and per RFC 6376 the body half defaults to `simple` when the tag, or
the slash inside it, is absent.

So `bh` alone does not let a later contract check a body. It has to
canonicalize that body the same way the signer did first, and `body_canon` is
the only place that choice is recorded once the blob is gone. The Extractor
reads it, canonicalizes the served body accordingly, hashes it and compares
with `bh`. Without it the Extractor would have to guess between two modes that
produce different hashes for the same bytes.

`body_canon` is empty when the signature could not be parsed at all, which is
the same condition that leaves `bh` empty.

## How a consumer reads a record

From another contract, at the Verifier address stored together with the
record id, never re-resolved through the Registry for a decision: ids start
at `"0"` on every Verifier, and the Registry pointer can move. See rules 1
and 4 in [interfaces.md](interfaces.md#5-rules-for-integrators).

```python
# VERIFIER is the address stored with record_id when the attestation was made.
verifier = gl.get_contract_at(Address(VERIFIER)).view(state=StorageType.LATEST_FINAL)

if verifier.check_for(record_id, "amazon.com", 1024, requester.as_hex):
    record = verifier.get(record_id)
    # record["bh"], record["body_canon"], record["message_id_sha256"] ...
```

```
check_for(id: str, domain: str, min_key_bits: int, requester: str) -> bool
```

`check_for` is the whole question in one call, and the only consumer check
the contract offers. It is true only if:

- the record exists,
- `valid` is true,
- `aligned` is true,
- the domain matches after lowercasing,
- `key_bits` is at least `min_key_bits`,
- `requester` is the address that sent the attestation transaction,
  compared as an address, so the spelling (checksum case, lower case) does
  not matter.

The requester test is what stops a record from being replayed by anyone
else: a record someone else requested says nothing about the caller in front
of the consumer. It does not stop anyone holding a copy of the same headers
from attesting them as their own requester. A malformed `requester` returns
false rather than raising,
so a consumer never has to guard the call.
A consumer that reads `get()` and compares the fields itself will sooner or
later forget one of them, which is what this method exists to prevent.

Views are `LATEST_NON_FINAL` by default. Pass
`state=StorageType.LATEST_FINAL` for a decision that cannot be replayed.

Off chain, with the tools in `tools/`:

```bash
python3 tools/read.py <VERIFIER> get str:0
python3 tools/read.py <VERIFIER> check_for str:0 amazon.com 1024 0x<requester>
python3 tools/read.py <VERIFIER> count
```

## Removed views

Three views were removed before the first deploy to keep the contract under
the 17 000 byte source limit (see [Building](#building-checking-and-deploying)):

- `latest_by_bh(bh)`, with its `bh_index` map. It returned the newest record
  for a body hash whatever its verdict, so its answer always had to go back
  through the consumer check anyway; a caller that holds a record id does
  not need it, and one that does not can find ids off chain from `get()`.
  It also let anyone move the pointer with a failing attestation.
- `fees_collected()`, with its `fees_total` counter. Every record carries
  `fee_paid`, so the income total is a sum over records, and the balance is
  what a payout is decided from.
- `check(id, domain, min_key_bits)`. It answered without the requester
  test, which made it the easier call to reach for and the wrong one for a
  consumer. `check_for` replaces it.

## The verification rules

**Signature selection comes first.** A blob may carry several
DKIM-Signature fields, since every relay that signs adds one. The contract
uses the one whose `d=` and `s=` equal the call's domain and selector,
compared in lower case, and ignores the rest, wherever the matching one sits.
Only when none of them matches is the record stored with the reason
`signature does not match domain or selector`, and then nothing is taken
from any signature: `bh`, `body_canon` and `from_domain` stay empty. The key
comes from the call's arguments, so checking another domain's signature
against it would only read as a bad signature.

Every rule below makes a record `valid` false. The RSA check of the selected
signature runs first; the rules then run in this order and the first one
that fails gives the reason, overriding the RSA verdict:

1. **From signed.** `from` must be in `h=`, or the reason is `from not
   signed`. An unsigned From can be anything.
2. **Duplicate signed headers.** For every name in `h=`, the blob may hold
   at most as many fields of that name as `h=` lists, or the reason is
   `duplicate signed header`. DKIM signs the bottom-most instance and a mail
   client shows the top one, so an extra From or Subject above the signed one
   verifies and still lies. The selected DKIM-Signature is not counted.
3. **Expiry.** If the signature carries `x=` and it is earlier than the
   runner datetime, the reason is `signature expired`. An `x=` that is not a
   plain number reads as 0, so it fails closed.

### Alignment

`aligned` is true when `d=` and `from_domain` are the same domain, or one of
them ends with `.` followed by the other: a From at `mail.example.com` signed
with `d=example.com` aligns, and so does a From at `example.com` signed with
`d=mail.example.com`. Siblings such as `news.example.com` and
`mail.example.com` do not.

No public suffix list is applied. DMARC relaxed alignment compares
organizational domains, which needs that list, and the list is too large to
carry on chain and changes over time. The rule here is the plain suffix
relation instead, so two domains under different registrable domains of a
shared suffix, such as `a.co.uk` and `b.co.uk`, are not aligned, by design.
The cost is that a signer using a sibling subdomain of the From domain is
reported as not aligned, where DMARC would accept it. That errs toward
refusing. A signer whose `d=` is a bare public suffix is unlikely rather
than excluded: `register_key` is open to anyone, so the only barrier is that
a DKIM key has to be published at that DNS name. The parent direction is
aligned, for example a From at `co.uk` signed with `d=anything.co.uk`; see
[Known limits](interfaces.md#7-known-limits).

Alignment is recorded, not enforced as validity: a record whose From domain
does not align with `d=` stays `valid` with `aligned` false, and
`check_for` refuses it. `from_domain` is read only when the blob has exactly
one From field; quoted display names are ignored, and more than one `@` or
`<` outside them leaves it empty, which reads as not aligned.

The duplicate rule only sees what the blob holds. A blob cut with
`experiments/dkim-probe/make_blob.py` keeps only the signed instance of each
header, so it cannot show that the original message had no unsigned copy
above it. The rule catches a blob that carries one; it does not prove the
message never did.

## attest

```
attest(headers_url: str, domain: str, selector: str) -> str
```

Payable. It returns the id of the record it wrote, with `source` `url`, or
one of the reason strings below if the call was refused.

Four things are checked before anything is fetched. None of them reverts:
each one refunds whatever the call carried, stores nothing and returns its
reason. See [What attest returns](#what-attest-returns).

1. The URL, after trimming, starts with `https://` and is at most 512
   characters, or the answer is `url not allowed`.
2. `gl.message.value` is at least `fee()`, or the answer is `fee not paid`.
   See [The fee](#the-fee).
3. The domain and the selector survive `normalize`, which trims, lowercases
   and drops a trailing dot, and empties anything over 253 or 63 characters.
   An empty result either way, including an empty argument, is
   `bad domain or selector`.
4. The Registry holds a key for that domain and selector and has not retired
   it, or the answer is `key not registered`. The key is read from the
   Registry's finalized state, so a newly registered key becomes usable only
   once its `register_key` transaction is FINALIZED; an attestation sent
   before that answers `key not registered` and can be sent again after.

Past those four checks nothing reverts either. The fetch, the parse and
the signature check all happen inside the non-deterministic block under
`gl.eq_principle.strict_eq`, which runs the probe on every validator and
compares the returned strings byte for byte, and every way that block can fail
is a stored record with `valid` false and a reason:

| reason | what happened |
|--------|---------------|
| `header signature verified` | the signature is good and every rule passed; this is the only `valid` true reason |
| `RSA PKCS#1 v1.5 check failed` | the signature did not verify against the Registry's key |
| `signature does not match domain or selector` | the blob is signed, but no signature in it is for the call's domain and selector |
| `from not signed` | `h=` does not list From |
| `duplicate signed header` | a signed header name occurs more often than `h=` lists it |
| `signature expired` | `x=` is earlier than the runner datetime |
| `no DKIM-Signature in the blob` | nothing to check, including an empty blob |
| `blob fetch failed: <ExceptionClass>` | the validator could not retrieve the URL |
| `blob HTTP <status>` | the URL answered, but not with 200 |
| `blob too large` | the fetched blob is over 16 384 bytes |
| `probe failed: <ExceptionClass>` | anything else the probe hit |
| `unsupported DKIM version`, `unsupported algorithm`, `unsupported header canonicalization`, `h= tag is empty`, `b= tag is not base64` | the signature is not one this verifier checks |

A fee is charged for the work the validators did, so a fetch that failed is
still a paid attestation: the caller bought the check, not the verdict. The
record says what went wrong and can be attested again against a working URL.

Validators fetch HTTPS on a domain name only. A raw IP or a non standard port
is refused inside the validator before the request leaves the node, and
arrives as `blob fetch failed`.

## attest_inline

```
attest_inline(headers_blob: str, domain: str, selector: str) -> str
```

Payable. The same verification as `attest`, on a blob passed in the call
instead of fetched, and the record's `source` is `inline`. There is nothing
non-deterministic to agree on, so it runs without the equivalence principle,
and every failure past the reverts is still a stored reason.

The blob travels as text, not bytes, and is encoded as UTF-8 before it is
parsed. That is lossless for a normal message: RFC 5322 headers are ASCII,
and a header with non-ASCII text carries it as an RFC 2047 encoded word,
which is ASCII too. A blob with raw 8-bit bytes in its headers cannot be
carried as text without changing those bytes, and a changed byte breaks the
signature, so such a message must use `attest` by URL, where the bytes are
fetched as they are.

Its rejections, all of them refunds rather than reverts:

1. The blob is over 16 384 bytes once encoded, which answers
   `blob too large`.
2. `fee not paid`, `bad domain or selector` and `key not registered`, as for
   `attest`. There is no URL, so `url not allowed` cannot happen here.

**The trade between the two methods.**

- `attest_inline` puts the blob in calldata, and calldata is permanent: every
  signed header, To and Subject included, can be read by anyone for as long
  as the chain exists. It needs no server and nothing can go missing between
  the call and finalization. It is meant for agent inboxes, where the
  mailbox is an automated one and its To and Subject lines are not personal.
- `attest` keeps To, Subject and every other header value off chain, but
  not private: the URL is in public calldata, and anyone who reads it can
  fetch the headers while they are served. The
  price is availability: the blob has to be served at the URL until the
  transaction is FINALIZED, because a validator that re-runs the probe during
  an appeal fetches it again, and a blob that is gone by then turns into a
  different verdict.

## What attest returns

`attest` and `attest_inline` both return a string. It is either the id of
the record that was written, which is always decimal digits, or one of these
reasons, in the order they are checked:

| returned | what happened | which method |
|----------|---------------|--------------|
| `0`, `1`, `2` ... | a record was written; read it with `get(id)` | both |
| `url not allowed` | the URL did not start with `https://`, or was over 512 characters | `attest` |
| `blob too large` | the blob was over 16 384 bytes once encoded | `attest_inline` |
| `fee not paid` | `gl.message.value` was below `fee()` | both |
| `bad domain or selector` | the domain was empty or over 253 characters, or the selector was empty or over 63 | both |
| `key not registered` | the Registry holds no usable key for that domain and selector, or its owner retired it | both |

**No call to `attest` or `attest_inline` can keep the sender's value without
creating a record.** Either the call writes a record, in which case the whole
value is kept and recorded in `fee_paid`, or it returns a reason, in which
case the whole value goes back to `gl.message.sender_address`. There is no
third outcome: neither method raises, so there is no path where the value
stays in the contract with nothing written for it.

A record with `valid` false is still a record. A failed fetch, a broken
signature or a rule the message did not pass are all verdicts the validators
did the work to reach, so they are stored and the fee is kept. Only the five
checks above, which happen before any work, give the value back.

A caller tells the two apart with `str.isdigit()` on the return value, or by
comparing against the reasons it cares about.

## The fee

`fee()` is the minimum value an `attest` or `attest_inline` call has to
carry, in wei. It starts at **zero**, so the contract works from the block it
is deployed in, and the owner moves it with `set_fee(new_fee)`.

- A call carrying less than `fee()` stores nothing and returns the string
  `fee not paid` instead of a record id. Whatever it carried is refunded to
  the sender, whole. A call carrying nothing is refused the same way, with
  nothing to refund.
- A call carrying more is accepted and the whole value is recorded in
  `fee_paid`. The excess is kept, not returned.
- `fee_paid` is per record, so what a given attestation cost stays readable
  after the fee changes.

**Why underpayment is not a revert.** v1 raised `fee not paid`, and what a
reverting payable call does with the value it carried has since been measured
on Bradbury: it keeps it. A call sending 5 000 000 000 000 000 wei against a
10 000 000 000 000 000 wei fee finished with an error, the contract balance
rose by exactly the amount sent, and the wallet got nothing back. The only
way out was the owner calling `withdraw` to the treasury, which settled on
finalization and brought the balance back to zero. A revert is therefore not
a way to refuse money on this chain, so v1.1 answers instead of reverting and
hands the value back itself.

**The refund settles on finalization,** the same way `withdraw` does: it
leaves through the external message path, the balance does not move inside
the call, and the sender is paid when the transaction FINALIZES. Between
ACCEPTED and FINALIZED the contract still reports a balance that includes
value already promised to a refund. See [Operations](#operations).

Every other rejection either method has works the same way, for the same
reason. They are listed in [What attest returns](#what-attest-returns).

**The gateway still sends exactly `fee()`,** read from `fee()` before every
call. The refund makes an underpayment survivable, not free: the call still
costs its gas, writes no record and has to be sent again, and the refund is
not in the sender's hands until finalization. One read is cheaper than that.

## The treasury and the payout

`treasury()` starts as the deployer. It moves in two steps, the same way
ownership does:

- `propose_treasury(address)` is owner only and stores a candidate; the zero
  address is refused. `pending_treasury()` reports it, or `""`.
- `accept_treasury()` succeeds only when the candidate itself sends it, which
  proves the address can sign and so can spend what it receives. Anyone
  else, the owner included, gets `pending treasury only`. The candidate is
  cleared once accepted.

Until `accept_treasury` lands, payouts still go to the old treasury. A
mistyped treasury address would otherwise receive every future payout with
nobody able to move it.

`withdraw(amount)` is owner only and sends `amount` wei to the treasury and
nowhere else. There is no destination argument: the owner cannot redirect a
single payout, only propose a new treasury in a write anyone can read.

The payout leaves through this contract's ghost contract as an external
message, which is the only path that reaches an address on the chain layer;
the internal, contract to contract path accepts the message and moves nothing.
That was measured in
[experiments/value-probe-2](../experiments/value-probe-2/README.md).

**It settles on finalization, not on acceptance.** The write is ACCEPTED with
the balance still in the contract and the value moves when the transaction
FINALIZES, which was about half an hour later on Bradbury. Between those two
points the contract still reports the whole balance. Anything that pays out
has to treat ACCEPTED as a promise and FINALIZED as the settlement.

`withdraw` refuses a non-positive amount and an amount above the balance.

## Operations

**Withdraw only when no attestation is waiting to finalize, and never the
whole balance in one call.**

A refused `attest` queues a refund that is paid when its transaction
FINALIZES, and `self.balance` counts that money until then. So between an
ACCEPTED refusal and its finalization the contract reports a balance it does
not entirely own. The value of a call that finalizes without executing
sits in the balance the same way, from activation until finalization, when
the protocol returns it to the sender. The contract does not track the
difference: there is no pending-refund counter and `withdraw` will happily
send the full reported balance.

What that means in practice:

- Withdraw when nothing is in flight. An attestation reaches FINALIZED in
  about half an hour on Bradbury, so a withdrawal that follows the last call
  by more than that is clear of it.
- Leave a margin. Withdrawing everything `balance()` reports is the one
  amount that cannot be safe; leaving the largest plausible refund behind
  costs nothing and cannot strand one.
- The income is the sum of `fee_paid` over the records, not the balance.
  Every kept fee wrote a record, by construction, so the records are the
  ledger and the balance is only what is currently sitting there.

The same applies to a fee change: `set_fee` does not touch value already in
the contract, and a refund in flight is for the fee that was in force when
its call was made.

## Ownership

The deployer is the first owner. `set_fee`, `propose_treasury`, `withdraw`
and `propose_owner` are the owner-only writes, and an unauthorized one raises
in the deterministic block, which reverts the whole transaction and leaves no
record.

Ownership moves in two steps, exactly as in the Registry: `propose_owner`
stores a candidate, the zero address is refused, and `accept_owner` succeeds
only for that candidate, which is what proves the address can sign. Until
`accept_owner` lands the old owner keeps every power it had. The owner sets
the fee and decides payouts, so a mistyped address has to be survivable.

## Building, checking and deploying

```bash
python3 contracts/verifier/build.py          # splices lacre/dkimcore.py in
python3 -m pytest -q                         # the copy and the built file
python3 tests/verifier_stub_run.py           # the whole contract, SDK stubbed
genvm-lint contracts/verifier/verifier.py
export PROBE_PK=0x<64 hex chars>
python3 tools/deploy.py contracts/verifier/verifier.py 0x<registry> --estimate-only
```

The build splices only the part of `lacre/dkimcore.py` the contract reaches.
The Verifier takes its key from the Registry, so the DER and DoH half of that
file is dead code here. `tests/test_dkimcore.py` holds `lacre/dkimcore.py`
byte for byte to the probe's verifier, and the same test rebuilds the
contract and fails if the committed file is stale.

**The deployed artifact carries no comments.** Source is charged by the
byte, so the build drops every full-line comment from both the template and
the spliced code. The only comment kept is the runner's `Depends` line on
line 1. The comments stay in `verifier_template.py` and `lacre/dkimcore.py`,
which are where the code is read and edited, and the reasoning that does not
fit in a one-line comment is in [Design notes](#design-notes) below. Read the
template, not `verifier.py`.

`build.py --check` verifies the built file without writing it, and prints the
size and the headroom under the 17 000 byte limit either way. At about 870
gas per byte that limit is about 14.8 M gas, 88 percent of the 2^24
transaction cap.

The deploy takes the Registry address as its constructor argument, the
Registry v1 address from deployments.json:

```bash
python3 tools/deploy.py contracts/verifier/verifier.py <REGISTRY>
python3 tools/call.py <REGISTRY> set_version verifier 0x<verifier address>
python3 tools/call.py <VERIFIER> attest https://lacre.in-sidr.xyz/<random>.txt amazon.com <selector>
```

The Registry pointer is what makes the address findable, so `set_version` is
part of the deploy rather than a later step. A contract cannot be read until
it is FINALIZED, so the first read after a deploy can fail and say nothing
about the deploy itself.

## Deployments

`deployments.json` at the repository root is the machine-readable copy of the
current deployment, written by `tools/deploy.py`. It keeps one entry per
contract name, so a redeploy replaces the `verifier` entry; retired addresses
are kept here instead. Both versions below are on Bradbury and were deployed
and exercised on 23 September 2026 from the owner wallet
`0xF27E3A6d7Bf4BfC0A837020FD74E73055aF17D53`.

| version | address | deploy consensus tx | deploy gas | source | status |
|---------|---------|---------------------|------------|--------|--------|
| v1.1 | `0x9821cfa5fe33a24f9d1D3Cca15885f1a2781EA1d` | `0x8ab6817cf0582fb5579dd3b36fc50a0f56dac4e895c934716e0b04a10e9d021e` | 13.21 M used, 0.028 GEN, AGREE | 16 912 bytes | live, `version("verifier")` points here |
| v1 | `0x74AfE3a7E6D2601bdC9BCC6265d8314F1a74807a` | `0x7b214b0f273c5c1b4135a7ed482cbab9b521c373ac88da3e57ba63f2d43132bc` | 13.24 M used of 14.3 M estimated, 0.028 GEN, AGREE | 16 954 bytes | retired by `set_version` |

### v1.1

v1.1 was deployed with Registry v1
`0x1E1380B71F1C9c622C432B6FD6fa56097B1E4Ddc` as its constructor argument, the
same Registry v1 resolves its keys through. The source is 16 912 bytes, 88 under the
17 000 byte limit.

The Registry pointer moved in the same session:
`set_version("verifier", "0x9821cfa5fe33a24f9d1D3Cca15885f1a2781EA1d")`,
consensus tx
`0x5f594ff01e1c99f1eb95aa2324600ce0b2f04d9d2de1356dfbe8eebb5f82083f`, AGREE
in 23 seconds. The earlier pointer is not erased: `versions_of("verifier")`
still lists `0x74AfE3a7E6D2601bdC9BCC6265d8314F1a74807a` first, so a consumer
holding a v1 record id can still find the contract that wrote it. The history
is in [docs/registry.md](registry.md).

**The refund test.** What v1.1 changes over v1 is that a refused call answers
and hands the value back instead of raising. That was measured on the deployed
contract with the fee set to 10 000 000 000 000 000 wei:

| call | value attached | consensus tx | result | gas |
|------|----------------|--------------|--------|-----|
| `attest`, underpaid | 5 000 000 000 000 000 wei | `0xfa4c961ae457caa1181f366902508a1a7a58b0732ca040c205cdefb7f98e9269` | FINISHED_WITH_RETURN, AGREE | 915 k |
| `attest`, unregistered selector | 10 000 000 000 000 000 wei | `0x05f57ee857c116eead6909f252de2401c5679ffe69d235166db3b99de5bd874c` | FINISHED_WITH_RETURN, AGREE | 907 k |

Neither call reverted, which is the point of the change: on v1 the first of
these would have raised, and a reverting payable call on this chain keeps what
it carried. Both returned their reason instead and queued a refund for the
whole amount attached.

Right after the two calls the contract balance was 15 000 000 000 000 000 wei,
the sum of the two amounts, with both refunds promised and neither settled.
That is the ACCEPTED state described in
[The treasury and the payout](#the-treasury-and-the-payout): a reported
balance the contract does not own. The fee was then set back to 0.

**Both refunds settled at FINALIZED,** on 23 September 2026:

| checked at | contract balance | owner wallet |
|------------|------------------|--------------|
| before the two calls | 0 wei | 19 161 952 081 578 793 850 wei |
| ACCEPTED, both refunds promised | 15 000 000 000 000 000 wei | unchanged |
| FINALIZED | 0 wei | 19 156 454 228 478 576 650 wei |

The contract kept nothing. The wallet is down 5 497 853 100 217 200 wei over
the whole test, which is exactly the gas of the two `attest` calls and the
`set_fee(0)` that followed them, so both refunds, 5 000 000 000 000 000 and
10 000 000 000 000 000 wei, landed in full. `count()` on v1.1 is 0: neither
call wrote a record, which is the other half of the promise in
[What attest returns](#what-attest-returns), that value is either kept against
a record or given back.

A refund leaves by the same external message path as `withdraw` and settled
with its transaction's finalization, not when the call was accepted.

### v1

v1 was deployed with the same Registry v1
`0x1E1380B71F1C9c622C432B6FD6fa56097B1E4Ddc` as its constructor argument.
Record 0 on it is a valid, aligned amazon.com attestation with `source` `url`,
read back from finalized state, and `check_for` returns true for it. That
record stays readable at the v1 address.

v1 is the version that reverted on underpayment and kept the value, which is
what v1.1 changes. The 0.005 GEN a reverting underpaid call left in it was
withdrawn to the treasury, and the balance was back to zero at FINALIZED. v1
stays on chain as the documented version that kept value on revert.

A GenLayer contract cannot be upgraded in place, so v1.1 is a new deploy at a
new address against the same Registry, and `set_version verifier` is what
moves the pointer to it. Nothing has to migrate: records are evidence of a
past check and a consumer that holds a v1 id keeps reading it from v1.

## Design notes

The contract template, `contracts/verifier/verifier_template.py`, carries
few comments, and the deployed file none. The reasoning behind it lives here.

- **Build.** `build.py` splices the part of `lacre/dkimcore.py` the contract
  reaches in at the `# @@DKIMCORE@@` marker and writes `verifier.py`. Edit
  the template, never the built file.
- **Privacy.** No header value, address, subject or Message-ID reaches
  calldata, storage or a log on the `attest` path. The blob is read inside
  the non-deterministic block and discarded there.
- **The recipient interface.** `_Recipient` is an empty EVM interface on
  purpose: a wallet on the chain layer has no method to call, only value to
  be handed, and an empty interface is how the SDK addresses it.
- **body_mode.** RFC 6376 3.5: `c=` is `header/body`, and the body half is
  `simple` when the tag, or the slash inside it, is absent. The Extractor
  canonicalizes with this value.
- **Signature selection.** `verify_headers` in `lacre/dkimcore.py` checks
  the first DKIM-Signature it finds, and that file has to stay byte for byte
  the probe's. So the template moves the selected signature to the top and
  re-joins the fields before calling it. The signed data does not depend on
  where the signature sits, since `signed_data` takes it out of the pool and
  adds it last.
- **The probe never raises.** Any failure inside it is a stored
  `valid=false` record, not a revert that stores nothing and still costs the
  caller the gas. `getattr` on the response keeps a renamed field from
  raising where nothing may raise.
- **Rules override the RSA verdict.** They are checked in a fixed order and
  the first failure is the reason, so the reason names the most basic
  problem rather than whichever was checked last.
- **Dates without datetime.** The runner datetime is a string. `unix_time`
  reads it by character position, so `T` or a space may separate date and
  time, and it accepts `Z`, `+hh:mm`, `+hhmm` or no zone. The day count is
  the civil-from-days formula. `tests/test_verifier_time.py` compares it
  against the standard library.
- **Numbers from the blob.** `as_number` accepts ASCII digits only, so a
  Unicode digit that `str.isdigit` accepts and `int` refuses returns 0
  instead of raising. `signed_at` is 0 for a `t=` of 20 or more digits, so it
  always fits a u256.
- **registry_key.** A key the Registry does not hold, or one its owner
  retired, is refused before anything is fetched rather than fetched and
  judged. It reads with `view(state=StorageType.LATEST_FINAL)`, imported
  from `genlayer.py.public_abi` because `from genlayer import *` does not
  export it: a key registration still open to appeal is not trusted, and
  the read is the same on every validator. `key_bits` and `key_sha256` on the record describe the key checked
  against, so they come from the Registry and never from the blob.
- **Neither attest method reverts.** Every deterministic rejection they have
  happens before the first fetch or parse, and every one of them refunds and
  returns a reason instead of raising, because a revert would keep the value.
  `refuse()` is the single place that does it, so a rejection added later
  cannot quietly skip the refund. Past those checks the caller has bought the
  work, whatever the verdict.
- **Raises that are left.** `set_fee`, `propose_owner`, `accept_owner`,
  `propose_treasury`, `accept_treasury` and `withdraw` still raise, and so
  does the constructor. None of them is payable, so none can be holding a
  sender's value when it raises. `check_for` parses an address and catches
  its own failure, and it is a view.
- **registry_key answers, it does not raise.** The cross-contract read is
  inside its `try` along with the parsing, so a Registry that is missing,
  reverting or returning something unexpected is a refused call with a
  refund rather than a revert holding the value.
- **Consensus.** `strict_eq` compares the probe's return values byte for
  byte, so consensus rides on the canonical string and never on the fetched
  bytes. `scrub()` keeps `|` out of every field, so the split yields a fixed
  number of parts, and the split is padded rather than allowed to raise.
- **Requester as an address.** `requester` is stored as an `Address` and
  `check_for` parses its argument into one, so two spellings of the same
  address compare equal and two different addresses never do.
- **Two-step transfers.** A typo in a proposal has to be survivable, so
  ownership and the treasury move only when the new address proves it can
  sign.
- **Payout path.** `withdraw` sends an external message through this
  contract's ghost contract. It settles on finalization, so the balance does
  not move inside the call. Every refund takes the same path, for the same
  reason: it is the only one that reaches a wallet.

## Serving a blob

The blob is one DKIM-Signature plus exactly the headers it signs, cut with
`experiments/dkim-probe/make_blob.py`, served at an HTTPS URL on a domain name
until the attestation is FINALIZED and then removed. The URL is published on
chain: it is in the transaction's calldata, public from the moment the
transaction is submitted, so a random name protects nothing once the
transaction is sent, and anyone reading the chain can fetch the headers while
they are served. It is not
stored in this repository and no sample is tracked. See
[experiments/dkim-onchain-probe/serve.md](../experiments/dkim-onchain-probe/serve.md).
