# Verifier

The Verifier is the contract that turns a DKIM signature into a record other
contracts can read. It is handed the signed headers, either as a URL the
validators fetch or inline in the call, with a domain and a selector. The RSA
signature is verified independently and what is stored is one small record:
the body hash the signature claimed, how the body was canonicalized, a digest
of the Message-ID, the From domain and whether it aligns with the signer, the
key it was checked against, a verdict and a reason.

It never reads DNS itself. v1.1, the deployed version, reads keys from the
[Registry](registry.md) it was deployed with.

This page describes **v1.2, which is built and not deployed**, and says where
it differs from v1.1. v1.2 reads keys from the [KeyCache](keycache.md), which
it finds through the [Router](router.md) on every call, so the KeyCache can be
replaced without a new Verifier. What v1.2 adds over v1.1:

- signatures carrying `l=` are refused, with a refund;
- a key the KeyCache holds as `pending`, `rotated` or `retired` is refused,
  with a refund and a reason per state; only an `active` key attests;
- every record carries `schema_version`, `"2"`;
- `records_of(requester)` and `last_refusal(requester)`, because the return
  value of a write cannot be read from the chain;
- the constructor argument is the Router address, and `registry()` is
  replaced by `router()`.

Everything else, the refund on every deterministic refusal included, is v1.1
unchanged.

## What a record contains

| field | meaning |
|-------|---------|
| `domain` | the signing domain, lowercased, as the call named it |
| `selector` | the selector, lowercased |
| `bh` | the body hash the signature committed to, base64, as published |
| `body_canon` | the body canonicalization from the signature's `c=` tag |
| `message_id_sha256` | SHA-256 of the Message-ID, hex, empty if there was none |
| `key_bits` | the modulus size of the key the KeyCache held (the Registry's on v1.1) |
| `key_sha256` | SHA-256 of the DER the domain published, from the same record |
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

On v1.2, `get` also returns `schema_version`, the string `"2"`. It is a
constant of the contract rather than a stored field: every record a given
Verifier writes has the same layout, so the value is the same for all of
them and costs no storage. Records of v1 and v1.1 carry no such field and
are schema 1. A reader that meets a `schema_version` it does not know should
stop rather than guess what the fields mean.

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
record id, never re-resolved through the Registry or the Router for a
decision: ids start at `"0"` on every Verifier, and either pointer can move. See rules 1
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

## What a caller's calls did (v1.2)

The return value of `attest` or `attest_inline`, a record id or a refusal
reason, cannot be read from the chain after the fact
([interfaces.md](interfaces.md), section 5, rule 15). v1.2 exposes both as
views, keyed by the address that sent the call:

- `records_of(requester) -> list` returns the ids of every record that
  requester's calls wrote on this Verifier, oldest first, as strings.
- `last_refusal(requester) -> str` returns the reason of that requester's
  most recent refused call, or `""` if none was ever refused.

Both parse `requester` as an address, so any spelling of it works, and a
malformed one answers `[]` or `""` rather than raising.

A client learns what its call did by reading both before sending and again
at FINALIZED: a new id at the end of `records_of` is its record; otherwise a
changed `last_refusal` is its refusal. A recorded call does not clear
`last_refusal`, and the view holds only the latest reason, so two refusals
in a row for the same reason read the same. A client that sends one call at
a time, as rule 13 requires, and still sees neither change knows its call
did not execute, or was refused for the same reason as the one before it;
the transaction's own status tells those two apart.

## Removed views

Three views were removed before the first deploy to keep the contract under
the 17 000 byte source limit v1 and v1.1 were built to (see
[Building](#building-checking-and-deploying)):

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

**`l=` is refused (v1.2).** If the selected signature carries an `l=` tag,
the probe stops there with the reason `body length limit not supported`, and
once the validators have agreed on it the call is refused: nothing is
stored, the whole value is refunded, and the reason is returned and kept in
`last_refusal`. An `l=` signature covers only a prefix of the body, and a
record cannot say which prefix, so a consumer checking a body against `bh`
could be shown a message with anything appended. `l=` on a signature that is
not the selected one is ignored, like everything else about that signature.
This is the one refusal that comes after the work rather than before it: on
the `attest` path the validators have fetched the blob by then. It is
refunded all the same, because it is decided on the agreed verdict, which
is the same on every validator, and a caller cannot tell an `l=` signature
from the outside before sending. On v1.1 `l=` is neither refused nor
recorded.

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
4. The key is usable. On v1.1 the Registry holds a key for that domain and
   selector and has not retired it, or the answer is `key not registered`.
   On v1.2 the Verifier reads `resolve("keycache")` from the Router and then
   `key_status(domain, selector)` from the KeyCache it names, both at
   `LATEST_FINAL`, and refuses unless the key is `active`:

   | reason | what happened |
   |--------|---------------|
   | `router unreadable` | the Router read raised |
   | `router resolves no keycache` | the Router has no current `keycache` |
   | `keycache unreadable` | the KeyCache read raised, or the Router named something that is not an address, or the record could not be parsed |
   | `key not registered` | the KeyCache holds no record, its modulus is not above 1 or its exponent not above 2, or its state is one the Verifier does not know |
   | `key pending` | the key is still in quarantine |
   | `key rotated` | DNS publishes a different key under the selector |
   | `key retired` | the key was retired by refresh or by the KeyCache owner |

   Either way the key is read from finalized state, so a newly registered
   key, or on v1.2 a newly confirmed one, becomes usable only once that
   transaction is FINALIZED; an attestation sent before that is refused and
   can be sent again after.

Past those four checks nothing reverts either. The fetch, the parse and
the signature check all happen inside the non-deterministic block under
`gl.eq_principle.strict_eq`, which runs the probe on every validator and
compares the returned strings byte for byte, and every way that block can fail
is a stored record with `valid` false and a reason, with one exception on
v1.2: a selected signature carrying `l=` is refused and refunded instead of
recorded (see [The verification rules](#the-verification-rules)).

| reason | what happened |
|--------|---------------|
| `header signature verified` | the signature is good and every rule passed; this is the only `valid` true reason |
| `RSA PKCS#1 v1.5 check failed` | the signature did not verify against the key (the KeyCache's on v1.2, the Registry's on v1.1) |
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
2. `fee not paid`, `bad domain or selector` and the key refusals, as for
   `attest`. There is no URL, so `url not allowed` cannot happen here.
3. On v1.2, `body length limit not supported` for a selected signature
   with `l=`.

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
| `key not registered` | v1.1: the Registry holds no usable key for that domain and selector, or its owner retired it. v1.2: the KeyCache holds no usable record | both |
| `router unreadable`, `router resolves no keycache`, `keycache unreadable` | v1.2 only: the KeyCache could not be found or read, see [attest](#attest) | both |
| `key pending`, `key rotated`, `key retired` | v1.2 only: the KeyCache holds the key in that state | both |
| `body length limit not supported` | v1.2 only: the selected signature carries `l=`; checked after the work, on the agreed verdict | both |

**No call to `attest` or `attest_inline` can keep the sender's value without
creating a record.** Either the call writes a record, in which case the whole
value is kept and recorded in `fee_paid`, or it returns a reason, in which
case the whole value goes back to `gl.message.sender_address`. There is no
third outcome: neither method raises, so there is no path where the value
stays in the contract with nothing written for it.

A record with `valid` false is still a record. A failed fetch, a broken
signature or a rule the message did not pass are all verdicts the validators
did the work to reach, so they are stored and the fee is kept. Only the
refusals above give the value back. All of them but `l=` happen before any
work; `l=` is refused after it, on the verdict the validators agreed on.

On v1.2 every refusal also sets `last_refusal(sender)`, and every record
appends its id to `records_of(sender)`, so both outcomes can be read after
the fact; see [What a caller's calls did](#what-a-callers-calls-did-v12).

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
genvm-lint check contracts/verifier/verifier.py
export PROBE_PK=0x<64 hex chars>
python3 tools/deploy.py contracts/verifier/verifier.py 0x<router> --estimate-only
```

`contracts/verifier/verifier.py` is now the v1.2 build. The v1.1 source that
is deployed is that file as of commit `a56f1c9`, which is what
`deployments.json` records and `tools/verify_deploy.py verifier` compares the
chain against. `genvm-lint` reports `E105` on the validate half for the
reason given in [docs/router.md](router.md#building-checking-and-deploying).

The build splices only the part of `lacre/dkimcore.py` the contract reaches.
The Verifier takes its key from the KeyCache, the Registry on v1.1, so the
DER and DoH half of that file is dead code here. `tests/test_dkimcore.py` holds `lacre/dkimcore.py`
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
size, the headroom under the build cap and the estimated deploy gas either
way. v1 and v1.1 were built to a 17 000 byte cap. v1.2 raises it to 18 500
rather than cut tested code: the v1.2 build is 18 289 bytes, which at the
870 gas per byte the builds estimate with is 15 911 430 gas, 94.8 percent of
the 2^24 transaction cap. The cap itself, 18 500 bytes, would be 16 095 000
gas, 95.9 percent, so by that rule the byte cap is no longer the binding
limit: 95 percent of 2^24 is reached at 18 320 bytes, 31 bytes above the
current build. v1.1 used 13.21 M gas for 16 912 bytes on Bradbury, about 781 gas
per byte.

The node's own estimate for this build (`tools/deploy.py --estimate-only`
with the Router argument `0x...dEaD`, 2026-09-26, source SHA-256
`dfc1c100...20189b48`, `lacre/dkimcore.py` at `834bbcdb...72301b92`,
18 597 bytes of calldata) is 15 341 609 gas, 91.4 percent of 2^24, below
the 95 percent line, so nothing is cut. That estimate, not the 870 rule, is
the figure to go by: it is computed from the exact calldata the deploy
sends, and it is the number `tools/deploy.py` signs from. At 91.4 percent,
the deploy's three-times margin does not apply. Three times the estimate is
clamped to 2^24, 16 777 216, which is 1.094 times the estimate, 1 435 607
gas of headroom. The deploy has to go out from the same source that was
estimated, after a fresh `--estimate-only` run on the same network, and
there is no retry with more gas: 2^24 is the ceiling. v1 used 13.24 M of
a 14.3 M estimate, 93 percent, so the headroom is expected to hold. If it
does not, or a fresh estimate reaches 95 percent, `last_refusal` is the
first candidate to drop: its view, its storage map and the line that writes
it are 279 bytes of the build, about 243 000 gas at 870 per byte.

The v1.1 deploy took the Registry address as its constructor argument, the
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

v1.2, when it is deployed, takes the Router address instead. On a Router
where `verifier` has never resolved, `set_version` takes effect at once; on
one where it already resolves, the change waits the Router's 48 hours:

```bash
python3 tools/deploy.py contracts/verifier/verifier.py <ROUTER>
python3 tools/call.py <ROUTER> set_version verifier 1.2 0x<verifier address>
python3 tools/call.py <ROUTER> apply_version verifier      # only if it was a change, 48 hours later
```

Until the Router resolves `keycache`, every call is refused with
`router resolves no keycache` and refunded. `tools/attest.py` is written for
v1.1: it reads `registry()` and the Registry's `get_key` to derive a refusal
and scans records to find its own, and has not been changed for v1.2.

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

v1.2 is built and tested and has not been deployed anywhere.

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
- **cached_key (v1.2; registry_key on v1.1).** A key that is not held, or
  not active, is refused before anything is fetched rather than fetched and
  judged. Both reads, the Router's `resolve("keycache")` and the KeyCache's
  `key_status`, use `view(state=StorageType.LATEST_FINAL)`, imported from
  `genlayer.py.public_abi` because `from genlayer import *` does not export
  it: a key registration or a Router change still open to appeal is not
  trusted, and the read is the same on every validator. `key_bits` and
  `key_sha256` on the record describe the key checked against, so they come
  from the KeyCache and never from the blob. Only the three states the
  KeyCache defines produce a `key <state>` reason; anything else a KeyCache
  answers is `key not registered`, so a KeyCache cannot put arbitrary text in
  a refusal.
- **The KeyCache is resolved on every call.** Holding its address from the
  constructor would tie a Verifier to one KeyCache for life, as v1.1 is tied
  to one Registry. Resolving it through the Router costs one more
  cross-contract view per call, and lets a new KeyCache take over behind the
  Router's 48 hour delay without a new Verifier.
- **Neither attest method reverts.** Every deterministic rejection they have
  refunds and returns a reason instead of raising, because a revert would
  keep the value. `_refuse()` is the single place that does it, and it also
  records the reason for `last_refusal`, so a rejection added later cannot
  quietly skip the refund or the view. All of them but `l=` happen before
  the first fetch or parse; past those checks the caller has bought the
  work, whatever the verdict, unless the signature carries `l=`.
- **l= after the work.** The tag is only visible inside the blob, which on
  the `attest` path exists only inside the non-deterministic block. The
  probe returns the refusal reason as its verdict, the validators agree on
  it like any other, and the deterministic half refuses on the agreed
  string. A refusal decided that way is the same on every validator.
- **schema_version is a constant, not a field.** Every record on one
  Verifier has the same layout, so storing the version per record would
  cost storage and say nothing more. `get` returns it with each record.
- **records_of and last_refusal.** Both are keyed by the requester's
  `as_hex`, the spelling `Address` produces, so the key is the same however
  the caller spelled its address. `records_of` is a `DynArray` per
  requester, appended once per record, so reading it never scans the whole
  record map.
- **Raises that are left.** `set_fee`, `propose_owner`, `accept_owner`,
  `propose_treasury`, `accept_treasury` and `withdraw` still raise, and so
  does the constructor. None of them is payable, so none can be holding a
  sender's value when it raises. `check_for` parses an address and catches
  its own failure, and it is a view.
- **cached_key answers, it does not raise.** Each cross-contract read is
  inside a `try` along with the parsing, so a Router or a KeyCache that is
  missing, reverting or returning something unexpected is a refused call
  with a refund rather than a revert holding the value.
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
