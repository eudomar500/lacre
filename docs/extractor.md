# Extractor

The Extractor is the first extraction layer: it answers "what does it say"
for a message the Verifier has already answered "who sent this" for. It
takes the id of a Verifier record and the URL of the message body, checks
that the body served there is the one the DKIM signature committed to, reads
a few fields out of it with the sender's patterns, and stores a record.

**Status: built and tested against the stubbed SDK, not deployed.** It is
meant to be registered on the Router under the name `extractor`. No address
exists yet; `tools/extract.py` stops with "the Router resolves no extractor"
until one does.

Source: `contracts/extractor/extractor_template.py`, with
`lacre/dkimbody.py` and `lacre/patterns.py` spliced in by
`contracts/extractor/build.py`. Read the template and the two modules, not
the built `extractor.py`, which has no comments and one space of indentation
per level (see [Building, checking and deploying](#building-checking-and-deploying)).

## How it links to the Verifier

A Verifier record carries `bh`, the body hash the signature claimed, and
`body_canon`, the body half of the signature's `c=` tag. Neither was checked
against a body: the Verifier never sees one. The Extractor closes that:

1. It resolves the Verifier through the Router, `resolve("verifier")`, on
   every call, and reads the record with `get(record_id)`, both at
   `LATEST_FINAL`. The Verifier's address is never stored in state, so the
   Router's owner can replace the Verifier (with the Router's 48 hour delay)
   without a new Extractor. Each record says which Verifier it read.
2. Each validator fetches the body, canonicalizes it with the record's
   `body_canon` and compares its SHA-256 with the record's `bh`. This is the
   body probe's measurement on Bradbury, with relaxed canonicalization added
   by `lacre/dkimbody.py`.
3. Only when the hash matches are the patterns applied.

There is no RSA and no DNS here. The chain of trust is: the Verifier record
says the signing domain signed a header block claiming `bh`; the Extractor
record says a body hashing to that `bh` says these things. A consumer that
trusts both records for the same Verifier, record id and `bh` has the whole
chain.

## Methods

| method | kind | access | returns |
|--------|------|--------|---------|
| `__init__(router: str)` | constructor | deployer | owner and treasury start as the deployer, fee starts at 0 |
| `extract(record_id: str, body_url: str)` | write, payable | anyone | `str`, a record id or a refusal reason |
| `set_patterns(domain: str, patterns_json: str)` | write | owner | `str`, the document's SHA-256 |
| `patterns(domain: str)` | view | anyone | `str`, the stored document or `""` |
| `patterns_sha256(domain: str)` | view | anyone | `str`, hex, or `""` |
| `get_record(id: str)` | view | anyone | `dict`, `{}` for an unknown id |
| `count()` | view | anyone | `int` |
| `records_of(requester: str)` | view | anyone | `list` of record ids |
| `last_refusal(requester: str)` | view | anyone | `str` |
| `fee()` | view | anyone | `int`, wei |
| `router()`, `owner()`, `pending_owner()`, `treasury()`, `pending_treasury()` | view | anyone | `str` |
| `set_fee(new_fee: int)` | write | owner | `str` |
| `propose_owner(address: str)`, `accept_owner()` | write | owner, then pending owner | `str` |
| `propose_treasury(address: str)`, `accept_treasury()` | write | owner, then pending treasury | `str` |
| `withdraw(amount: int)` | write | owner | `str` |

The fee, the treasury, the two-step handovers and `withdraw` behave exactly
as on Verifier v1.2; see [docs/verifier.md](verifier.md#the-fee). A
malformed `requester` reads as `[]` and `""`, never as an error.

## extract

`extract(record_id, body_url)` never raises. It returns a record id, always
decimal digits, or a refusal reason.

**Refusals.** Checked in this order before any work. Each one stores
nothing, writes the reason to `last_refusal(sender)`, returns it, and
refunds the whole `gl.message.value` to the sender by external message,
which settles at FINALIZED. The helper that does this is the Verifier's.

| reason | condition |
|--------|-----------|
| `fee not paid` | `gl.message.value` is below `fee()` |
| `router unreadable` | `resolve("verifier")` on the Router raised |
| `router resolves no verifier` | the Router resolves `verifier` to nothing |
| `verifier unreadable` | the resolved address is not an address, or `get` on it raised |
| `record not found` | the Verifier has no record with that id (surrounding whitespace is trimmed; anything that is not an id is not found) |
| `record not valid` | the record's `valid` is not true |
| `record not aligned` | the record's `aligned` is not true |
| `body canonicalization not supported` | the record's `body_canon` is neither `simple` nor `relaxed` |
| `no patterns for domain` | no document is stored for the record's `domain` |
| `url not allowed` | the URL, trimmed, does not start with `https://` or is over 512 characters |

The four reasons about the Router and the Verifier, and the one about
`body_canon`, are not in the original request; they are the Verifier's
`router unreadable` family and the rule of
[docs/interfaces.md](interfaces.md) section 7 that an Extractor must refuse
any `body_canon` other than `simple` or `relaxed`.

**The non-deterministic block.** Past the refusals, every validator runs the
same function under `gl.eq_principle.strict_eq`:

1. fetch the URL with `accept: */*`;
2. anything but HTTP 200 is `body HTTP <status>`, and an exception is
   `body fetch failed: <ExceptionClass>`, the class name only, since an
   exception's text can echo the URL;
3. a body over 262 144 bytes is `body too large`;
4. canonicalize the body under the record's `body_canon` and compare the
   base64 SHA-256 with the record's `bh`; a difference is `bh mismatch`;
5. take the first `text/plain` part, as the body probe did; none is
   `no text part`;
6. apply the domain's patterns (below); success is `extracted`.

Any exception from steps 4 to 6 is `extract failed: <ExceptionClass>`.

The validators agree on one string:

    match|shipped|eta_day|eta_date|order_id_found|patterns_sha256|reason

`match`, `shipped` and `order_id_found` are `0` or `1`; `eta_day` is a
weekday word or empty; `eta_date` is `YYYY-MM-DD` or empty. `reason` is the
seventh field. The request named the first six only, and a record has to be
able to say `bh mismatch` or `body too large`, which cannot be derived
outside the non-deterministic block; the reason is one of the fixed phrases
above or an exception class name, so nothing read from the body can reach
it. Nothing else from the block reaches storage, and the deterministic side
holds each field to its shape again before storing it: a record with
`match` false always has `shipped` and `order_id_found` false and both
dates empty, whatever the string said.

**Outcomes that are records, not refusals.** Every outcome of the block,
`bh mismatch`, `body too large`, a fetch failure and `no text part`
included, is a stored record and keeps the whole value, as a record with
`valid` false does on the Verifier. The requester paid for the validators'
work, and that work happened. If the validators do not agree, nothing is
written in that round and the consensus protocol decides the outcome.

| reason | match | fields |
|--------|-------|--------|
| `extracted` | true | as read |
| `no text part` | true | all empty |
| `bh mismatch` | false | all empty |
| `body too large` | false | all empty |
| `body HTTP <status>` | false | all empty |
| `body fetch failed: <ExceptionClass>` | false | all empty |
| `extract failed: <ExceptionClass>` | false | all empty |

`extract failed` after a matching hash is reported as match false: the
reading failed, so the record should not be used, and a consumer that gates
on `match` is kept away from it.

## The record

`get_record(id)` returns `{}` for an unknown id, otherwise:

| field | type | where it comes from |
|-------|------|---------------------|
| `id` | str | this Extractor's record id, `"0"`, `"1"`, ... |
| `schema_version` | str | `"1"` |
| `verifier` | str, address | the Verifier the Router resolved at extraction time |
| `record_id` | str | the Verifier record id, trimmed |
| `domain` | str | the Verifier record's `domain` |
| `bh` | str | the Verifier record's `bh` |
| `match` | bool | the body served hashed to `bh` under `body_canon` |
| `reason` | str | see the table above, at most 96 characters |
| `method` | str | `"patterns"` |
| `patterns_sha256` | str | SHA-256, hex, of the document that read this record |
| `shipped` | bool | a `shipped` expression matched |
| `eta_day` | str | ASCII weekday, `lunes` to `domingo`, or empty |
| `eta_date` | str | `YYYY-MM-DD` when the sender's patterns capture a full valid date, else empty |
| `order_id_found` | bool | an `order_id` expression matched |
| `signed_at` | str | the Verifier record's `signed_at`, the signature's `t=` |
| `requester` | str, address | the sender of the extracting transaction |
| `extracted_at` | str | `gl.message_raw["datetime"]` of that transaction, unmodified, as the KeyCache stores its times |
| `fee_paid` | str | the whole value of that transaction, in wei |

Ids are local to one Extractor. A consumer stores the Extractor address with
the id, as it stores the Verifier address with a Verifier id.

## The patterns document

One JSON document per domain, set by the owner with `set_patterns`. It is an
object with exactly four keys, each a list of Python `re` expressions:
`shipped`, `eta_day`, `eta_date` and `order_id`. `set_patterns` normalizes
the domain as the Verifier does (trimmed, lowercased, outer dots removed),
trims the document and raises `[EXPECTED] ...` for:

- more than 4096 bytes, UTF-8, after trimming (`patterns too large`);
- text that is not JSON (`patterns not JSON`);
- anything but an object with those four keys, each a list
  (`patterns need lists under eta_date eta_day order_id shipped`); an extra
  key is refused as a missing one is;
- an expression that is not a string or does not compile
  (`patterns key does not compile: <key>`);
- an `eta_date` expression without the named groups `y`, `m` and `d`
  (`eta_date needs groups y m d`).

The stored text is the trimmed document, and `patterns_sha256(domain)` and
every record's `patterns_sha256` are the SHA-256 of its UTF-8 bytes. Trimming
is what lets a file with a trailing newline and the same text passed through
a shell hash alike. A replacement takes effect for records written after it;
earlier records keep the digest of the document that read them. There is no
way to delete a document; storing one whose lists are all empty reads every
body as nothing.

**Matching rules.** They are the body probe's (`experiments/dkim-probe/dkim/body.py`),
with the three fixed expressions replaced by lists:

- The text is the first `text/plain` part, decoded from quoted-printable or
  base64 as its headers say, then as UTF-8 with replacement. The lowercase
  vowels with acute accents, u with diaeresis and n with tilde are folded to
  ASCII, and then the text is lowercased; this is the probe's order, so an
  uppercase accented letter is lowercased but not folded. Expressions are
  therefore written in lowercase ASCII.
- `shipped` and `order_id`: true when any expression matches anywhere
  (`re.search`).
- `eta_day`: expressions in document order; each offers its first match
  only. The value is group 1, or the whole match for an expression with no
  group, and is kept only if it is one of `lunes`, `martes`, `miercoles`,
  `jueves`, `viernes`, `sabado`, `domingo`. The first expression that yields
  one wins.
- `eta_date`: the same, with the value built from the groups `y`, `m` and
  `d`. They have to be ASCII digits (a bare `\d` also matches other
  scripts), four for the year and one or two for the month and day, and
  form a valid Gregorian date, leap years included. The value is
  `YYYY-MM-DD`.
- An empty list never matches.

`lacre/extractors/amazon.json` is the amazon.com document, the probe's three
expressions ported as data, with `eta_date` empty. `tests/test_patterns.py`
holds it to `lacre/dkimbody.py`'s `extract_fields` on a set of texts.

**The runner has `re` and `json`.** The contract imports both at the top
level. `re` is the module Verifier v1.2 already runs on Bradbury (its
`from_domain` and the spliced `lacre/dkimcore.py` use it); the stub run checks
that the deployed Verifier source, by the hash `deployments.json` records,
imports it the same way. `json` is part of the runner's standard library and
the SDK's own calldata code imports it, but no Lacre contract has executed it
on chain yet; the first `set_patterns` on a deployment is where that is
confirmed.

## Checking a document and a message off chain

```bash
python3 tools/extract_check.py MESSAGE.eml lacre/extractors/amazon.json --domain amazon.com
```

It checks the document with the same `load_patterns` the contract runs, picks
the DKIM-Signature by `d=` (and `s=` if given) as the Verifier does, refuses
`l=` and any `body_canon` the Extractor refuses, verifies the body against
`bh=`, and prints the canonical string and the document's SHA-256. The code
is `lacre/dkimbody.py` and `lacre/patterns.py`, the same files the build
splices in, so the string is the one the validators would agree on for that
body served unchanged. It prints no header value, no address and no order
number. Exit 0 is a match read to the end, 2 a record with `match` false, 1
an error.

## Security notes

**What a malicious body can do.** Anyone can call `extract` for any valid,
aligned Verifier record and serve anything at the URL.

- It cannot put a value in a record for a body that is not the signed one.
  The hash is checked before any pattern runs, and a mismatch stores `match`
  false with every field empty.
- It cannot put arbitrary text in storage. `eta_day` is one of seven words,
  `eta_date` is a validated date, the booleans are booleans, and `reason` is
  a fixed phrase or an exception class name. The block's output is re-checked
  field by field before it is stored.
- It cannot make validators disagree on purpose through the patterns: every
  validator runs the same expressions over the same bytes. What it can do is
  serve different bytes to different validators, which ends in disagreement
  and no record, or in a `bh mismatch` record the caller paid for.
- A signed body can still say false things. The signature proves the sender
  wrote the body, not that the parcel shipped. A sender's own template can
  also contain text crafted by whoever controls parts of it, such as a
  product name; patterns should anchor on the template's fixed wording.
- It can cost time. Python `re` backtracks, and a badly written expression
  over a 256 KB body can take long enough to time a validator out. The body
  cap bounds the input; the expressions are owner data, reviewed when set,
  and should avoid nested quantifiers.

**What the owner can do.** The owner sets the patterns, so the owner decides
what `shipped` means for a domain. A record's `patterns_sha256` says which
document read it and `patterns(domain)` shows the current one, so a consumer
can pin the digest it reviewed and refuse records read by any other. The
owner cannot change a record once written, cannot make a mismatched body
match, and cannot choose the Verifier: that is the Router's, with its delay.

**Why the order number is never stored.** An order number identifies a
purchase and, with the merchant, a person. It would be public forever in
storage, and a hash of it is no better: order numbers have a fixed, small
format, so a hash is reversed by enumeration. The expression that finds it is
reduced to a boolean inside `extract_body`, in `lacre/patterns.py`, and the match is
never kept; it reaches neither the canonical string, nor storage, nor a
log. Binding a record to one order without publishing it needs a salted
commitment held by the parties, which is a product decision and not this
contract's.

**Why the ETA is text.** The message says when the parcel arrives in words,
relative to a date the contract does not know for certain: "llega el
miercoles" means the Wednesday after some day near `signed_at`. Turning that
into a timestamp means choosing a time zone and a reference day, and every
choice is a claim the message does not make. The record reports what the
message says, the weekday as a word, and `signed_at` next to it, and leaves
the arithmetic to the consumer. `eta_date` is filled only when the sender's
own text carries a full date.

**The body is public while it is served.** The URL is in calldata from the
moment the transaction is submitted, and validators may fetch it again during
an appeal, so the body has to be served until the transaction is FINALIZED
and should be removed after. A body carries the recipient's name and address;
serve it only from a URL nobody else can list, and take it down at
finalization, as [docs/verifier.md](verifier.md#serving-a-blob) says for the
headers.

**The requester.** `requester` is whoever paid for this extraction. It is not
required to equal the Verifier record's requester, and neither proves who
received the message.

## Rules for consumers

1. Decide only on a record read at `LATEST_FINAL`, from a FINALIZED
   transaction ([docs/interfaces.md](interfaces.md) section 5, rules 1, 10
   and 11).
2. Gate on `match` true and `reason` `extracted`. Anything else says
   nothing about the body.
3. Read the Verifier record the Extractor record names (`verifier`,
   `record_id`) and apply the Verifier's own rules to it, `check_for`
   included. The Extractor checked `valid` and `aligned` when it ran, not
   the domain, key size or requester a consumer wants.
4. Pin the `patterns_sha256` you reviewed for a domain, and refuse records
   read by another document.
5. Store the Extractor address with the record id.
6. Keep your own record of what you have paid out on: the same body can be
   extracted any number of times.

## Building, checking and deploying

```bash
python3 contracts/extractor/build.py          # splices dkimbody.py and patterns.py
python3 -m pytest -q                          # the modules and the built file
python3 tests/extractor_stub_run.py           # the whole contract, SDK stubbed
genvm-lint lint contracts/extractor/extractor.py
python3 tools/extract_check.py MESSAGE.eml lacre/extractors/amazon.json --domain amazon.com
export PROBE_PK=0x<64 hex chars>
python3 tools/deploy.py contracts/extractor/extractor.py 0x<router> --estimate-only
```

The build keeps the reachable part of `lacre/dkimbody.py` (the fixed Amazon
expressions and `extract_fields` are dropped, since the patterns come from
storage) and all of `lacre/patterns.py`, drops the `from lacre` import the
splice makes redundant and a second `import hashlib` and `import re`, and
strips full-line comments, as the other builds do. It then rewrites
indentation to one space per level and drops blank lines, and refuses the
result unless it parses to the same syntax tree as the input. That step is
new: the request put the source under 13 000 bytes, and with comments
stripped alone the contract was 15 222 bytes. The template and the modules
keep normal indentation and are where the code is read.

Built on 2026-09-28: 12 878 bytes, under the 13 000 byte cap. The node's
estimate for that source (`tools/deploy.py --estimate-only` against Bradbury
with the Router `0xEf37cb72C3A9dD6bCE2f3575B75c94C555F9c8d9` as the
constructor argument, source SHA-256 `f7ab0bb1...59b4c0b1be`) was
11 176 279 gas, 66.6 percent of the 2^24 per-transaction cap. The 870 gas per
byte rule the builds print gives 11 203 860, 66.8 percent.

`genvm-lint lint` passes. `genvm-lint check` reports "No contract class found"
on the validate half for this contract and for the deployed Verifier alike,
so it says nothing about either.

A deploy also needs, after it is FINALIZED: `set_patterns("amazon.com",
<amazon.json>)` from the owner, a check that `patterns_sha256("amazon.com")`
prints what `extract_check.py` printed, and `set_version("extractor", <label>,
<address>)` on the Router. None of that has been done.
