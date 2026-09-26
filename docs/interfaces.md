# Lacre interfaces

This is the interface specification of every Lacre layer, written from the
code that is deployed on Testnet Bradbury. Where it and another document
disagree, this one follows the code. Sections 1 to 7 describe what is
deployed. Section 8 describes what is planned and is a proposal only.

The key words MUST, MUST NOT, SHOULD and SHOULD NOT in section 5 are to be
read as described in RFC 2119.

## 1. Layers and the plug-in rule

Lacre is split into layers, and a consumer, whether an agent or a contract,
connects only to the layer that answers its question. No layer requires the
consumer to talk to another one.

| layer | status | what it answers |
|-------|--------|-----------------|
| Registry | deployed, v1 | Which contract is the current Verifier, which contracts have held that name, and what RSA key a domain published under a selector. It is a key cache and a version router. |
| Verifier | deployed, v1.1 | Whether a set of email headers carries a valid DKIM signature from a given domain, and whether the From domain aligns with the signer. It answers "who sent this". |
| Extractors | planned, see section 8 | What a signed body says. They will answer "what does it say". |

Which layer a consumer needs:

- **Who sent this?** The Verifier, through `check_for`. A consumer that
  already holds a Verifier address needs nothing else. It uses the Registry
  only to find that address, or to look up a key's current status.
- **What does it say?** No deployed layer answers this today. A Verifier
  record carries the hooks an Extractor needs (`bh` and `body_canon`, see
  section 4), but the Verifier never reads a body.
- **What key did this domain publish?** The Registry, through `get_key`.

## 2. Deployed contracts

All contracts are on Testnet Bradbury (chain id 4221), deployed from the
owner wallet `0xF27E3A6d7Bf4BfC0A837020FD74E73055aF17D53`. Read from the
chain for this document, that wallet is still the owner of Registry v1 and
of both Verifiers, and the treasury of both Verifiers. `deployments.json` records only the current entry
per contract name. The retired addresses and their transactions come from
[docs/registry.md](registry.md), [docs/verifier.md](verifier.md) and the
chain.

Every contract entry in `deployments.json`, the two value probes aside, carries the commit its source came from and the SHA-256 of the exact source sent on chain, and a reader checks one with `python3 tools/verify_deploy.py <name or address>`, which reads the source back from the deploy transaction without a key and compares it with both (section 8); `verifier_v1` is the one retired contract kept there, for its hash alone, with its commit recorded as unknown.

| layer | version | status | address | deploy consensus tx | date (UTC) |
|-------|---------|--------|---------|---------------------|------------|
| Registry | v1 | current | `0x1E1380B71F1C9c622C432B6FD6fa56097B1E4Ddc` | `0x88e06a33bfd5c35dabe4ef49bb0cd69a208eed942dca60576bc08bed6e275058` | 2026-09-23 14:14 |
| Registry | v0 | retired, nothing points at it | `0xd9C6a6A0942490880BfF1405d8746AFC3e55d85e` | `0xf6884c48f915c659362cf1a820d84f89e145f9bbd1062e8ab7f5fa4c40225034` | 2026-09-22 |
| Verifier | v1.1 | current, `version("verifier")` | `0x9821cfa5fe33a24f9d1D3Cca15885f1a2781EA1d` | `0x8ab6817cf0582fb5579dd3b36fc50a0f56dac4e895c934716e0b04a10e9d021e` | 2026-09-23 16:01 |
| Verifier | v1 | retired by `set_version`, still readable | `0x74AfE3a7E6D2601bdC9BCC6265d8314F1a74807a` | `0x7b214b0f273c5c1b4135a7ed482cbab9b521c373ac88da3e57ba63f2d43132bc` | 2026-09-23 14:17 |

Both Verifiers were deployed with Registry v1 as their constructor argument.

Other transactions an integrator may want to check:

| what | contract | consensus tx | date (UTC) |
|------|----------|--------------|------------|
| First production attestation: record `0`, amazon.com, `source` `url`, `valid` and `aligned` true | Verifier v1 | `0xa7a977399f18291bffe8bd92b67df4735522f7fdd391724fd0b762cd7fa86c1c` | 2026-09-23 14:48:13 |
| `register_key("amazon.com", "yg4mwqurec7fkhzutopddd3ytuaqrvuz")` | Registry v1 | `0x665eaed86082cec0edb334cad710743f38359f63725e34358bbe03f2d8e9ec00` | 2026-09-23 14:15:59 |
| `set_version("verifier", <Verifier v1>)` | Registry v1 | `0x305aec371de532442d1b3367796408e376e3a8d028b29de5792ac81575c9bf1e` | 2026-09-23 14:18:57 |
| `set_version("verifier", <Verifier v1.1>)` | Registry v1 | `0x5f594ff01e1c99f1eb95aa2324600ce0b2f04d9d2de1356dfbe8eebb5f82083f` | 2026-09-23 16:02:30 |

Record 0 on Verifier v1 was read back from the chain for this document. Its
`attested_at` is `2026-09-23T14:48:13Z`, its `key_sha256` is
`bbf3759e9e7f30d0ebd2dbe1e316afa63687820c1a582729114e8466c3ab329c` (a 1024
bit key) and its `requester` is the owner wallet. Verifier v1.1 holds no
records yet.

The source that each current contract was deployed with is byte for byte
`contracts/registry/registry.py` and `contracts/verifier/verifier.py` as of
commit `a56f1c9`. Verifier v1 was deployed from a build that is not in the
repository history.

## 3. Registry v1 interface

Source: `contracts/registry/registry_template.py`, with `lacre/dkimkey.py`
spliced in by `contracts/registry/build.py`. Nothing on the Registry is
payable.

### 3.1 Names

Domains, selectors and version names are normalized before use: surrounding
whitespace is trimmed, the text is lowercased and leading and trailing dots
are removed. The result must be non-empty, at most 253 characters for a
domain and 63 for a selector or a version name, and contain only `a-z`,
`0-9`, `-`, `.` and `_`. Anything else normalizes to the empty string.

A key record is stored under `<selector>._domainkey.<domain>`, the DNS name
it was read from.

### 3.2 What is stored per key

The Registry stores the full RSA public key: the modulus as lowercase hex
(`n_hex`, no `0x`) and the public exponent (`e`). It does not store the DER
bytes or the TXT record. The DER that DNS published is represented only by
its SHA-256 (`key_sha256`). The flags of the DNS key record (`t=`, `h=`,
`s=`) are read but neither stored nor applied.

| field | type | source |
|-------|------|--------|
| `domain` | str | normalized argument |
| `selector` | str | normalized argument |
| `n_hex` | str | modulus decoded from the DER both resolvers returned |
| `e` | u256 | public exponent from the same DER |
| `key_bits` | u256 | bit length of the modulus |
| `key_sha256` | str | SHA-256 of the DER, hex |
| `first_seen` | str | `gl.message_raw["datetime"]` of the registering transaction, stored unmodified |
| `retired` | bool | set by `retire_key` or by `refresh_key`; never cleared |
| `rotated` | bool | set by `refresh_key`; never cleared |

The key fields never change after the record is written. Only the two flags
can change, and only from false to true.

### 3.3 Methods

| method | kind | access | returns |
|--------|------|--------|---------|
| `__init__()` | constructor | deployer | sets `owner` to the deployer |
| `register_key(domain: str, selector: str)` | write | anyone | `str` |
| `refresh_key(domain: str, selector: str)` | write | anyone | `str` |
| `retire_key(domain: str, selector: str)` | write | owner | `bool` |
| `get_key(domain: str, selector: str)` | view | anyone | `dict` |
| `has_key(domain: str, selector: str)` | view | anyone | `bool` |
| `key_count()` | view | anyone | `int` |
| `set_version(name: str, address: str)` | write | owner | `str` |
| `version(name: str)` | view | anyone | `str` |
| `all_versions()` | view | anyone | `dict` |
| `versions_of(name: str)` | view | anyone | `list` |
| `owner()` | view | anyone | `str` |
| `propose_owner(address: str)` | write | owner | `str` |
| `accept_owner()` | write | pending owner | `str` |
| `pending_owner()` | view | anyone | `str` |

A write that fails an access check or an argument check raises
`gl.vm.UserError` in the deterministic part of the transaction. The
transaction is reverted and nothing is stored. The messages all start with
`[EXPECTED]`.

**`register_key(domain, selector) -> str`**

- Raises `domain or selector is not a name` when either argument normalizes
  to empty.
- If a record already exists, returns `"exists"`, or `"retired"` if it is
  retired, and reads nothing from DNS.
- Otherwise each validator asks two DNS-over-HTTPS resolvers,
  `https://dns.google/resolve` and `https://cloudflare-dns.com/dns-query`,
  for the TXT record, with `accept: application/dns-json`. Each answer is
  reduced to the DER its `p=` decodes to. The validators must agree, under
  `gl.eq_principle.strict_eq`, on the canonical string
  `n_hex|e|key_bits|key_sha256|reason`.
- Returns `"registered"` when both resolvers returned the same DER and it
  decodes to an RSA key. Otherwise nothing is stored, the transaction does
  not revert, and the return value is one of:
  - `resolver unavailable: <host>[, <host>]`: a resolver raised, answered
    with an HTTP status other than 200, or with a DNS status other than
    NOERROR (0) or NXDOMAIN (3);
  - `resolvers disagree`: the two DER byte strings differ, including one
    resolver having a key and the other none;
  - `key revoked or absent`: both resolvers report no key (NXDOMAIN, no TXT
    record, or an empty `p=`);
  - `key unusable: <ExceptionClass>`: the record or the DER could not be
    decoded as an RSA key, including `v=` other than `DKIM1` and `k=` other
    than `rsa`.

**`refresh_key(domain, selector) -> str`**

Re-reads a registered key through the same two resolvers and never reverts.
Returns `"not registered"`, `"retired"` (already retired, DNS not read),
`"unchanged"` (same DER hash), `"retired by refresh"` (both resolvers report
no key; `retired` is set), `"rotated under same selector"` (a different key
is published; `rotated` is set and the stored key is kept), or any lookup
failure reason from `register_key` (nothing changes).

**`retire_key(domain, selector) -> bool`**

Owner only; raises `owner only` otherwise, and `no such key` for an unknown
record. Sets `retired` and returns true. The record stays readable.

**`get_key(domain, selector) -> dict`**

Returns `{}` for an unknown record. Otherwise a dict with `domain`,
`selector`, `n_hex`, `e`, `key_bits`, `key_sha256` and `first_seen` as
strings, and `retired` and `rotated` as booleans. `has_key` and `key_count`
answer existence and count. There is no enumeration of registered keys.

**`set_version(name, address) -> str`**

- Owner only; raises `owner only` otherwise.
- Raises `version name is empty or not a name` or `not a 20 byte hex
  address` on bad arguments.
- Any 20 byte address is accepted, including the zero address and an
  address that holds no contract. Nothing checks that the target is a
  Verifier.
- The effect is immediate: `version(name)` returns the new address as soon
  as the transaction is accepted (for readers of non-final state) or
  finalized (for readers of final state). There is no delay, no announcement
  period and no event.
- Every call appends `{name, address, set_at}` to a history that is never
  edited. `set_at` is the runner datetime of the transaction.
- A name cannot be unset.

`version(name)` returns the current address as a hex string, or `""` for an
unset name. `all_versions()` returns every current pointer. On chain today it
holds only `verifier`. `versions_of(name)` returns the history for one name,
oldest first.

**Ownership.** `propose_owner(address)` is owner only and refuses the zero
address (`the zero address cannot be proposed`). `accept_owner()` succeeds
only when sent by the pending owner (`pending owner only` otherwise), moves
ownership and clears the proposal. `owner()` returns the current owner and
`pending_owner()` the candidate or `""`.

### 3.4 Trust assumption created by set_version

A consumer that resolves `version("verifier")` at the moment it decides
trusts the Registry owner for that decision. The owner can point the name at
any contract, including one that answers `check_for` with true for any
input, and the change takes effect at once with no notice. A consumer that
does not want that trust MUST NOT re-resolve the Verifier for a decision. It
pins the Verifier address it has reviewed and calls that address directly.

The owner cannot write or change a key. Keys enter only through
`register_key`, which anyone can call and which takes what both resolvers
publish. The owner can retire any key at once with `retire_key`, and a
retired key is refused by the Verifier for every new attestation. That is a
power to stop attestations for a sender, not to forge them.

## 4. Verifier v1.1 interface

Source: `contracts/verifier/verifier_template.py`, with the reachable part
of `lacre/dkimcore.py` spliced in by `contracts/verifier/build.py`. The
Registry address is fixed in the constructor and cannot be changed.

### 4.1 Methods

| method | kind | access | returns |
|--------|------|--------|---------|
| `__init__(registry: str)` | constructor | deployer | owner and treasury start as the deployer, fee starts at 0 |
| `attest(headers_url: str, domain: str, selector: str)` | write, payable | anyone | `str` |
| `attest_inline(headers_blob: str, domain: str, selector: str)` | write, payable | anyone | `str` |
| `get(id: str)` | view | anyone | `dict` |
| `check_for(id: str, domain: str, min_key_bits: int, requester: str)` | view | anyone | `bool` |
| `count()` | view | anyone | `int` |
| `fee()` | view | anyone | `int`, wei |
| `registry()` | view | anyone | `str` |
| `owner()`, `pending_owner()` | view | anyone | `str` |
| `treasury()`, `pending_treasury()` | view | anyone | `str` |
| `set_fee(new_fee: int)` | write | owner | `str` |
| `propose_owner(address: str)` | write | owner | `str` |
| `accept_owner()` | write | pending owner | `str` |
| `propose_treasury(address: str)` | write | owner | `str` |
| `accept_treasury()` | write | pending treasury | `str` |
| `withdraw(amount: int)` | write | owner | `str` |

### 4.2 attest and attest_inline

Both return a string. It is either a record id, which is always decimal
digits, or a rejection reason. Neither method raises.

**Rejections.** These are checked in this order before any verification
work. Each one stores nothing, returns its reason, and refunds the whole
`gl.message.value` to `gl.message.sender_address` through an external
message that settles when the transaction is FINALIZED.

| reason | condition | method |
|--------|-----------|--------|
| `url not allowed` | the URL, trimmed, does not start with `https://` or is over 512 characters | `attest` |
| `blob too large` | the blob, encoded as UTF-8, is over 16384 bytes | `attest_inline` |
| `fee not paid` | `gl.message.value` is below `fee()` | both |
| `bad domain or selector` | the domain or selector, trimmed, lowercased and stripped of dots, is empty or longer than 253 or 63 characters | both |
| `key not registered` | the Registry, read at `LATEST_FINAL`, has no record for the name, the record is retired, its modulus is not above 1 or its exponent is not above 2, or the read failed | both |

The Verifier checks only length on names. A name with other characters
passes the name check and is then refused as `key not registered`. A key
whose `register_key` transaction is not yet FINALIZED is also refused as
`key not registered`.

**Verification.** Past the rejections the call always writes a record and
keeps the whole value it carried. On `attest` each validator fetches the URL
with `accept: text/plain` and the validators must agree, under
`gl.eq_principle.strict_eq`, on the canonical string
`bh|body_canon|message_id_sha256|valid|reason|from_domain|aligned|signed_at`.
If they do not agree, no record is written in that round and the outcome is
decided by the consensus protocol, not by the contract. On `attest_inline`
the blob is in the calldata and the same function runs without an
equivalence principle.

Signature selection: the contract uses the first DKIM-Signature field whose
`d=` and `s=`, lowercased, equal the normalized domain and selector. The
other signatures are ignored.

`reason` on a record is one of:

| reason | valid |
|--------|-------|
| `header signature verified` | true, the only true reason |
| `RSA PKCS#1 v1.5 check failed` | false |
| `no DKIM-Signature in the blob` | false |
| `signature does not match domain or selector` | false |
| `unsupported DKIM version` (`v=` is not `1`) | false |
| `unsupported algorithm` (`a=` is not `rsa-sha256`) | false |
| `unsupported header canonicalization` (header half of `c=` is not `relaxed`, including an absent `c=`) | false |
| `h= tag is empty` | false |
| `b= tag is not base64` | false |
| `from not signed` (`from` is not in `h=`) | false |
| `duplicate signed header` (a name in `h=` occurs in the blob more often than `h=` lists it) | false |
| `signature expired` (`x=` is present and earlier than `attested_at`; a malformed `x=` reads as 0) | false |
| `blob fetch failed: <ExceptionClass>` | false, `attest` only |
| `blob HTTP <status>` | false, `attest` only |
| `blob too large` (the fetched blob is over 16384 bytes) | false, `attest` only |
| `probe failed: <ExceptionClass>` | false |

The RSA check runs first. Then `from not signed`, `duplicate signed header`
and `signature expired` are checked in that order, and the first that fails
replaces the reason and sets `valid` to false.

Note that `blob too large` is a refunded rejection on `attest_inline` and a
stored, paid record on `attest`.

### 4.3 Fee and refund

- `fee()` is the minimum value, in wei. It started at 0 and is 0 on chain
  today. The owner changes it with `set_fee`, which raises `negative fee`
  for a negative value.
- A call that writes a record keeps the whole value, including any excess
  over `fee()`, and records it in `fee_paid`. A record with `valid` false
  is still paid.
- A rejected call returns the whole value. The refund is paid when the
  transaction is FINALIZED. Until then the contract balance still includes
  it.
- `withdraw(amount)` is owner only, sends to the treasury and nowhere else,
  and raises `amount out of range` for a non-positive amount or one above
  the balance. It settles at FINALIZED. It does not account for refunds
  still in flight.
- Treasury and ownership each move in two steps: `propose_*` (owner only,
  zero address refused) and `accept_*` (only the proposed address).

### 4.4 The record

`get(id)` returns `{}` for an unknown id, otherwise every field below plus
`id`. Booleans are returned as booleans, `requester` as a hex address, and
every other field as a string. Ids are `"0"`, `"1"`, ... in the order
records were written. They are local to one Verifier contract.

| field | type | where it comes from |
|-------|------|---------------------|
| `domain` | str | the call's domain after normalization. When a signature was selected it equals that signature's `d=` |
| `selector` | str | the call's selector after normalization |
| `bh` | str | the selected signature's `bh=` tag with whitespace removed, as the signer claimed it. Not recomputed. Empty when no signature was selected |
| `body_canon` | str | the body half of the selected signature's `c=` tag, lowercased, `simple` when absent. Taken from the signed tag and not checked to be `simple` or `relaxed`. Empty when no signature was selected |
| `message_id_sha256` | str | SHA-256, hex, of the first Message-ID field in the blob, unfolded and trimmed. Empty if there is none. The Message-ID is not required to be in `h=`, so it may be unsigned |
| `key_bits` | u256 | `key_bits` of the Registry record at attestation time |
| `key_sha256` | str | `key_sha256` of the Registry record at attestation time |
| `valid` | bool | see 4.2 |
| `reason` | str | see 4.2, at most 96 characters |
| `from_domain` | str | domain part of the From address, lowercased, trailing dot removed. Empty unless the blob has exactly one From field and the address is unambiguous (quoted display names removed, at most one `@` and one `<`) |
| `aligned` | bool | `from_domain` is non-empty and equals the signing domain, or one ends with `.` followed by the other. No public suffix list is applied |
| `signed_at` | u256 | the signature's `t=` tag. 0 when absent, not ASCII digits, or 20 or more characters |
| `source` | str | `url` or `inline` |
| `requester` | Address | `gl.message.sender_address` of the attesting transaction |
| `attested_at` | str | `gl.message_raw["datetime"]` of the attesting transaction, unmodified, for example `2026-09-23T14:48:13Z` |
| `fee_paid` | u256 | the whole `gl.message.value` of the attesting transaction, in wei |

Every string field taken from the blob has `|`, CR and LF replaced by a
space and is truncated (255 characters for `bh`, 63 for `body_canon`, 253
for `from_domain`).

### 4.5 check_for

`check_for(id, domain, min_key_bits, requester) -> bool` is true only when
all of these hold:

- a record with that id exists on this contract;
- `valid` is true;
- `aligned` is true;
- the record's `domain` equals `domain` after the same normalization;
- `key_bits` is at least `min_key_bits`;
- the record's `requester` equals `requester`, compared as addresses.

A malformed `requester` returns false instead of raising. `check_for` does
not look at `source`, `signed_at`, `message_id_sha256`, the key's current
Registry status, or whether the record has been used before.

### 4.6 What valid=true guarantees

`valid` true, together with the record's `domain` and `selector`, means all
of the following were true when the record was written:

- the headers contained a DKIM-Signature with that `d=` and `s=`, `v=1` and
  `a=rsa-sha256`, relaxed header canonicalization, and a non-empty `h=` that
  lists `from`;
- that signature verified under RSA PKCS#1 v1.5 with SHA-256 against the key
  the Registry held, finalized and not retired, for that domain and
  selector. `key_sha256` identifies that key;
- no header name in `h=` appeared in the blob more times than `h=` lists it;
- the signature had no `x=`, or its `x=` was not earlier than `attested_at`.

### 4.7 What valid=true does not guarantee

- **The body.** The Verifier never sees a body. `bh` is the hash the signer
  claimed, and only a party holding the body can check it, by
  canonicalizing it with `body_canon` and hashing it.
- **The whole body, when `l=` is present.** An `l=` tag is neither rejected
  nor recorded. A signature with `l=` covers only a prefix of the body, and
  a record cannot tell such a signature from one without it.
- **Any algorithm but rsa-sha256.** Ed25519 and rsa-sha1 signatures, and
  simple header canonicalization, produce `valid` false.
- **Alignment.** `valid` can be true with `aligned` false: a correctly
  signed message whose From domain is unrelated to the signer. Alignment is
  a plain suffix relation, not DMARC. No DMARC or SPF policy is read, the
  signature's `i=` is not checked, and the key record's `t=` flags are
  ignored.
- **Key strength.** Any RSA key is accepted. 1024 bit keys are in use (the
  amazon.com key is one). The consumer sets the floor with `min_key_bits`.
- **Who received the message.** `requester` is whoever sent the attesting
  transaction. Anyone holding a copy of the signed headers can attest them
  as their own requester.
- **Uniqueness.** The same message can be attested any number of times, by
  one requester or several, and each call writes a new record.
- **The Message-ID.** It may be unsigned, so `message_id_sha256` can be set
  by whoever submits the blob unless Message-ID is in `h=`, and the record
  does not say whether it was.
- **Current key status.** A key retired or marked `rotated` after the record
  was written does not change the record.
- **The signing time.** `signed_at` is whatever the signer put in `t=`. A
  `t=` in the future is not rejected.

## 5. Rules for integrators

1. A consumer MUST NOT release goods or money on an attestation until the
   attesting transaction is FINALIZED. An ACCEPTED transaction can still be
   appealed and its result changed. A contract meets this rule by reading
   the Verifier with `state=StorageType.LATEST_FINAL`, which only sees
   finalized records. A front end that shows a result before FINALIZED MUST
   show it as provisional.
2. A consumer MUST gate on `valid` and `aligned` both being true. The
   existence of a record, or an `attest` return value made of digits, means
   only that the check ran. It says nothing about the verdict.
3. A consumer MUST check the sender domain, the minimum key size and the
   requester through `check_for`, and SHOULD NOT read the raw fields from
   `get` and compare them itself.
4. A consumer MUST store the Verifier address together with the record id.
   Ids start at `"0"` on every Verifier, so an id resolved against a later
   Verifier names a different record, or none.
5. A consumer that pays out once per message MUST keep its own record of
   what it has already paid for. The Verifier does not prevent the same
   message from being attested again. It SHOULD key that record on signed
   values (`domain`, `selector`, `bh`, `signed_at`) and SHOULD NOT rely on
   `message_id_sha256` alone, which may be unsigned.
6. A consumer MUST NOT read `requester` as proof that the requester
   received the message. It proves only who paid for the check.
7. A consumer that needs the body to say something MUST verify the body
   itself against `bh` and `body_canon`, or wait for an Extractor. A `valid`
   record makes no statement about the body.
8. A consumer that releases goods or money on an attestation MUST read the
   key's current status from the Registry (`retired`, `rotated`) at
   decision time. Other consumers SHOULD. A record keeps the key it was
   checked against, and neither flag changes it after it is written (see
   section 7, first registration is permanent).
9. A caller of `attest` or `attest_inline` SHOULD send exactly `fee()` and
   MUST treat a return value that is not all digits as a rejection whose
   refund arrives at FINALIZED. On Verifier v1.1 that return value cannot
   be read from the chain (rule 15), so a caller learns of a rejection the
   way rule 15 describes.
10. **An attestation exists only as a record.** An attestation exists only
    when its record can be read from the Verifier at `LATEST_FINAL`. A
    transaction status, the explorer's "Return Value" or an
    `eqBlocksOutputs` reading is not proof that state was written: probe D2
    call 36 FINALIZED with result TIMEOUT and its reading visible in
    `eqBlocksOutputs`, and wrote no record
    ([experiments/llm-probe-2](../experiments/llm-probe-2/README.md),
    Findings, "Call 36"; the incident run of the same day had two FINALIZED
    AGREE transactions that left no record either). Consumers MUST decide on
    the record. A missing record is "no attestation", whatever the
    transaction shows.
11. **Executed means three things at once.** A call executed only when its
    stored status is ACCEPTED or FINALIZED, its result is AGREE (or
    MAJORITY_AGREE), and its execution result is FINISHED_WITH_RETURN
    (`executed()` in `tools/txstate.py`). None of the three alone is enough:
    GenLayer's documentation says an Accepted receipt "can represent a
    successful return, a user error, a GenVM error, or a timeout", and that
    Finalized "does not convert an error result into a successful contract
    call"
    ([transaction statuses](https://docs.genlayer.com/understand-genlayer-protocol/core-concepts/transactions/transaction-statuses)).
    A client that sends attestations MUST apply the confirmation protocol of
    `tools/attest.py`: send, wait for FINALIZED on the stored status, read
    the record, and send again only after a finalization without execution
    (or an executed finalization whose record cannot be read at
    `LATEST_FINAL`). It MUST NOT send again while an appeal is in progress,
    while the transaction is CANCELED, or while it is undecided. Sending
    again can, in the worst case, produce two records for one attestation;
    both are valid records (rule 4 and rule 5 already key on record ids and
    on signed values).
12. **Value on calls that do not execute.** On Bradbury (consensus v0.5,
    commit `9c68608`, which has no consensus fee budget) the value of a call
    that finalizes without executing (UNDETERMINED, VALIDATORS_TIMEOUT or
    LEADER_TIMEOUT) is refunded in full to the sender inside the
    finalization transaction. Only the L2 gas of the submission is lost.
    This was read from the chain on 24 September 2026 on 8 paid,
    non-executed transactions from other senders, for example the two 20 GEN
    LEADER_TIMEOUT refunds in L2 blocks 21486001 and 21487655, where the
    finalization is the only transaction in the block. A refusal by the
    Verifier is different: it executes, and the Verifier returns the value
    by its own message (section 4.2). The value of every activated call
    moves into the Verifier's balance at activation, so between activation
    and finalization that balance includes value of transactions that may
    never execute. The owner MUST NOT withdraw the whole balance (see
    [docs/verifier.md](verifier.md), Operations). A sender MUST be able to
    receive GEN: the protocol's refund path has an event,
    `ValueWithdrawalFailed(txId, recipient, value)`, for a transfer that
    fails, and where the value goes after it was not verified. All 8
    senders observed were externally owned accounts.
13. **One call at a time per contract.** Transactions to one contract are
    processed one at a time: ConsensusMain does not activate a transaction
    while an earlier one to the same contract is undecided, and queues it
    instead (it emits CreatedTransaction rather than NewTransaction). The
    queue holds 20 transactions per contract, and beyond that a send reverts
    with PendingQueueFull (probe D2, "Incident on 24 September"). When the
    network is healthy that is about one decided call per minute; in probe
    D2's clean run, on a degraded network, windows of ten calls took 24 to
    31 minutes. Clients MUST NOT send a second call to the same contract
    before the first is decided. A gateway serving many agents SHOULD
    expect roughly 1,400 attestations per day per Verifier at best, and
    SHOULD plan for several Verifiers behind the Registry.
14. **Status semantics.** A stored CANCELED is not final: in the probe D2
    incident, queued transactions stored as CANCELED were later activated
    and FINALIZED. The timestamped views (`getTransactionData`,
    `getTransactionStatus`) also report a queued transaction as CANCELED
    from 1800 s after its creation while its stored status is still PENDING,
    and can report a status number the SDK does not know: 14 was returned on
    16 of probe D2's calls, and genlayer-py 0.16.3 fails on it with a
    KeyError. Status 11 (READY_TO_FINALIZE in the SDK) has not been seen on
    Bradbury. Status 12 is named VALIDATORS_TIMEOUT by the SDK but was never
    returned for a Lacre transaction; it appears on Bradbury only as the
    previous status of other senders' finalizations, and its name is not
    confirmed by source. Status 13 is LEADER_TIMEOUT (probe D2 call 36). A
    DETERMINISTIC_VIOLATION vote in the final round is how a validator's
    disagreement with the leader's reading is recorded, not a fault in the
    contract: every such vote in probe D2 came from a validator whose result
    hash differed from the leader's, on a contested reading. Clients SHOULD
    read the stored status through the consensus contracts
    (`ConsensusData.getTransactionAllData`, as `tools/txstate.py` does) and
    SHOULD treat a status number they do not know as undecided.
15. **Every outcome of a write must be a view.** The return value of a write
    call cannot be read from the chain: `eqBlocksOutputs` holds only the
    output of the non-deterministic block, and `attest_inline` has none, so
    neither a record id nor a refusal reason is available after the fact.
    Every outcome of a write MUST therefore be exposed by a view. On
    Verifier v1.1, `tools/attest.py` copes by reading `count()` before the
    first attempt and scanning the records written since for one whose
    `requester`, `domain`, `selector`, `source` and `fee_paid` match the
    call, and, when there is none, by deriving the refusal reason from
    running the Verifier's own checks read-only, in the Verifier's order.
    The planned Verifier v1.2 adds `records_of(requester)` and
    `last_refusal(requester)` for this (section 8).

## 6. Evidence and verdict

The principle is minimal evidence and a public verdict. The record is
public: anyone can read every field of it, forever. The email is not stored.
No body, no header value and no address is written to contract storage,
only the fields in section 4.4, of which `from_domain` is the only one taken
from a header value, and `message_id_sha256` is a digest.

What remains on chain besides the record depends on the path:

- **`attest_inline`** puts the signed headers in the calldata of the
  transaction, which is public and permanent. To, Subject and every other
  header the blob carries can be read by anyone. In exchange, anyone can
  re-verify the signature at any time, from the calldata and the key the
  Registry recorded (`n_hex`, `e`), without trusting the validators.
- **`attest`** puts only the URL, the domain and the selector in calldata.
  The blob is meant to be served until the transaction is FINALIZED and then
  deleted. After that, a third party cannot re-verify the signature. What
  remains is the record and the fact that the validators agreed on it. The
  URL is public in calldata from the moment the transaction is submitted, so
  anyone who reads the chain can fetch the headers while they are served.

### 6.1 The model-reading lane (measured, not deployed)

No model-reading lane is deployed. Probe D2
([experiments/llm-probe-2](../experiments/llm-probe-2/README.md)), run on
Bradbury on 24 September 2026, measured the design it will use:

- **The hardened prompt builder**, `llm/prompt.py` in the probe, as it is:
  the body is sanitized, placed between markers tagged with a hash of the
  body, quoted as one JSON string, and surrounded by the rules on both
  sides. 40 of 40 final readings were correct on `shipped` and `eta`,
  including the delimiter attack that fooled every validator in probe D (4
  of 4 refused).
- **Strict equality on `shipped` and `eta` only.** The injection question
  is asked but kept out of the compared value: comparing it caught nothing
  the reading did not, and the calls that compared it drew 8
  DETERMINISTIC_VIOLATION votes in 30 against 1 in 10.
- **A deterministic prefilter in front of the model**, `llm/prefilter.py`.
  Measured locally, it flags 6 of the 8 attack bodies and neither ordinary
  body, so it sits in front of the builder and does not replace it.
- **The record carries the method** that produced the reading, and the
  consumer decides on the record, not on the transaction (section 5, rule
  10).

## 7. Known limits

- **`l=` signatures.** Not rejected and not recorded (section 4.7). A
  consumer checking a body against `bh` cannot tell that the signature
  covered only part of it.
- **Prompt injection against a model-reading lane.** Measured in
  [experiments/llm-probe](../experiments/llm-probe/README.md): a body that
  closed the prompt's delimiter early and planted its own instructions
  changed the reading in both equivalence modes, and all validators agreed
  on the wrong answer (5 of 5 AGREE in strict mode). Consensus does not
  protect against an attack that works on every validator's model. No
  model-reading lane is deployed.
- **Validator timeouts.** In the same probe, 6 of 50 final-round validator
  votes were TIMEOUT, three of ten transactions took extra rounds, and one
  took 175 seconds to reach ACCEPTED. A timeout is not a disagreement, but
  it delays acceptance.
- **The admin key and set_version.** One owner key controls the Registry
  pointer, with immediate effect and no delay (section 3.4), and can retire
  any key. The same key sets the Verifier fee and withdraws its balance.
- **Public calldata on the inline path.** Every header in the blob is public
  permanently. The URL path puts the URL in public calldata as well.
- **No body verification in any deployed layer.** Section 4.7.
- **First registration is permanent.** Whoever calls `register_key` first
  for a selector stores whatever both resolvers return at that moment, and
  the key fields never change afterwards. The precondition for an attack is
  that both resolvers return the same false record, for example during a
  takeover of the domain's DNS. If that happens during one registration, the
  attacker's key is recorded. A later `refresh_key` that sees the real key
  again only sets `rotated`, and the Verifier ignores `rotated`, so the
  attacker's key keeps producing valid records until the owner calls
  `retire_key`. Two proposals in section 8 address this: the registration
  quarantine in Registry v2 and refusing rotated keys in Verifier v1.2.
- **Alignment in the parent direction.** `aligned` is true when the signing
  domain ends with `.` followed by `from_domain`, and no public suffix list
  is applied. A message with `From: x@co.uk` signed with `d=anything.co.uk`
  is therefore aligned, with `from_domain` `co.uk`. `check_for` is safe
  against this, because it requires the consumer's domain to equal the
  signing domain, so a consumer that asks about `co.uk` gets false. A
  consumer that reads `from_domain` from `get()` and decides on it is not
  safe.
- **`body_canon` is not validated.** Whatever follows the slash in the
  signed `c=` tag is recorded, up to 63 characters, and a record can be
  valid with a value that is neither `simple` nor `relaxed`. A consumer or
  Extractor that checks a body against `bh` MUST refuse any `body_canon`
  other than `simple` or `relaxed`.
- **`message_id_sha256` and non-ASCII.** The Message-ID is decoded as
  latin-1 and re-encoded as UTF-8 before it is hashed, so for a Message-ID
  with non-ASCII bytes the digest is not the SHA-256 of the raw bytes, and an
  off-chain recomputation has to do the same.
- **One Verifier per Registry, fixed.** A Verifier reads keys from the
  Registry it was deployed with, for its whole life.
- **Inline blobs are text.** `attest_inline` encodes its argument as UTF-8,
  so headers with raw 8-bit bytes cannot be carried inline without breaking
  the signature. They have to go through `attest`.
- **Throughput.** One call at a time per contract, about one a minute on a
  healthy network, and at most 20 queued behind it (section 5, rule 13).
  One Verifier serves roughly 1,400 attestations a day at best.
- **Status semantics.** A stored CANCELED is not final, the timestamped
  views report CANCELED early and return numbers the SDK cannot name (14),
  11 and 12 are unconfirmed on Bradbury, and DETERMINISTIC_VIOLATION is a
  disagreement vote, not a contract fault (section 5, rule 14).
- **Return values of writes are not readable.** Neither the record id nor
  the refusal reason of an `attest` call can be read from the chain after
  the fact, so on Verifier v1.1 a client has to find its record by scanning
  and derive a refusal by rerunning the checks (section 5, rule 15).
- **The refund of non-executed calls is silent and undocumented.** The
  protocol returns the value of a call that finalizes without executing
  inside the finalization transaction, but the refund emits no event of its
  own and no public source or documentation describes it for Bradbury's
  consensus v0.5. It was verified on 8 transactions from other senders,
  from balances read at the finalization blocks (section 5, rule 12).

## 8. Planned, not deployed

Every item in this section is a proposal, except the last one, deploy
provenance, which is tooling and is in place. None of it is deployed, and all
of the proposals are subject to change.

- **Registry v2 (proposal).**
  - Pinned versions: a consumer can call a specific Verifier version by a
    stable reference, unaffected by any later `set_version`.
  - A mandatory delay before a `set_version` takes effect. The pending change
    is announced on chain when it is proposed, so consumers can see it
    coming and react before it applies.
  - Registration quarantine. `register_key` stores a new key as pending,
    not usable by the Verifier. After a fixed delay, proposed as 24 hours
    and measured with the runner datetime against `first_seen`, anyone can
    call a confirmation that re-reads both resolvers. The key becomes active
    only if the same DER is still published, and is discarded otherwise.
    Rationale: a DNS takeover then has to fool both resolvers for the whole
    delay, not for one read. Cost: a new selector can be used only after the
    delay.
- **Verifier v1.2 (proposal).**
  - Reject signatures that carry `l=`, with a refund like every other
    rejection.
  - A schema version field in every record.
  - Refuse keys marked `rotated` in the Registry, with a refund, the same
    way retired keys are refused. Rationale: reusing a selector for a new
    key goes against recommended DKIM practice, so legitimate old mail lost
    this way should be rare, and a suspicious key stops working as soon as
    anyone calls `refresh_key`. Cost: mail signed with the previous key
    under a reused selector can no longer be attested.
  - `records_of(requester)`, the ids of the records a requester's calls
    wrote, and `last_refusal(requester)`, the reason of that requester's
    last refused call. Rationale: the return value of a write cannot be
    read from the chain (section 5, rule 15), so every outcome needs a
    view.
- **Pre-paid balances: not planned for Bradbury.** The per-call value model
  is kept, because the protocol already refunds the value of calls that do
  not execute (section 5, rule 12). Pre-paid balances are a study item for
  mainnet, to be revisited if mainnet runs consensus v0.6 with a fee
  budget.
- **Extractors (proposal).** Two separate Extractor contracts, one using
  patterns and one reading with a model, each behind its own selector, so
  that a flaw in one cannot affect the other. Each record says which method
  produced it.
- **Build provenance (proposal).** The library version and hash recorded for
  every deployment.
- **Deploy provenance (in place).** `tools/deploy.py` checks the working
  tree before it reads the key or touches the network. It refuses to deploy,
  and prints what is wrong, when a tracked file has uncommitted changes, when
  an untracked file sits under `contracts/`, `lacre/` or the source path,
  when git does not track the source, or when the artifact is not what the
  `build.py` beside it produces now. `--allow-dirty` deploys anyway, for
  probes, and the entry then says `commit_dirty: true`. Each new entry
  records `commit` (the full sha), `commit_dirty`, `source_path`,
  `source_sha256` and `source_size` of the exact bytes sent, which is the
  built artifact and not the template, and `inlined_modules`, the SHA-256 of
  every `lacre/` module the build inlined, by file name. The same facts are
  printed before the deploy proceeds, so they are in the deploy log.
  `tools/verify_deploy.py` takes a contract name or an address from
  `deployments.json`, is read-only and needs no key. It reads the stored
  deploy transaction from ConsensusData, takes the source out of its
  calldata, and compares its SHA-256 with the recorded address, hash and
  size, with the file and with the build at the recorded commit, and checks
  the recorded module hashes against that commit. It prints match, MISMATCH
  or cannot check for each item and exits 1 on any mismatch. For an entry
  with no commit it lists the checks it cannot make and compares the chain
  bytes with the current build instead. Every contract so far was deployed
  before the commit that contains it, so the existing entries were
  backfilled on 2026-09-26 with what could be proven, and say so: the
  deployed bytes of Registry v1 and Verifier v1.1 equal the build at commit
  `a56f1c9`, which they record with the module hashes at that commit, and
  Verifier v1, whose build is not in the repository history, records only
  the SHA-256 of its deployed source, as `verifier_v1`, with the commit
  unknown. The value probes' entries are unchanged.

## 9. Related work

**ZK Email** (Ethereum). The user generates a zero-knowledge proof off
chain, and a contract verifies it against a DKIM key registry. Keys in that
registry are maintained by a manager, by oracles or by governance. Each
email type needs its own circuit, with its own regular expressions. The
content of the email stays private. It has production applications.

**XION.** A protocol-level DKIM key registry paired with a ZK module, on
testnet in 2026.

**Lacre.** Validators verify the signature directly. Keys are fetched by
validator consensus from two DNS-over-HTTPS resolvers and recorded
permanently, with no administrator in the path that writes a key. New
senders are added as data, not as circuits. Validators can interpret
content. Lacre gives up privacy toward validators, which ZK Email keeps, and
it is far less mature.

The value-refund and confirmation rules of section 5 (rules 10 to 14) are
network behaviour that any GenLayer contract inherits, not Lacre-specific
design.
