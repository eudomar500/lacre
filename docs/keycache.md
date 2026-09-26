# KeyCache

The KeyCache records what RSA key a domain published under a DKIM selector.
It is the key half of Registry v1, split out so that key handling can change
without moving the entry point, plus a quarantine: a new key waits 24 hours
and is read again before anything can use it. It is built and tested and
**not deployed**; Registry v1 in [docs/registry.md](registry.md) is what holds
keys on chain today. The [Router](router.md) resolves it under the name
`keycache`, and Verifier v1.2 finds it that way on every call.

It starts empty. There is no migration from Registry v1: keys are registered
again, and each one waits out the quarantine.

## Why the quarantine

On Registry v1 whoever calls `register_key` first stores whatever both
resolvers return at that moment, and the key fields never change afterwards.
If both resolvers return the same false record during that one read, for
example during a takeover of the domain's DNS, the attacker's key is
recorded, and it keeps producing valid attestations until the owner retires
it ([interfaces.md](interfaces.md), section 7, "First registration is
permanent").

Here a registration only stores the key as pending. It becomes active only
if a second read, at least 24 hours later, finds the same DER published on
both resolvers again. A takeover then has to be in place at both reads
instead of one, which in practice means holding it across the window, and a
key that only appeared for a moment is discarded. The contract does not
watch DNS between the two reads; it cannot. What the window adds is time:
the owner can retire a pending key that looks wrong before it is ever
usable. The cost is that a new selector can be used only a day after it is
first registered.

## What it stores

`keys` is keyed by `<selector>._domainkey.<domain>`, lowercased, the DNS name
the record was read from, as on the Registry. Each record holds:

| field | meaning |
|-------|---------|
| `domain`, `selector` | normalized as on the Registry |
| `state` | `pending`, `active`, `rotated` or `retired`, see below |
| `n_hex` | the RSA modulus in hex, no `0x` |
| `e` | the public exponent |
| `key_bits` | the modulus size |
| `key_sha256` | SHA-256 over the DER `p=` published, as hex |
| `first_seen` | runner datetime of the registering transaction, unmodified |
| `activated_at` | runner datetime of the confirming transaction; empty while pending |
| `refreshed_at` | runner datetime of the last successful read: the confirmation, or the last `refresh_key` that got an answer; empty while pending |

The key fields, `n_hex` to `key_sha256`, never change after the record is
written. `failures` maps the same key to the last lookup that failed for that
name, as `"<runner datetime> <reason>"`.

### States

| state | how it is reached | usable by the Verifier |
|-------|-------------------|------------------------|
| `pending` | `register_key` | no |
| `active` | `confirm_key` with the same DER on both resolvers | yes |
| `rotated` | `refresh_key` finds a different key published under the name | no |
| `retired` | `refresh_key` finds no key, or `retire_key` by the owner | no |

`pending` moves to `active`, or the record is deleted. `active` moves to
`rotated` or `retired`, and `rotated` to `retired`. Nothing moves back:
retirement is terminal, a rotated key stays rotated if the old key is
published again, and a deleted pending key can only come back through a new
`register_key`, which starts a new quarantine.

## Methods

| method | kind | access | returns |
|--------|------|--------|---------|
| `__init__()` | constructor | deployer | sets `owner` to the deployer |
| `register_key(domain: str, selector: str)` | write | anyone | `str` |
| `confirm_key(domain: str, selector: str)` | write | anyone | `str` |
| `refresh_key(domain: str, selector: str)` | write | anyone | `str` |
| `retire_key(domain: str, selector: str)` | write | owner | `bool` |
| `key_status(domain: str, selector: str)` | view | anyone | `dict` |
| `last_failure(domain: str, selector: str)` | view | anyone | `str` |
| `has_key(domain: str, selector: str)` | view | anyone | `bool` |
| `key_count()` | view | anyone | `int` |
| `owner()`, `pending_owner()` | view | anyone | `str` |
| `propose_owner(address: str)` | write | owner | `str` |
| `accept_owner()` | write | pending owner | `str` |

Nothing is payable and there is no fee.

**`register_key(domain, selector) -> str`**

- Raises `domain or selector is not a name` when either argument normalizes
  to empty.
- On an existing record it reads nothing from DNS and returns `"exists"` for
  an active or rotated key, `"pending"` or `"retired"` otherwise.
- Otherwise it reads both resolvers exactly as Registry v1 does (see
  [Two resolvers](#two-resolvers)) and, when they return the same RSA key,
  stores it as `pending` with `first_seen` set, and returns `"pending"`.
- A lookup that fails stores no key, is written to `last_failure` and
  returned: `resolver unavailable: <host>[, <host>]`, `resolvers disagree`,
  `key revoked or absent` or `key unusable: <ExceptionClass>`. The
  transaction does not revert.

**`confirm_key(domain, selector) -> str`**

- Raises `no pending key` unless the record exists and is `pending`, and
  `the quarantine has not passed` while the runner datetime is less than
  24 hours after `first_seen`. Neither reads DNS.
- Otherwise it re-reads both resolvers. If they agree on a key whose
  `key_sha256` equals the stored one, the record becomes `active`,
  `activated_at` and `refreshed_at` are set, and it returns `"active"`.
- Every other outcome is written to `last_failure` and returned, and the
  transaction does not revert. What happens to the pending record depends on
  whether the resolvers answered:

| outcome at confirm time | returned | pending record |
|-------------------------|----------|----------------|
| both agree on a different key | `key changed during quarantine` | deleted |
| both report no key (NXDOMAIN, no TXT, empty `p=`) | `key revoked or absent` | deleted |
| both answer, with different keys or one with no key | `resolvers disagree` | deleted |
| both answer the same record, which does not decode | `key unusable: <ExceptionClass>` | deleted |
| one or both cannot be read | `resolver unavailable: <host>[, <host>]` | kept, `first_seen` unchanged |

A key that changed is a reason to refuse it; a resolver that did not answer
says nothing about the key. So an answer that is not the key first read
discards the pending record, and it has to be registered again and wait
another 24 hours. An outage leaves the record exactly as it was: still
`pending`, the same `first_seen`, so the quarantine clock does not restart,
and `confirm_key` can be called again at any later time. The retry reads
both resolvers again and follows the same table; nothing is ever activated
without the same DER from both.

"Cannot be read" is the same test the register path uses for `resolver
unavailable` (see [Two resolvers](#two-resolvers)): the request raises, the
HTTP status is not 200, or the DNS status is neither NOERROR nor NXDOMAIN.
When one resolver cannot be read, the other's answer is not acted on, even
if it reports no key or another key: the contract acts on no single
resolver's answer, and that one comes back on the retry, read together with
the other.

This is why the mixed case, one resolver unreachable and the other reporting
no key, is an outage that keeps the pending record rather than a revocation
that discards it. Discarding would mean `fetch_key` returning `key revoked or
absent` on one resolver's answer. `fetch_key` also drives `refresh_key`, which
retires an active key on that same reason, so the change would let a single
resolver retire a key in use while the other was down. `fetch_key` reports
`resolver unavailable` whenever either side cannot be read, before it looks
at the other's answer, and both paths inherit that.

**`refresh_key(domain, selector) -> str`** re-reads an active or rotated key
and never reverts. It returns:

| result | meaning |
|--------|---------|
| `"unchanged"` | DNS still publishes the key whose SHA-256 is `key_sha256`; `refreshed_at` is set |
| `"rotated under same selector"` | DNS publishes a different key under the name; the state becomes `rotated`, the key fields are kept, `refreshed_at` is set |
| `"retired by refresh"` | both resolvers report no key (NXDOMAIN, no TXT record, or an empty `p=`, RFC 6376 3.6.1); the state becomes `retired`, `refreshed_at` is set |
| `"pending"` | the key is still in quarantine; DNS is not read, `confirm_key` settles it |
| `"retired"` | already retired; DNS is not read |
| `"not registered"` | no such record; nothing is stored |
| any lookup failure reason | nothing changes except `last_failure` |

**`retire_key(domain, selector) -> bool`** is owner only, raises `owner
only` or `no such key`, sets the state to `retired` and returns true. It
works on a pending key too, which then can never be confirmed. The record
stays readable.

**`key_status(domain, selector) -> dict`** returns `{}` for an unknown or
discarded record, otherwise every field in the table above, with `e` and
`key_bits` as strings. It is the one read the Verifier makes per call.

**`last_failure(domain, selector) -> str`** returns the last failed lookup
for that name with its datetime, or `""`. It is not cleared by a later
success, so a reader compares its datetime with `first_seen`,
`activated_at` and `refreshed_at`. A pending key whose `last_failure` is a
`resolver unavailable` later than its `first_seen` is waiting for a
`confirm_key` retry.

`has_key` and `key_count` answer existence and count, pending keys
included. There is no enumeration.

**Ownership** moves in two steps exactly as on the Registry.

### Names that changed from Registry v1

- `get_key` is replaced by `key_status`. The v1 shape reports a key as
  usable unless `retired` is true, and cannot express `pending`, so a v1
  consumer reading it here would accept a key still in quarantine. It is
  removed rather than kept as an alias. `retired` and `rotated` are now one
  field, `state`.
- `confirm_key` and `last_failure` are new.
- `register_key` returns `"pending"` where v1 returned `"registered"`.
- `register_key`, `refresh_key`, `retire_key`, `has_key`, `key_count` and the
  ownership methods keep their names and arguments.
- `set_version`, `version`, `all_versions` and `versions_of` are not here;
  routing is the Router's.

## Two resolvers

Unchanged from Registry v1, and the code is the same, `lacre/dkimkey.py`
spliced in by the build. Every lookup asks
`https://dns.google/resolve` and `https://cloudflare-dns.com/dns-query` for
the TXT record with `accept: application/dns-json`, reduces each answer to
the DER its `p=` decodes to, and compares the DER, not the text. The
validators agree under `gl.eq_principle.strict_eq` on the canonical string
`n_hex|e|key_bits|key_sha256|reason`. A resolver that raises, answers with
an HTTP status other than 200, or with a DNS status other than NOERROR or
NXDOMAIN is unavailable. The full description is in
[docs/registry.md](registry.md#two-resolvers).

## Failure behaviour

- Access and argument checks raise `gl.vm.UserError` with an `[EXPECTED]`
  message in the deterministic part, and the transaction stores nothing.
  That covers bad names, owner-only calls, and `confirm_key` on a key that
  is not pending or too early.
- DNS outcomes never raise. They are return values, and since the return
  value of a write cannot be read from the chain ([interfaces.md](interfaces.md),
  section 5, rule 15), each one is also readable from a view: a stored or
  changed record through `key_status`, a failed lookup through
  `last_failure`.
- No write is payable, so no revert can hold a sender's value.

## Operations

- **Registering a sender** is two transactions a day apart:
  `register_key`, then `confirm_key` once `first_seen` is 24 hours old.
  Anyone can send either. The gateway keeps the list of pending names and
  confirms them on schedule; a key nobody confirms stays pending and
  unusable indefinitely. A `resolver unavailable` result from `confirm_key`
  means call it again later; any other failure means the key is gone and
  `register_key` starts over.
- **Refreshing** is as on Registry v1: the gateway calls `refresh_key` for
  every active key on a schedule, since a revocation or a rotation is only
  recorded when someone refreshes. A `resolver unavailable` or `resolvers
  disagree` result means try again on the next run.
- **Keys from Registry v1** are not copied. Each one is registered here
  again and confirmed a day later.
- **Replacing the KeyCache** is a new deployment and a Router change, with
  the Router's 48 hour delay. Keys are registered again on the new one.

## Building, checking and deploying

```bash
python3 contracts/keycache/build.py          # splices lacre/dkimkey.py in
python3 contracts/keycache/build.py --check
python3 tests/keycache_stub_run.py           # the whole contract, SDK stubbed
python3 -m pytest -q tests/test_router_keycache_build.py tests/test_verifier_time.py
genvm-lint check contracts/keycache/keycache.py
```

`tests/keycache_stub_run.py` fetches the live amazon.com key record from both
resolvers once and hands it to the contract through the stubbed fetch, like
the Registry run, so it needs the network; run it before a deploy, not in CI.
`genvm-lint` reports `E105` on the validate half for the reason given in
[docs/router.md](router.md#building-checking-and-deploying).

The build is the Registry build with the names changed: it splices the part
of `lacre/dkimkey.py` the contract reaches (everything but `key_from_tags`)
and drops full-line comments. `unix_time`, which measures the quarantine, is
the Verifier's function; `tests/test_verifier_time.py` checks every copy
against the standard library and holds them to one another.

Measured on the current build: 12 479 bytes of source, against a build cap
of 14 000. At 870 gas per byte that is 10 856 730 gas, 64.7 percent of the
2^24 transaction cap. The node's own estimate for this source
(`tools/deploy.py --estimate-only`, 2026-09-26, source SHA-256
`77e9413a...9743cfa8`, `lacre/dkimkey.py` at `93e04f54...5ce50cda`) is
10 652 847 gas, 63.5 percent, and is the figure to go by. `tools/deploy.py`
signs at three times the estimate clamped to 2^24, which here is 1.57
times. The KeyCache takes no constructor argument, and the deployer is the
owner.
