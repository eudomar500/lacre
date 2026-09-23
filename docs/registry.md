# Registry

The Registry is the one address a consumer has to know. Everything else in
Lacre is reachable from it. This page describes v1, which replaces v0 on
Bradbury before anything was pointed at v0; the addresses and the
transactions behind them are under Deployments below.

## Why it exists

A GenLayer contract cannot be upgraded in place. A fix to the Verifier is a
new deploy at a new address, and any contract or agent that hardcoded the old
address is now pointing at the old code. The Registry is the indirection: it
is deployed once, it never changes, and it answers two questions.

1. Which Verifier and which Extractor are current.
2. What RSA key a domain published under a selector, so that the question is
   settled once for all consumers instead of once per attestation.

The second one is not just caching. A DKIM key lives in DNS, which is outside
consensus: it can be rotated, withdrawn or replaced between two attestations.
Recording the key the first time it is seen, with the SHA-256 of the DER it
published, turns "the signature verified" into "the signature verified against
this exact key", which is a claim that stays true after the record leaves
DNS.

## What it stores

### Version pointers

`versions` maps a name to an address. Two names are in use, `verifier` and
`extractor`; the map takes any other name a later contract needs. Names are
lowercased and are limited to letters, digits, `-`, `.` and `_`.

- `set_version(name, address) -> str` is owner only and returns the stored
  address. It emits no event; the pointer is state, and a consumer that cares
  about the change reads it.
- `version(name) -> str` returns the address, or `""` if the name is unset.
- `all_versions() -> dict` returns every pointer.
- `versions_of(name) -> list` returns every address the name has pointed
  to, oldest first, as `{name, address, set_at}`. `set_at` is the runner's
  transaction datetime, stored unmodified like `first_seen`.

`version` only answers "which one is current". An attestation lives in the
Verifier that wrote it, so a consumer holding an attestation id from an older
Verifier needs the history to find that contract. Every `set_version`
appends one entry, including one that sets the address the name already
has; entries are never removed or edited.

### Ownership

The deployer is the first owner. `set_version`, `retire_key` and
`propose_owner` are the owner-only writes.

Ownership moves in two steps, because the owner is the only account that can
retire a compromised key and a mistyped address would strand that power
forever.

- `propose_owner(address) -> str` is owner only and stores a candidate. The
  zero address is refused, so the proposal cannot be used to clear ownership.
- `accept_owner() -> str` succeeds only for the pending owner, which is what
  proves the address can sign. It moves `owner` and clears `pending_owner` in
  the same write.
- `pending_owner() -> str` returns the candidate, or `""` while none is
  pending.

Until `accept_owner` lands, the old owner keeps every power it had, including
the ability to propose a different address.

### Key records

`keys` is keyed by `<selector>._domainkey.<domain>`, lowercased, which is the
DNS name the record was read from. Each record holds:

| field | meaning |
|-------|---------|
| `domain` | the signing domain, normalized |
| `selector` | the selector, normalized |
| `n_hex` | the RSA modulus in hex, no `0x` |
| `e` | the public exponent |
| `key_bits` | the modulus size, which is what a consumer weighs the signature by |
| `key_sha256` | SHA-256 over the DER `p=` published, as hex |
| `first_seen` | the runner's transaction timestamp for the write, see below |
| `retired` | set once, by the owner or by `refresh_key`, and never cleared |
| `rotated` | set once, by `refresh_key`, and never cleared, see below |

`get_key(domain, selector) -> dict` returns the record or `{}`,
`has_key(domain, selector) -> bool` answers without the payload,
`key_count() -> int` counts the records, and `owner() -> str` returns the
deployer.

## The immutability rule

A key record is written once. Its key fields never change after that; the
only mutations are the two flags, `retired` and `rotated`, which can be set
and never cleared.

- `register_key(domain, selector) -> str` is open to anyone: it costs the
  sender the gas and records a fact about a public DNS record. On a record
  that already exists it returns `"exists"`, or `"retired"` if the key was
  retired, and touches nothing either way. A published key does not change
  under its selector, so re-reading DNS could only replace a good record with
  whatever answers today.
- The DNS lookup happens in a non-deterministic block under
  `gl.eq_principle.strict_eq`, over the canonical string
  `n_hex|e|key_bits|key_sha256|reason`. Consensus rides on that string, never
  on the bytes the resolvers sent, so a differing TTL or a reordered answer
  cannot break agreement and a genuinely different key can.
- A lookup that fails is an answer, not a failed write: `register_key` stores
  nothing and returns the reason, and the transaction does not revert. The
  reasons are `resolver unavailable: <host>[, <host>]`, `resolvers disagree`,
  `key revoked or absent` and `key unusable: <ExceptionClass>`. Exceptions
  are recorded by class name only, the convention the probes established.
- `retire_key(domain, selector) -> bool` is owner only and marks the record
  retired. The record stays readable: a consumer has to be able to tell a key
  that was withdrawn from one that was never registered. It is the answer to
  a compromised key that is still published.
- Retirement is terminal. There is no path that clears the flag, and neither
  `register_key` nor `refresh_key` re-reads DNS for a retired record, so a key
  that was withdrawn once can never be silently reinstated by whoever pays
  for the next write. A sender that rotates its key should publish it under a
  new selector, which is a new record.

### Two resolvers

Every lookup, for `register_key` and for `refresh_key`, asks two public DoH
resolvers for the same name:

- `https://dns.google/resolve?name=<selector>._domainkey.<domain>&type=TXT`
- `https://cloudflare-dns.com/dns-query?name=<selector>._domainkey.<domain>&type=TXT`

both with `Accept: application/dns-json`. The answer counts only when both
agree. One resolver that is wrong, serving stale data or answering for
someone else cannot put a key in the Registry on its own.

- Agreement is on the key, not the text. Each answer is reduced to the DER
  its `p=` decodes to, and the two DER byte strings are compared. Resolvers
  split a long TXT record into character-strings differently and quote them
  differently, so comparing the raw strings would report a disagreement over
  the same key.
- A resolver that raises, answers with an HTTP status other than 200, or
  answers with a DNS status other than NOERROR (0) or NXDOMAIN (3) is
  unavailable, and the reason names it. A SERVFAIL says nothing about the
  record, and reading it as "the key is gone" would let a failing upstream
  retire a key through `refresh_key`.
- NXDOMAIN, an answer with no TXT record, and a record with an empty `p=` are
  all "no key". Both resolvers have to say it for it to count.
- One resolver saying "no key" while the other returns one is a
  disagreement, not a revocation.

Consequence, by design: while either resolver is down or the two disagree,
no new key can be registered and `refresh_key` changes nothing. Keys already
in the Registry are unaffected, since reading a record never touches DNS. A
registration that failed this way can simply be sent again later.

### Refreshing a key

`refresh_key(domain, selector) -> str` is open to anyone, like
`register_key`. It re-reads a registered key through the same two-resolver
path and compares what DNS publishes now with what was recorded.

| result | meaning |
|--------|---------|
| `"unchanged"` | DNS still publishes the key whose SHA-256 is `key_sha256` |
| `"retired by refresh"` | both resolvers say the key is gone: NXDOMAIN, no TXT record, or an empty `p=`, which RFC 6376 3.6.1 defines as revocation. `retired` is set |
| `"rotated under same selector"` | DNS publishes a different key under the same name. The record keeps its key; `rotated` is set |
| `"retired"` | the record was already retired; DNS is not read |
| `"not registered"` | there is no such record; nothing is stored |
| any lookup failure reason | as for `register_key`; nothing changes |

A rotated record is not overwritten, because a signature verified against
the recorded key is still a statement about that key, and replacing it would
change what past attestations mean. `rotated` tells a consumer that the
publisher no longer stands behind the recorded key under this name; whether
to accept new signatures against it is the consumer's decision. A rotated
record can still be retired later, by the owner or by a refresh that finds
the name empty.

Neither flag is ever cleared. A refresh that finds the original key
published again returns `"unchanged"` and leaves `rotated` set, and a
retired record is never refreshed.

`refresh_key` does not revert on any of these outcomes, so a caller can
sweep every registered key in a loop and read the results.

Unauthorized writes raise in the deterministic block, which reverts the whole
transaction and leaves no record.

## Operations

`refresh_key` is meant to be called by the gateway on a schedule, once per
registered key, and not only when a consumer asks. A revocation is only
recorded when someone refreshes the key, so how quickly a withdrawn key
shows up as retired depends on how often the gateway runs the sweep. The
gateway keeps the list of registered `(domain, selector)` pairs itself: the
Registry exposes `key_count` but no enumeration.

Each refresh is a write with two DoH fetches per validator, so the sweep
costs gas per key. A result of `resolver unavailable` or `resolvers
disagree` means the refresh should be retried on the next run, not that
anything is wrong with the key.

## How a consumer resolves the current contracts

From another contract, through the Registry address:

```python
registry = gl.get_contract_at(Address(REGISTRY))
verifier_address = registry.view().version("verifier")
key = registry.view().get_key("amazon.com", "yg4mwqurec7fkhzutopddd3ytuaqrvuz")
history = registry.view().versions_of("verifier")
```

A consumer should check `retired` and `rotated` on every key it uses; the
Verifier checks `retired`.

`view()` defaults to `LATEST_NON_FINAL`; pass
`state=StorageType.LATEST_FINAL` to read only what has finalized, which is the
right choice for a decision that cannot be replayed.

Off chain, with the tools in `tools/`:

```bash
export PROBE_PK=0x<64 hex chars>
python3 tools/read.py <REGISTRY> version verifier
python3 tools/read.py <REGISTRY> all_versions
python3 tools/read.py <REGISTRY> get_key amazon.com <selector>
python3 tools/read.py <REGISTRY> versions_of verifier
python3 tools/call.py <REGISTRY> refresh_key amazon.com <selector>
python3 tools/read.py <REGISTRY> owner
```

## Runner facts this contract depends on

Checked in the pinned runner, `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`,
the id the probes deployed against. The copy read here is the one shipped in
the GenVM v0.2.16 bundle.

- **Sender.** `gl.message.sender_address` is an `Address`. `gl.message` is a
  `NamedTuple` with `contract_address`, `sender_address`, `origin_address`,
  `value` and `chain_id`. The wider `gl.message_raw` dict adds `stack`,
  `datetime`, `is_init` and `entry_kind`.
- **Block height.** There is none. Neither `gl.message` nor `gl.message_raw`
  carries a block number or height, and the SDK exposes no other source, so
  `first_seen` holds `gl.message_raw["datetime"]` instead: the transaction
  timestamp the runner supplies, stored exactly as given, with no parsing and
  no reformatting. It is a timestamp, not a height, so it orders two records
  against each other and nothing more. It is written in the deterministic
  block, which is the half of the transaction every validator executes
  identically, so it should be the same string on all of them. Should is not
  measured: the first live `register_key` is what confirms it, and a
  disagreement would show up as a consensus failure on that write rather than
  as a wrong value in storage.
- **Cross-contract views.** `gl.get_contract_at(address).view().method(args)`,
  with `state=StorageType.LATEST_NON_FINAL` by default or `LATEST_FINAL`, and
  `.lazy(...)` for the deferred form. `gl.contract_interface` declares a typed
  `View`/`Write` pair over the same mechanism. Writes go through
  `.emit(value=..., on="finalized")`, which posts a message rather than
  calling.
- **Web fetch.** `gl.nondet.web.get(url, headers={...})` returns a `Response`
  with `status`, `headers` and `body`. Validators fetch HTTPS on a domain name
  only: plain HTTP, a raw IP or a non standard port is refused inside the
  validator before the request is issued.

## Building, checking and deploying

```bash
python3 contracts/registry/build.py          # splices lacre/dkimkey.py in
python3 -m pytest -q                         # dkimkey against a synthetic key
python3 tests/registry_stub_run.py           # the whole contract, SDK stubbed
genvm-lint contracts/registry/registry.py
export PROBE_PK=0x<64 hex chars>
python3 tools/deploy.py contracts/registry/registry.py --estimate-only --network bradbury
```

`build.py --check` verifies that the committed `registry.py` matches the
template and `dkimkey.py` without writing it.

The build drops two things on the way in, as the Verifier build does:
definitions of `dkimkey.py` the contract never reaches (in v1 that is
`key_from_tags`, which the tests still use) and full-line comments from both
halves. The template and `dkimkey.py` keep their comments; the deployed
`registry.py` carries only the runner Depends line.

The deploy, and the first two writes:

```bash
python3 tools/deploy.py contracts/registry/registry.py --network bradbury
python3 tools/call.py <REGISTRY> register_key amazon.com yg4mwqurec7fkhzutopddd3ytuaqrvuz
python3 tools/call.py <REGISTRY> set_version verifier 0x<verifier address>
```

`tests/registry_stub_run.py` takes an optional path, so a candidate build can
be checked before it replaces `registry.py`.

The deployer is the owner: the address behind `PROBE_PK` at deploy time is
what the owner-only writes check against, and it moves only through
`propose_owner` and `accept_owner`. A contract cannot be read until it is
FINALIZED, so the first read after a deploy can fail and say nothing about the
deploy itself.

## Deployments

`deployments.json` at the repository root is the machine-readable copy of the
current deployment, written by `tools/deploy.py` and tracked in git. It keeps
one entry per contract name, so a redeploy replaces the `registry` entry;
retired addresses are kept here instead.

| version | network | address | status |
|---------|---------|---------|--------|
| v1 | Bradbury | `0x1E1380B71F1C9c622C432B6FD6fa56097B1E4Ddc` | current |
| v0 | Bradbury | `0xd9C6a6A0942490880BfF1405d8746AFC3e55d85e` | retired |

### v1

v1 adds the two-resolver lookup, `refresh_key` with the `rotated` flag, and
`versions_of`. Storage layout changed (a new field on every key record and a
new history list), and a GenLayer contract cannot be upgraded in place, so v1
is a new deploy at a new address. Nothing points at v0 and no Verifier has
been deployed against it, so nothing has to migrate. The one key v0 held is
registered again on v1.

Bradbury, 23 September 2026, from the owner wallet
`0xF27E3A6d7Bf4BfC0A837020FD74E73055aF17D53`.

| field | value |
|-------|-------|
| address | `0x1E1380B71F1C9c622C432B6FD6fa56097B1E4Ddc` |
| deploy consensus tx | `0x88e06a33bfd5c35dabe4ef49bb0cd69a208eed942dca60576bc08bed6e275058` |
| deployed at | `2026-09-23T14:14:11Z` |

The redeploy, and the first writes:

```bash
python3 tools/deploy.py contracts/registry/registry.py --network bradbury
python3 tools/call.py <REGISTRY_V1> register_key amazon.com yg4mwqurec7fkhzutopddd3ytuaqrvuz
python3 tools/read.py <REGISTRY_V1> get_key amazon.com yg4mwqurec7fkhzutopddd3ytuaqrvuz
```

### Version history of `verifier`

Both `set_version` calls below are on v1, on 23 September 2026, from the owner
wallet. They are listed oldest first, which is the order
`versions_of("verifier")` returns them in; `version("verifier")` answers with
the last row only.

| order | address | consensus tx | when |
|-------|---------|--------------|------|
| 1 | `0x74AfE3a7E6D2601bdC9BCC6265d8314F1a74807a` (Verifier v1) | `0x305aec371de532442d1b3367796408e376e3a8d028b29de5792ac81575c9bf1e` | AGREE in 22 s, at Verifier v1 deploy time |
| 2 | `0x9821cfa5fe33a24f9d1D3Cca15885f1a2781EA1d` (Verifier v1.1) | `0x5f594ff01e1c99f1eb95aa2324600ce0b2f04d9d2de1356dfbe8eebb5f82083f` | AGREE in 23 s |

The second call retired Verifier v1 as the current version without removing
it from the history. That is what the history is for: an attestation lives in
the Verifier that wrote it, so a consumer holding a record id from v1 reads
`versions_of("verifier")` to find the address it has to read from. See
[docs/verifier.md](verifier.md).

### v0, retired

Bradbury, 22 September 2026. Superseded by v1 before anything pointed at it.
It stays on chain and readable, but nothing should be pointed at it and its
records are not refreshed.

| field | value |
|-------|-------|
| address | `0xd9C6a6A0942490880BfF1405d8746AFC3e55d85e` |
| deploy consensus tx | `0xf6884c48f915c659362cf1a820d84f89e145f9bbd1062e8ab7f5fa4c40225034` |
| deploy gas | 10 190 630 estimated, 9 577 154 used, 0.0202 GEN |
| consensus | 5 of 5 AGREE, FINALIZED 30 minutes after submission |
| owner | the deploying address; `pending_owner` is empty |

The first key, `register_key("amazon.com",
"yg4mwqurec7fkhzutopddd3ytuaqrvuz")`, consensus tx
`0xd3e4315d6aac2e0ed2ee35253f1a6149d1c6d6c6d6284ff1f330939ad964c197`, 843 309
gas, returned `registered`. `get_key` reads back:

| field | value |
|-------|-------|
| key_bits | 1024 |
| e | 65537 |
| key_sha256 | `bbf3759e9e7f30d0ebd2dbe1e316afa63687820c1a582729114e8466c3ab329c` |
| first_seen | `2026-09-22T22:54:19Z` |
| retired | false |

That `first_seen` reached consensus, which settles the open question in the
runner facts above: the datetime the runner supplies is identical on every
validator, so storing it unmodified is safe. A value that differed between
validators would have failed the write rather than stored something wrong.

## Networks

`tools/chain.py` holds one `NETWORKS` table: RPC URL, chain id, ConsensusMain
address, explorer, faucet and the gas rule, one row per network. Every tool
takes `--network` and defaults to `bradbury`.

`connect()` applies the row to the genlayer-py chain object and then checks
the chain id and the ConsensusMain address the SDK ends up with against the
row, and refuses to sign on a disagreement. The table is meant to be the thing
that is wrong when something is wrong, rather than a comment next to a value
the SDK quietly overrode.

The gas rule, three times the estimate clamped to a per-transaction cap, is
per row, so a network can carry its own cap once one is measured there.
Bradbury's 2^24 is measured; Studio Next carries the same numbers unmeasured.

Each row also carries a mode. Bradbury is `l2`, the path these tools
implement: sign an addTransaction calldata against ConsensusMain and follow
the L2 receipt. Studio Next is `studio`, which serves the Studio RPC API
instead and exposes no ConsensusMain, so `connect()` refuses it until the
Studio client used in carnage is ported here.

A successful deploy appends to `deployments.json` at the repository root:

```json
{
  "bradbury": {
    "registry": {
      "address": "0x...",
      "consensus_tx": "0x...",
      "deployed_at": "2026-09-22T21:33:42+00:00"
    }
  }
}
```

Other networks and other contracts in that file are read back and written out
untouched. Re-deploying the same contract on the same network replaces its own
entry, which is the point of the file: it records where the current one is.
