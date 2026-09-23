# Registry

The Registry is the one address a consumer has to know. Everything else in
Lacre is reachable from it. It is live on Bradbury; the address and the
transactions behind it are under Deployments below.

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
| `retired` | set once, by the owner, and never cleared in place |

`get_key(domain, selector) -> dict` returns the record or `{}`,
`has_key(domain, selector) -> bool` answers without the payload,
`key_count() -> int` counts the records, and `owner() -> str` returns the
deployer.

## The immutability rule

A key record is written once and mutated exactly once, by `retire_key`.

- `register_key(domain, selector) -> str` is open to anyone: it costs the
  sender the gas and records a fact about a public DNS record. On a record
  that already exists it returns `"exists"`, or `"retired"` if the key was
  retired, and touches nothing either way. A published key does not change
  under its selector, so re-reading DNS could only replace a good record with
  whatever answers today.
- The DNS lookup happens in a non-deterministic block under
  `gl.eq_principle.strict_eq`, over the canonical string
  `n_hex|e|key_bits|key_sha256|reason`. Consensus rides on that string, never
  on the bytes the resolver sent, so a differing TTL or a reordered answer
  cannot break agreement and a genuinely different key can.
- A lookup that fails is an answer, not a failed write: `register_key` stores
  nothing and returns the reason, and the transaction does not revert. The
  reasons are `DoH fetch failed: <ExceptionClass>`, `DoH HTTP <status>`,
  `no key record: <ExceptionClass>`, `key revoked or absent` and
  `key unusable: <ExceptionClass>`. Exceptions are recorded by class name
  only, the convention the probes established.
- `retire_key(domain, selector) -> bool` is owner only and marks the record
  retired. The record stays readable: a consumer has to be able to tell a key
  that was withdrawn from one that was never registered. This is the only
  mutation a key record has, and it is the answer to a compromised or
  withdrawn key.
- Retirement is terminal. There is no path that clears the flag, and
  `register_key` will not re-read DNS for a retired record, so a key that was
  withdrawn once can never be silently reinstated by whoever pays for the next
  write. A sender that rotates its key publishes it under a new selector,
  which is a new record.

Unauthorized writes raise in the deterministic block, which reverts the whole
transaction and leaves no record.

## How a consumer resolves the current contracts

From another contract, through the Registry address:

```python
registry = gl.get_contract_at(Address(REGISTRY))
verifier_address = registry.view().version("verifier")
key = registry.view().get_key("amazon.com", "yg4mwqurec7fkhzutopddd3ytuaqrvuz")
```

`view()` defaults to `LATEST_NON_FINAL`; pass
`state=StorageType.LATEST_FINAL` to read only what has finalized, which is the
right choice for a decision that cannot be replayed.

Off chain, with the tools in `tools/`:

```bash
export PROBE_PK=0x<64 hex chars>
python3 tools/read.py <REGISTRY> version verifier
python3 tools/read.py <REGISTRY> all_versions
python3 tools/read.py <REGISTRY> get_key amazon.com <selector>
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

The deploy, and the first two writes:

```bash
python3 tools/deploy.py contracts/registry/registry.py --network bradbury
python3 tools/call.py <REGISTRY> register_key amazon.com yg4mwqurec7fkhzutopddd3ytuaqrvuz
python3 tools/call.py <REGISTRY> set_version verifier 0x<verifier address>
```

The deployer is the owner: the address behind `PROBE_PK` at deploy time is
what the owner-only writes check against, and it moves only through
`propose_owner` and `accept_owner`. A contract cannot be read until it is
FINALIZED, so the first read after a deploy can fail and say nothing about the
deploy itself.

## Deployments

Bradbury, 22 September 2026. `deployments.json` at the repository root is the
machine-readable copy of this, written by `tools/deploy.py` and tracked in
git; the table here is for reading.

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
