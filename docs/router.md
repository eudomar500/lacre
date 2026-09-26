# Router

The Router is the entry point of the next generation of Lacre contracts. It
maps a name to the address of the contract that currently answers to it, and
does nothing else. It is built and tested and **not deployed**: the Registry
v1 in [docs/registry.md](registry.md) is still what is on chain.

## Why it exists

Registry v1 does two jobs. It routes versions, which should change as rarely
as possible, and it caches DKIM keys, which is where every planned change
lives. With both in one contract, a change to how keys are handled is a new
Registry, and the address every consumer was told to start from moves with
it. The split puts key handling in the [KeyCache](keycache.md) and leaves
routing here, so that a change to key handling or to verification is a new
KeyCache or a new Verifier behind the same Router.

**No address is permanent.** Bradbury cannot upgrade a contract in place, so
any change to any contract, the Router included, is a new deployment at a new
address. The testnet itself may be reset, and mainnet will be deployed from
scratch. The split exists so that changes to key handling or verification do
not force a new entry point, not because the entry point cannot change. The
Router is the piece designed to need redeploying least, which is why it is
kept this small: nothing about keys, DNS, fees or attestations is in it.

## What it stores

One entry per name. The names in use are `keycache` and `verifier`, and
`extractor` is reserved; any other name a later contract needs is accepted.
Names and version labels are normalized the way the Registry normalizes
names: trimmed, lowercased, leading and trailing dots removed, at most 63
characters of `a-z`, `0-9`, `-`, `.` and `_`. Anything else normalizes to the
empty string.

| storage | what it holds |
|---------|---------------|
| `current` | name to the address of the current version |
| `pinned` | `<name>/<label>` to the address that label was applied with |
| `changes` | name to the one pending change: label, address and `proposed_at` |
| `versions` | every applied change, in order, as name, label, address and `set_at` |
| `owner_address`, `pending_owner_address` | the owner and the proposed owner |

`proposed_at` and `set_at` are `gl.message_raw["datetime"]` of the proposing
and the applying transaction, stored unmodified, as the Registry stores
`first_seen`. For the first address of a name, which takes effect at once,
`set_at` is the datetime of the `set_version` call.

## Methods

| method | kind | access | returns |
|--------|------|--------|---------|
| `__init__()` | constructor | deployer | sets `owner` to the deployer |
| `resolve(name: str)` | view | anyone | `str` |
| `resolve_pinned(name: str, version: str)` | view | anyone | `str` |
| `history(name: str)` | view | anyone | `list` |
| `pending(name: str)` | view | anyone | `dict` |
| `set_version(name: str, version_label: str, address: str)` | write | owner | `str` |
| `apply_version(name: str)` | write | anyone | `str` |
| `cancel_version(name: str)` | write | owner | `str` |
| `owner()`, `pending_owner()` | view | anyone | `str` |
| `propose_owner(address: str)` | write | owner | `str` |
| `accept_owner()` | write | pending owner | `str` |

Nothing is payable and there is no fee.

**`resolve(name) -> str`** returns the current address as a hex string, or
`""` for a name that has never been set. A pending change is not
visible here until it is applied.

**`resolve_pinned(name, version) -> str`** returns the address that was
applied under that label, or `""`. A label is bound to one address the first
time it is proposed and applied, and `set_version` refuses to bind it to
another, so what `resolve_pinned` returns for a label never changes once it
returns anything. A consumer that audited a version pins its label and is
unaffected by every later change to the name.

**`history(name) -> list`** returns every applied change for the name, oldest
first, as `{version, address, set_at}`. `set_at` is when the change was
applied, not when it was proposed. Cancelled changes are not in it.

**`pending(name) -> dict`** returns `{}` when nothing is pending, otherwise
`{version, address, proposed_at, effective_at}`. `effective_at` is Unix
seconds, `proposed_at` read as UTC plus the delay: the first moment
`apply_version` succeeds.

**`set_version(name, version_label, address) -> str`** returns the address.
For a name that has never resolved, it sets it at once: `resolve`,
`resolve_pinned` and `history` show it in the same write and nothing is
pending. For a name that already resolves, it records a pending change and
does not change `resolve`.

- Owner only; raises `owner only` otherwise.
- Raises `name is empty or not a name`, `version label is empty or not a
  name` or `not a 20 byte hex address` on bad arguments.
- Raises `a change is already pending` while one is pending for that name.
  The owner cancels first. Only a name that already resolves can have a
  pending change, so this never blocks a first set. Replacing a pending change in place would let the
  owner swap the target late in the announced window.
- Raises `version label already names another address` when the label was
  applied before with a different address. The same label with the same
  address is allowed, which is how a rollback to an audited version keeps
  its label.
- Any 20 byte address is accepted, as on the Registry. Nothing checks that
  the target is a KeyCache or a Verifier.

**`apply_version(name) -> str`** makes the pending change current, records it
under its label and in the history, clears it, and returns the address.
Anyone may call it: once a change has been announced and waited out, it
should not depend on the owner coming back to finish it. Raises `nothing
pending`, or `the delay has not passed` while the runner datetime is earlier
than `effective_at`.

**`cancel_version(name) -> str`** is owner only, clears the pending change
and returns the name. Raises `nothing pending` when there is none. A
cancelled change leaves no trace in `history` and binds no label.

**Ownership.** As on the Registry: `propose_owner(address)` is owner only and
refuses the zero address, `accept_owner()` succeeds only for the proposed
address, which is what proves it can sign, and moves ownership in the same
write. Until then the old owner keeps every power it had.

## The delay

`DELAY` is 48 hours, a constant. It is measured with the runner datetime: a
change proposed at `proposed_at` can be applied by a transaction whose
datetime is at least `proposed_at` plus 172 800 seconds. Fractions of a
second are not read.

The delay is what changes the trust a consumer places in the owner. On
Registry v1 the owner can point `verifier` at any contract at once (see
[interfaces.md](interfaces.md), section 3.4). Here a change is visible in
`pending(name)` for 48 hours before it can take effect, so a consumer that
re-resolves a name has that long to notice a change it does not accept and
stop, and a consumer that does not want to trust the owner at all pins a
label with `resolve_pinned`.

The delay protects changes, not initialization. The first `set_version`
for a name, when no address has been recorded for it yet, takes effect at
once; every later `set_version` for that name records a pending change and
waits the full 48 hours. The delay exists so that a consumer bound to a name
is not moved without notice, and nobody can be bound to a name that has
never resolved: until the first set, `resolve` returns `""` and there is
nothing to follow or pin. Names are independent, so the first set of one
name is immediate even while another name has a change pending.

This is decided by whether the name has a current address, not by whether
the Router is new. A name that once resolved always resolves (nothing
removes an entry from `current`), so after its first set every change to it
waits, rollbacks included. A cancelled pending change never made a name
resolve, and does not count as a first set.

A new Router is therefore usable as soon as it is wired: `set_version` for
`keycache` and `verifier` resolves both in the same transactions. Anyone who
watches the Router sees that wiring in `history`, and every change after it
in `pending` for 48 hours first.

The delay does not cover ownership. A new owner can propose a change as soon
as `accept_owner` lands, and that change still waits the full 48 hours.

## Failure behaviour

Every write that fails an access check or an argument check raises
`gl.vm.UserError` in the deterministic part of the transaction, with a
message starting `[EXPECTED]`. The transaction is reverted and nothing is
stored. None of these writes is payable, so a revert cannot be holding a
sender's value. Every outcome of a write is readable afterwards from a view:
`pending`, `resolve`, `resolve_pinned` and `history` show what a successful
write did, and a failed one changed nothing.

The views never raise. A name or label that normalizes to empty resolves to
`""`, `[]` or `{}`.

## How a consumer resolves the current contracts

From another contract:

```python
router = gl.get_contract_at(Address(ROUTER)).view(state=StorageType.LATEST_FINAL)
verifier = router.resolve("verifier")                # follows every change
audited = router.resolve_pinned("verifier", "1.2")   # never moves
coming = router.pending("verifier")                  # {} or the change and when
```

`LATEST_FINAL` sees only finalized state, which is the right read for a
decision that cannot be replayed. The Verifier itself resolves `keycache`
this way on every call.

Section 5 of [interfaces.md](interfaces.md) still applies: a consumer stores
the Verifier address together with a record id, and reads the record at that
address, never at whatever `resolve("verifier")` returns later.

## Operations

- **Wiring a new Router.** Deploy, then `set_version` for `keycache` and for
  `verifier`. Each is a first set and resolves at once; there is nothing to
  apply. Until `keycache` is set, a Verifier pointed at the Router refuses
  every call with `router resolves no keycache` and refunds it. Because the
  first set skips the delay, the address given to it is worth checking
  before the call: correcting it afterwards is a change and waits 48 hours.
- **Watching.** Whoever runs the gateway reads `pending(name)` for every
  name on a schedule shorter than the delay, and treats a change it did not
  expect as an incident. The Router emits no event: the pending change is
  state, and state is what is read.
- **Replacing the KeyCache or the Verifier.** Deploy the new contract,
  `set_version(name, label, address)`, wait, `apply_version(name)`. The
  Router's address does not change, and a Verifier resolves the new KeyCache
  on its next call.
- **Replacing the Router.** It is a new address, like any other change. The
  Verifier takes the Router address in its constructor, so a new Router
  means a new Verifier too.

## Building, checking and deploying

```bash
python3 contracts/router/build.py            # strips comments, writes router.py
python3 contracts/router/build.py --check
python3 tests/router_stub_run.py             # the whole contract, SDK stubbed, no network
python3 -m pytest -q tests/test_router_keycache_build.py tests/test_verifier_time.py
genvm-lint check contracts/router/router.py
```

`genvm-lint` 0.10.0 passes the lint half and fails the validate half with
`E105 No contract class found` on every Lacre contract, the deployed ones
included: its class finder skips any class named `Contract`, which is the
name this repository uses. The same file with the class renamed validates
cleanly, and the name is kept.

The build inlines nothing from `lacre/`: it drops full-line comments and
keeps the runner Depends line, as the Registry and Verifier builds do. The
template, `contracts/router/router_template.py`, is where the code is read.

Measured on the current build: 6 043 bytes of source, against a build cap
of 8 000. At the 870 gas per byte the builds estimate with, that is
5 257 410 gas, 31.3 percent of the 2^24 transaction cap. The node's own
estimate for this source (`tools/deploy.py --estimate-only`, 2026-09-26,
source SHA-256 `2dc36351...6f166d86`, 6 309 bytes of calldata) is
5 675 496 gas, 33.8 percent: 8 percent above the 870 rule, so on a
contract this small the rule is not an upper bound. The node's estimate is
the figure to go by. `tools/deploy.py` signs at three times the estimate
clamped to 2^24, which here is 2.96 times.

The Router takes no constructor argument. The deployer is the owner.
