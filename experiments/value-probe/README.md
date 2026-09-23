# Value probe (Testnet Bradbury feasibility experiment)

## What this measures

One question, in three parts:

**Can an Intelligent Contract on Bradbury take GEN with a call, hold it, and
send it out to an ordinary wallet?**

1. **In.** A write carrying value on the L2 transaction reaches the contract
   as `gl.message.value`, and the contract's balance goes up by that much.
2. **Held.** The balance is readable from inside, through
   `gl.Contract.balance`, and from outside, through `eth_getBalance` on the
   contract address. The two agree.
3. **Out.** `emit_transfer` on a message to an externally owned account
   actually pays that account, and the contract's balance goes down. This is
   the part the runner source cannot answer, and the reason the probe exists.

If the third part does not hold, Lacre cannot charge for attestations inside
the contract that produces them, and the fee has to sit somewhere else. That
is a product decision, so it is worth one deploy to settle.

## What the pinned runner provides

Read in `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`
and its `py-lib-genlayer-std` dependency, the same runner the DKIM probes
deployed against.

- **Value on a call.** `gl.message.value`, built in `genlayer/gl/__init__.py`
  as `u256(message_raw['value'])`. `u256` is a `NewType` over `int`
  (`genlayer/py/types.py`), so it is a plain integer in the native token's
  smallest unit, wei, with 18 decimals for GEN.
- **Payable methods.** `genlayer/gl/annotations.py` defines
  `gl.public.write.payable`, which sets `__gl_payable__` on the method;
  `genlayer/py/get_schema.py` publishes it as `payable` in the contract
  schema. The runner only marks the method. Whether a call with value to a
  non-payable method is refused is enforced outside the runner, so the probe
  uses `@gl.public.write.payable` on `pay()` and does not test the other case.
- **Own balance.** `_genlayer_wasi.pyi` declares `get_self_balance() -> int`
  and `get_balance(address: bytes) -> int`. They surface as the `balance`
  property on `gl.Contract` and on a contract proxy, both in
  `genlayer/gl/genvm_contracts.py`.
- **Value out.** One mechanism only, in `genvm_contracts.py`: a posted
  message. `gl.get_contract_at(addr).emit_transfer(value=u256(n),
  on="finalized")` sends value with no method call, and
  `.emit(value=u256(n), on=...).method(args)` sends it with one. Both build a
  `PostMessage` gl_call with `address`, `calldata`, `value` and `on`. There is
  no synchronous transfer primitive, and nothing in the runner rejects an
  address that is not a contract: `_ContractAt` only checks that it was handed
  an `Address`.
- **When it settles.** `on` defaults to `"finalized"`, and the SDK warns
  against `"accepted"` for value. The message is executed by the consensus
  contract after the transaction settles, so the balance does not move inside
  the call that posts it.
- **Who executes it.** Not visible in the runner, but the ConsensusMain ABI
  shipped with genlayer-py 0.16.3 carries
  `executeMessage(address recipient, uint256 value, bytes data)`,
  `flushExternalMessages(bytes32 txId)`,
  `getPendingTransactionValue(bytes32 txId)` and the events
  `InternalMessageProcessed(txId, recipient, activator)` and
  `ValueWithdrawalFailed(txId, recipient, uint256 value)`. A value transfer to
  a recipient is therefore a first class operation of the consensus contract,
  and it has a named failure mode. Which of the two an externally owned
  recipient gets is exactly what this probe reports.
- **Value from the client.** `addTransaction` is `payable` in that same ABI,
  and `genlayer_py/contracts/actions.py` `_prepare_transaction` puts the
  caller's `value` on the L2 transaction to ConsensusMain
  (`"value": hex(value)`), not in the calldata. `write_contract(..., value=N)`
  is the library's entry point; `tools/call.py --value <wei>` does the same
  thing through the tools in this repository.

Nothing above is measured. It is what the source says.

## The contract

`contracts/value_probe.py`, deployed as is, with no build step.

| method | kind | what it does |
|--------|------|--------------|
| `pay()` | write, payable | adds `gl.message.value` to a running total and to a per-sender total, returns the value received |
| `total()` | view | every wei ever received |
| `paid_by(address)` | view | what one address has paid |
| `self_balance()` | view | `gl.Contract.balance`, to compare with `eth_getBalance` |
| `owner()` | view | the deployer |
| `withdraw(to, amount)` | write, owner only | posts a transfer of `amount` wei to `to` |

`withdraw` refuses the zero address, a non positive amount and an amount over
the balance, so a failed run says something about the transfer rather than
about the arguments.

## Check it before spending anything

```bash
python3 experiments/value-probe/tests/stub_run.py
genvm-lint experiments/value-probe/contracts/value_probe.py
export PROBE_PK=0x<64 hex chars>
python3 tools/deploy.py experiments/value-probe/contracts/value_probe.py --estimate-only
```

## Run

```bash
export PROBE_PK=0x<64 hex chars>

# 1. deploy
python3 tools/deploy.py experiments/value-probe/contracts/value_probe.py

# 2. pay 0.01 GEN into it
python3 tools/call.py <PROBE> pay --value 10000000000000000

# 3. read it back, from inside and from outside
python3 tools/read.py <PROBE> total
python3 tools/read.py <PROBE> paid_by 0x<your wallet>
python3 tools/read.py <PROBE> self_balance
curl -s -X POST https://rpc-bradbury.genlayer.com \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["<PROBE>","latest"]}'

# 4. send it back out to a wallet
python3 tools/call.py <PROBE> withdraw 0x<your wallet> 10000000000000000

# 5. read the balance again, after the transaction FINALIZES
python3 tools/read.py <PROBE> self_balance
curl -s -X POST https://rpc-bradbury.genlayer.com \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["<PROBE>","latest"]}'
```

Step 5 is the measurement. The transfer is posted `on="finalized"`, so the
balance is expected to be unchanged right after step 4 returns ACCEPTED and to
drop once the transaction is FINALIZED. Watch the consensus transaction on
https://explorer-bradbury.genlayer.com for `InternalMessageProcessed` or
`ValueWithdrawalFailed`, and read the wallet's own balance as the other side
of the answer.

## Results

Run of 22 September 2026 on Testnet Bradbury, contract
`0x22eB139537F8c77043cFF308727A778dFcaDCd33`, wallet
`0xF27E3A6d7Bf4BfC0A837020FD74E73055aF17D53`.

| step | tx | value sent | gas used | contract balance after | result |
|------|----|------------|----------|------------------------|--------|
| deploy | `0x8a13038fa7bc4cbc34af6023bd83f32f7cca75141107231ac8dd4003da9bdcb7` | 0 | 3 404 309 | 0 | deployed at `0x22eB1395...` |
| pay 0.01 GEN | `0x539f006ab312c31ce0aee3b6947fc22f03f0cdeec839872d521b61dd19acad7d` | 10000000000000000 | 824 202 | `0x2386f26fc10000` | value received and recorded |
| read total, self_balance, eth_getBalance | - | 0 | 0 | `0x2386f26fc10000` | all three agree on 10000000000000000 |
| withdraw to wallet | `0xccf0203cdaa5d0596d291570333029eacb1c425e79d0843c6b98923997188bd8` | 0 | - | `0x2386f26fc10000` | FINALIZED 20:00, 5 of 5 AGREE, returned the amount |
| balance one hour after FINALIZED | - | 0 | 0 | `0x2386f26fc10000` | nothing moved, wallet unchanged |

## Findings

1. **Value in works.** A write marked `@gl.public.write.payable`, called with
   value on the L2 transaction, reaches the contract as `gl.message.value` and
   credits the contract's balance. `pay()` recorded 10000000000000000 wei and
   returned it.
2. **The balance is readable from both sides, and they agree.**
   `self_balance()`, which is `gl.Contract.balance` over
   `wasi.get_self_balance`, returned the same number as `eth_getBalance` on
   the contract address, and `total()` matched.
3. **Value out to a wallet does not work on this path, and does not say so.**
   `withdraw()` finalized with 5 of 5 AGREE and FINISHED_WITH_RETURN, and the
   finalize carried two events the pay transaction does not have, one naming
   the wallet as recipient and one from ConsensusMain carrying exactly
   10000000000000000 with a count of 1. No value moved. An hour later the
   contract still held the whole 0.01 GEN, the wallet had not gained a wei,
   `getPendingTransactionValue` was 0, neither `InternalMessageProcessed` nor
   `ValueWithdrawalFailed` was emitted, and a simulated
   `flushExternalMessages` was a no-op with zero logs against a control that
   does return logs. Nothing reports a failure anywhere.
4. **The cause is the path, not the amount or the guard.**
   `gl.get_contract_at(addr).emit_transfer(...)` is the internal message path,
   which the documentation at docs.genlayer.com, features/value-transfers,
   describes as contract to contract. A wallet is an account on the chain
   layer, not an Intelligent Contract, so there is no recipient to activate
   and the message is dropped. The documented internal flow deducts the value
   from the sender as soon as the message is emitted; that did not happen
   either, which is the second tell. Reaching a wallet needs the external
   message path, which is what `experiments/value-probe-2/` measures.

## Status

The contract stays deployed as the record of that behaviour, and the 0.01 GEN
stays in it: there is no path in this contract that can move it, which is the
finding. It is a feasibility probe on a testnet, with no access control beyond
the owner check on `withdraw` and no accounting a real fee split would need,
and it is not something to build on. The working payout is in
`experiments/value-probe-2/`.
