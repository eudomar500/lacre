# Value probe 2 (Testnet Bradbury feasibility experiment)

## What this measures

The same question probe C asked, with the payout rewritten:

**Can an Intelligent Contract on Bradbury take GEN with a call, hold it, and
send it out to an ordinary wallet?**

Probe C settled the first two parts and failed the third. This one changes
exactly one line of the contract, the line that sends, and measures it again.

## The two paths, and which one a wallet needs

GenLayer has two ways for a contract to send value, and they are not
interchangeable.

**Internal message, contract to contract.**
`gl.get_contract_at(addr).emit_transfer(value=u256(n), on="finalized")` posts a
`PostMessage` from inside the VM, addressed to another Intelligent Contract.
The documentation is explicit that this is the Intelligent Contract path, and
that the value is deducted from the sender's balance as soon as the message is
emitted and credited to the recipient when the child transaction activates.

**External message, to an address on the chain layer.** A wallet is not an
Intelligent Contract: it is an account on the chain underneath, so the
transfer has to leave through this contract's ghost contract. That is an
external message, and the way to address it is an empty EVM interface:

```python
@gl.evm.contract_interface
class _Recipient:
    class View:
        pass

    class Write:
        pass

_Recipient(Address(recipient)).emit_transfer(value=v)
```

In the pinned runner this is a different call altogether. The internal path
issues `PostMessage` (`genlayer/gl/genvm_contracts.py`), the external path
issues `EthSend` with empty calldata and the value
(`genlayer/gl/_internal/eth.py`, built by
`genlayer/py/evm/generate.py::contract_generator`). The external form takes
`value` only; there is no `on`, because an external message always executes on
finalization. The documented note is that the syntax borrows the EVM contract
interface even when the recipient is a plain wallet, and that this is expected
to be simplified later.

## Why probe C moved zero wei

Probe C used the internal path against a wallet. Measured on Bradbury, with
contract `0x22eB139537F8c77043cFF308727A778dFcaDCd33` and wallet
`0xF27E3A6d7Bf4BfC0A837020FD74E73055aF17D53`:

- `pay()` with 0.01 GEN worked. The contract's balance went to
  `0x2386f26fc10000` and `gl.message.value` was recorded.
- `withdraw()` (consensus tx
  `0xccf0203cdaa5d0596d291570333029eacb1c425e79d0843c6b98923997188bd8`)
  finalized with 5 of 5 AGREE and FINISHED_WITH_RETURN. The contract body ran
  and returned.
- The finalize (L2 tx
  `0x0e4d7f9feaaa293485176278dcfd7f9909ce42eccc6c6b08e8a1e5281f24e599`)
  emitted two events that the pay transaction does not have: one naming the
  wallet as recipient, and one from ConsensusMain carrying exactly
  10000000000000000 with a count of 1. So the message was recorded.
- Nothing moved. An hour later the contract still held the whole 0.01 GEN,
  the wallet had not gained a wei,
  `getPendingTransactionValue(txId)` was 0, no `InternalMessageProcessed` and
  no `ValueWithdrawalFailed` were emitted, and a simulated
  `flushExternalMessages(txId)` was a no-op with zero logs against a control
  that does return logs.

An internal message to an address that is not an Intelligent Contract has no
recipient to activate. It was accepted, recorded and dropped. The balance was
not even deducted, which is the other half of the tell: the documented
internal flow deducts on emit, and that did not happen either.

## What changed in the contract

`contracts/value_probe2.py` is `../value-probe/contracts/value_probe.py` with
two edits, and nothing else:

1. The empty `_Recipient` EVM interface at module level.
2. In `withdraw`, `gl.get_contract_at(target).emit_transfer(value=u256(wei),
   on="finalized")` became `_Recipient(target).emit_transfer(value=u256(wei))`.

The owner check, the zero address guard, the positive amount guard, the
balance guard, `pay`, `total`, `paid_by`, `self_balance` and `owner` are
unchanged, so a difference in the result is a difference in the send path and
nothing else.

## Check it before spending anything

```bash
python3 experiments/value-probe-2/tests/stub_run.py
genvm-lint experiments/value-probe-2/contracts/value_probe2.py
export PROBE_PK=0x<64 hex chars>
python3 tools/deploy.py experiments/value-probe-2/contracts/value_probe2.py --estimate-only
```

The stub records both paths separately and asserts the external one was taken
and the internal one was not, so a regression to probe C's line fails before a
deploy.

## Run

```bash
export PROBE_PK=0x<64 hex chars>

# 1. deploy
python3 tools/deploy.py experiments/value-probe-2/contracts/value_probe2.py

# 2. pay 0.01 GEN into it
python3 tools/call.py <PROBE2> pay --value 10000000000000000

# 3. read it back, from inside and from outside
python3 tools/read.py <PROBE2> total
python3 tools/read.py <PROBE2> self_balance
curl -s -X POST https://rpc-bradbury.genlayer.com \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["<PROBE2>","latest"]}'

# 4. send it back out to a wallet
python3 tools/call.py <PROBE2> withdraw 0x<your wallet> 10000000000000000

# 5. read both balances again, after the transaction FINALIZES
python3 tools/read.py <PROBE2> self_balance
curl -s -X POST https://rpc-bradbury.genlayer.com \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["<PROBE2>","latest"]}'
curl -s -X POST https://rpc-bradbury.genlayer.com \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["0x<your wallet>","latest"]}'
```

Step 5 is the measurement, and it has to wait for FINALIZED rather than
ACCEPTED. Watch the consensus transaction on
https://explorer-bradbury.genlayer.com and compare the finalize logs with
probe C's: the question is whether this one carries a transfer that executes.

## Results

Run of 22 September 2026 on Testnet Bradbury, contract
`0x28CEC877b187475655847ab2Be6267c8Ca18d8ce`, wallet
`0xF27E3A6d7Bf4BfC0A837020FD74E73055aF17D53`.

| step | tx | value sent | gas used | contract balance after | wallet balance after | result |
|------|----|------------|----------|------------------------|----------------------|--------|
| deploy | `0x0225f66b49d2b7a58db531d1677e57be03dee5a674d1063f9b17fe3acc652069` | 0 | 3 488 257 | 0 | - | deployed at `0x28CEC877...` |
| pay 0.01 GEN | `0xcae4ebbeef241bc1dc3c21b1dc6ffe69a63c66d914718f3969e86fd0a6e9dccf` | 10000000000000000 | 824 202 | 10000000000000000 | - | `self_balance()` is 10000000000000000 |
| read total, self_balance, eth_getBalance | - | 0 | 0 | 10000000000000000 | `0x10b0f8b1045e35e3a` | all three agree |
| withdraw to wallet | `0xfbf66c495398dbb43a7bb0f9a309d4bb342e83d62d88a7b0d44f17d4753e06b0` | 0 | - | 10000000000000000 | `0x10b0f8b1045e35e3a` | ACCEPTED 22:12, balance unmoved at that point |
| balances after FINALIZED | - | 0 | 0 | 0 | `0x10b331202b5a45e3a` | FINALIZED 22:44, wallet up by exactly `0x2386f26fc10000` |

The explorer showed an extra step on this transaction that probe C's withdraw
never had, "Messages on finalization". That step is the payout.

## Findings

1. **The external message path pays a wallet.** The same 0.01 GEN that probe C
   could not move left the contract and arrived: `self_balance()` went from
   10000000000000000 to 0, and the wallet went from `0x10b0f8b1045e35e3a` to
   `0x10b331202b5a45e3a`, a difference of exactly `0x2386f26fc10000` wei. Not
   a rounded amount, not net of a fee: the whole value.
2. **It executes on finalization, not on acceptance.** The write was ACCEPTED
   at 22:12 with the balance still in the contract, and the value moved when
   the transaction FINALIZED at 22:44, about half an hour later. Between those
   two points the contract still reports the full balance, so a caller that
   reads `self_balance()` right after a payout write is reading a number that
   is about to change. Anything that pays out has to treat ACCEPTED as a
   promise and FINALIZED as the settlement.
3. **One line separates the two probes.** The contract is otherwise identical
   to probe C's, guards included. `_Recipient(target).emit_transfer(value=...)`
   through an empty `@gl.evm.contract_interface` works;
   `gl.get_contract_at(target).emit_transfer(...)` moves zero wei with no
   error. The difference is the gl_call underneath, `EthSend` against
   `PostMessage`, and it is invisible in the contract's own result.
4. **Fees in GEN are viable for Lacre.** A contract can charge for its work
   with a payable method, hold the proceeds, and pay them out to a treasury
   address that is configurable rather than compiled in, using the external
   message path. So the Verifier can take a fee per attestation on chain,
   instead of billing off chain or leaving the fee question to a wrapper, as
   long as the payout is treated as settling on finalization and the treasury
   address is owner-controlled the way the Registry's version pointers are.

## Status

A feasibility probe on a testnet, and the second attempt at one question. It
answers that question: the contract has no access control beyond the owner
check on `withdraw`, keeps no accounting a real fee split would need, and is
not something to build on, but the payout line in it is the one a production
contract should copy.
