# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

# Probe C2: the same measurement as probe C, with the payout rewritten to the
# external message path. Probe C sent to a wallet with an internal message,
# which is the contract to contract path, and moved zero wei. A wallet lives
# on the chain layer, so the transfer has to leave through this contract's
# ghost contract instead. See README.md.

from genlayer import *

ZERO_ADDRESS = Address(bytes(20))


# An empty EVM interface is how an address on the chain layer is addressed:
# there is no method to call on a wallet, only value to hand it.
@gl.evm.contract_interface
class _Recipient:
    class View:
        pass

    class Write:
        pass


def as_address(value):
    try:
        return Address(str(value).strip())
    except Exception:
        raise gl.vm.UserError("[EXPECTED] not a 20 byte hex address")


def payer_key(address):
    # as_hex is EIP-55 checksummed, so one address has two spellings. The
    # lower case one is the key, on the write and on the read.
    return address.as_hex.lower()


def require_owner(owner):
    if gl.message.sender_address != owner:
        raise gl.vm.UserError("[EXPECTED] owner only")


class Contract(gl.Contract):
    owner_address: Address
    received: u256
    by_sender: TreeMap[str, u256]

    def __init__(self):
        self.owner_address = gl.message.sender_address
        self.received = u256(0)

    @gl.public.write.payable
    def pay(self) -> str:
        # gl.message.value is the value field of the L2 transaction that
        # carried this call, in wei. The decorator is what makes the call
        # accept value at all: a plain write is not payable.
        amount = int(gl.message.value)
        sender = payer_key(gl.message.sender_address)
        self.received = u256(int(self.received) + amount)
        self.by_sender[sender] = u256(int(self.by_sender.get(sender, u256(0))) + amount)
        return str(amount)

    @gl.public.view
    def total(self) -> int:
        return int(self.received)

    @gl.public.view
    def paid_by(self, address: str) -> int:
        return int(self.by_sender.get(payer_key(as_address(address)), u256(0)))

    @gl.public.view
    def self_balance(self) -> int:
        # wasi.get_self_balance behind gl.Contract.balance. Comparing it with
        # eth_getBalance on the same address is half of what this probe is for.
        return int(self.balance)

    @gl.public.view
    def owner(self) -> str:
        return self.owner_address.as_hex

    @gl.public.write
    def withdraw(self, to: str, amount: int) -> str:
        require_owner(self.owner_address)
        target = as_address(to)
        if target == ZERO_ADDRESS:
            raise gl.vm.UserError("[EXPECTED] the zero address cannot receive")
        wei = int(amount)
        if wei <= 0:
            raise gl.vm.UserError("[EXPECTED] amount must be positive")
        held = int(self.balance)
        if wei > held:
            raise gl.vm.UserError("[EXPECTED] amount exceeds the balance")
        # External message: it goes out through this contract's ghost
        # contract and always executes on finalization, so the balance does
        # not move inside this call and the probe reads it again afterwards.
        _Recipient(target).emit_transfer(value=u256(wei))
        return str(wei)
