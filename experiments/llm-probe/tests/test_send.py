"""experiments/llm-probe/send.py: pulling the reading off a consensus receipt.

The value a write agreed on is not where send.py first looked for it. It is
not on the receipt genlayer-py 0.16.3 builds at all: on Bradbury that receipt
carries tx_data_decoded, which decodes the transaction's input calldata, and
a tx_receipt of "0x", which leaves consensus_data empty. The reading is in
eqBlocksOutputs, field 11 of the V06 tuple ConsensusData.getTransactionData
returns, which the SDK drops on the way to the receipt.

The fixtures below are the bytes of that field, recorded from three real
Bradbury transactions, so the decoding is tested without a network.
"""

import importlib.util
from pathlib import Path

PROBE = Path(__file__).resolve().parents[1]
SEND = PROBE / "send.py"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


send = load(SEND, "probe_send")


def blob(hexadecimal):
    return bytes.fromhex(hexadecimal)


# Recorded from Bradbury. Transaction hashes are in the README table.

# Row 0, extract_strict on 01_shipped. The reading is 20 characters, so its
# calldata header is two bytes.
ROW_0 = blob("df9700a401736869707065643d317c6574613d6a756576657386706164646564")

# Row 2, extract_strict on 02_pending_trap. The reading is 14 characters, so
# its header is the single byte 14 << 3 | 4 = 116, which is "t".
ROW_2 = blob("d8900074736869707065643d307c6574613d86706164646564")

# The deploy of the contract, which runs no non-deterministic block: the
# padding sentinel is the whole list.
DEPLOY = blob("c786706164646564")


def test_a_recorded_write_yields_its_reading():
    assert send.eq_block_values(ROW_0) == ["shipped=1|eta=jueves"]
    assert send.eq_block_values(ROW_2) == ["shipped=0|eta="]


def test_the_reading_carries_no_record_id():
    """The block returns the reading; the method returns "<id> <reading>".

    Only the first of those is on the transaction, so nothing downstream may
    expect to split an id off the front of it.
    """
    value = send.eq_block_values(ROW_0)[0]
    assert value == "shipped=1|eta=jueves"
    assert not value[0].isdigit()


def test_the_header_byte_the_explorer_shows_is_the_calldata_length():
    """Why a 14 character reading reads as "tshipped=0|eta=" on the explorer.

    A calldata string is a header of length << 3 | 4 followed by the bytes.
    At 14 characters that is 116, one byte, and 116 is "t"; at 20 it is 164,
    which LEB128 spreads over two bytes that are not printable ASCII. So the
    explorer prints a leading "t" on the short reading and nothing on the
    long one, and it is the length, not part of the reading.
    """
    assert ROW_2[3:4] == b"t"
    assert (14 << 3 | 4) == ord("t")
    assert ROW_0[3:5] == bytes([164, 1])
    assert (20 << 3 | 4) == 164


def test_the_padding_sentinel_is_not_an_output():
    assert send.eq_block_values(DEPLOY) == []


def test_a_missing_field_is_not_a_failure():
    for absent in (None, b"", bytearray()):
        assert send.eq_block_values(absent) == []


def test_undecodable_bytes_are_not_a_failure():
    assert send.eq_block_values(b"\xff\xff\xff") == []
    # Well formed RLP, but the payload is not calldata.
    assert send.eq_block_values(blob("c4830041ff")) == []


def test_a_result_code_other_than_return_is_skipped():
    """Only code 0 carries a value; a rollback carries a message instead."""
    # One RLP string of code byte 1 and the message "boom".
    rolled_back = blob("c68501" + b"boom".hex())
    assert send.eq_block_values(rolled_back) == []
