"""Tests for the coinbase-output encoders/formatters in bitcoin_binary.

Known vectors:
- Genesis block P2PK pubkey -> Satoshi's '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'.
- P2PKH built from the same hash160 -> the same address.
- BIP-173 / BIP-350 segwit witness-program vectors for P2WPKH / P2WSH / P2TR.
- OP_RETURN / nonstandard scripts -> None passthrough.
- Both format_outputs_* conventions on a small synthetic output list.
"""

from __future__ import annotations

import pytest

from stale_blocks_analysis.bitcoin_binary import (
    encode_btc_address,
    canonical_output_token,
    format_outputs_canonical,
    parse_coinbase_tx,
)

# hash160 of the genesis uncompressed pubkey == Satoshi's address payload
SATOSHI_ADDR = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
GENESIS_HASH160 = bytes.fromhex("62e907b15cbf27d5425399ebf6f0fb50ebb88f18")
GENESIS_PUBKEY = bytes.fromhex(
    "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6"
    "49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
)


def _p2pkh(h160: bytes) -> bytes:
    return b"\x76\xa9\x14" + h160 + b"\x88\xac"


def _p2sh(h160: bytes) -> bytes:
    return b"\xa9\x14" + h160 + b"\x87"


def _op_return(payload: bytes = b"\xde\xad\xbe\xef") -> bytes:
    return b"\x6a" + bytes([len(payload)]) + payload


# ---------------------------------------------------------------------------
# encode_btc_address
# ---------------------------------------------------------------------------


def test_p2pkh_genesis_address():
    assert encode_btc_address(_p2pkh(GENESIS_HASH160)) == SATOSHI_ADDR


def test_p2pk_compressed_and_uncompressed():
    # Uncompressed genesis pubkey hashes to the same hash160 -> same address.
    spk = bytes([0x41]) + GENESIS_PUBKEY + bytes([0xAC])
    assert encode_btc_address(spk) == SATOSHI_ADDR


def test_p2sh_prefix_3():
    addr = encode_btc_address(_p2sh(GENESIS_HASH160))
    assert addr is not None and addr.startswith("3")


def test_p2wpkh_bip173_vector():
    prog = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
    spk = b"\x00\x14" + prog
    assert encode_btc_address(spk) == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"


def test_p2wsh_bip173_vector():
    prog = bytes.fromhex(
        "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
    )
    spk = b"\x00\x20" + prog
    assert encode_btc_address(spk) == (
        "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
    )


def test_p2tr_bip350_vector():
    prog = bytes.fromhex(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    spk = b"\x51\x20" + prog  # OP_1 <32>
    addr = encode_btc_address(spk)
    assert addr == "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
    assert addr.startswith("bc1p")


def test_op_return_returns_none():
    assert encode_btc_address(_op_return()) is None


def test_nonstandard_returns_none():
    assert encode_btc_address(b"\x00\x01\x02\x03") is None
    assert encode_btc_address(b"") is None


def test_p2wpkh_distinct_from_p2wsh_witver():
    # v0 20-byte vs v0 32-byte both use bech32 (not bech32m).
    a20 = encode_btc_address(b"\x00\x14" + bytes(20))
    a32 = encode_btc_address(b"\x00\x20" + bytes(32))
    assert a20.startswith("bc1q") and a32.startswith("bc1q")
    assert a20 != a32


# ---------------------------------------------------------------------------
# format_outputs_canonical
# ---------------------------------------------------------------------------

P2PKH_SPK = _p2pkh(GENESIS_HASH160)
OPRET_SPK = bytes.fromhex("6a24aa21a9ed" + "11" * 32)
P2PK_SPK = bytes.fromhex("41" + "04" * 65 + "ac")


def test_format_outputs_canonical_tuple_shape():
    # parse_coinbase() returns (value, spk) tuples with satoshi amounts.
    outs = [(5000000000, P2PKH_SPK), (0, OPRET_SPK)]
    assert format_outputs_canonical(outs) == (
        f"{SATOSHI_ADDR}:5000000000;{OPRET_SPK.hex()}:0"
    )


def test_format_outputs_canonical_spk_dict_shape():
    outs = [{"value": 1, "spk": P2PKH_SPK}, {"value": 2, "pkscript": OPRET_SPK}]
    assert format_outputs_canonical(outs) == (f"{SATOSHI_ADDR}:1;{OPRET_SPK.hex()}:2")


def test_format_outputs_canonical_jsonrpc_uses_script_not_child_address():
    # A merge-mined node decodes the BTC payout into its own address format,
    # so the scriptPubKey hex is authoritative and the amount is BTC.
    outs = [
        {"value": 6.25, "scriptPubKey": {"hex": P2PKH_SPK.hex(), "address": "N1abc"}},
    ]
    assert format_outputs_canonical(outs) == f"{SATOSHI_ADDR}:625000000"


def test_canonical_token_keeps_hex_where_no_address_exists():
    # P2PK has no address form, and collapsing nulldata to a label would
    # discard the segwit witness commitment it carries.
    assert canonical_output_token(P2PK_SPK) == P2PK_SPK.hex()
    assert canonical_output_token(OPRET_SPK) == OPRET_SPK.hex()
    assert canonical_output_token(P2PKH_SPK) == SATOSHI_ADDR


def test_format_outputs_canonical_empty():
    assert format_outputs_canonical([]) == ""


def test_parse_coinbase_tx_returns_scriptsig_and_outputs():
    raw_tx = (
        bytes.fromhex("01000000")
        + b"\x01"
        + b"\x00" * 32
        + bytes.fromhex("ffffffff")
        + b"\x03\xaa\xbb\xcc"
        + bytes.fromhex("ffffffff")
        + b"\x02"
        + (5000000000).to_bytes(8, "little")
        + bytes([len(P2PKH_SPK)])
        + P2PKH_SPK
        + (0).to_bytes(8, "little")
        + bytes([len(OPRET_SPK)])
        + OPRET_SPK
        + bytes.fromhex("00000000")
    )

    parsed = parse_coinbase_tx(raw_tx)

    assert parsed is not None
    assert parsed["scriptsig"].hex() == "aabbcc"
    assert (
        format_outputs_canonical(parsed["outputs"])
        == f"{SATOSHI_ADDR}:5000000000;{OPRET_SPK.hex()}:0"
    )


def test_format_outputs_canonical_preserves_scriptless_slots():
    # An output whose script bytes are unavailable still occupies its slot:
    # dropping it would renumber every later claim. With a value the slot
    # renders amount-only; with neither it renders as an empty gap.
    assert format_outputs_canonical([(7, None), (8, bytes.fromhex("51"))]) == ":7;51:8"
    assert format_outputs_canonical([(None, None), (8, bytes.fromhex("51"))]) == ";51:8"


def test_format_outputs_canonical_rejects_sub_satoshi_amounts():
    # A BTC amount that is not a whole number of satoshis cannot describe a
    # real output; rounding would publish mutated evidence, so the JSON-RPC
    # path fails closed exactly as amount_to_sats() does on the parse side.
    out = {"value": 0.000000006, "scriptPubKey": {"hex": P2PKH_SPK.hex()}}
    with pytest.raises(ValueError, match="satoshi multiple"):
        format_outputs_canonical([out])


def test_format_outputs_canonical_rejects_amounts_above_uint64():
    # The claims parser bounds amounts to uint64; accepting more here would
    # let extraction write a cell that later aborts normalization.
    out = {"value": 184467440737.09551616, "scriptPubKey": {"hex": "51"}}
    with pytest.raises(ValueError, match="uint64"):
        format_outputs_canonical([out])
