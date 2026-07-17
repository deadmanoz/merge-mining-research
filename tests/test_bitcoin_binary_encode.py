"""Tests for the coinbase-output encoders/formatters in bitcoin_binary.

Known vectors:
- Genesis block P2PK pubkey -> Satoshi's '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'.
- P2PKH built from the same hash160 -> the same address.
- BIP-173 / BIP-350 segwit witness-program vectors for P2WPKH / P2WSH / P2TR.
- OP_RETURN / nonstandard scripts -> None passthrough.
- Both format_outputs_* conventions on a small synthetic output list.
"""

from __future__ import annotations

from stale_blocks_analysis.bitcoin_binary import (
    encode_btc_address,
    format_outputs_addr,
    format_outputs_pkhex,
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
# format_outputs_addr / format_outputs_pkhex
# ---------------------------------------------------------------------------

P2PKH_SPK = _p2pkh(GENESIS_HASH160)
OPRET_SPK = b"\x6a\x02\x00\x00"


def test_format_outputs_addr_tuple_shape():
    # parse_coinbase() returns (value, spk) tuples.
    outs = [(5000000000, P2PKH_SPK), (0, OPRET_SPK)]
    assert format_outputs_addr(outs) == f"{SATOSHI_ADDR}:5000000000|OP_RETURN:0"


def test_format_outputs_pkhex_tuple_shape():
    outs = [(5000000000, P2PKH_SPK), (0, OPRET_SPK)]
    assert format_outputs_pkhex(outs) == f"{P2PKH_SPK.hex()};{OPRET_SPK.hex()}"


def test_format_outputs_addr_spk_dict_shape():
    # extract_bitcoin_vault_auxpow.py shape: {"value", "spk"}.
    outs = [{"value": 1, "spk": P2PKH_SPK}, {"value": 2, "spk": OPRET_SPK}]
    assert format_outputs_addr(outs) == f"{SATOSHI_ADDR}:1|OP_RETURN:2"


def test_format_outputs_pkhex_pkscript_dict_shape():
    # raw-hex extractor shape: {"value", "pkscript"}.
    outs = [{"value": 1, "pkscript": P2PKH_SPK}, {"value": 2, "pkscript": OPRET_SPK}]
    assert format_outputs_pkhex(outs) == f"{P2PKH_SPK.hex()};{OPRET_SPK.hex()}"


def test_format_outputs_addr_jsonrpc_shape():
    # JSON-RPC extractor shape: pre-decoded scriptPubKey dict.
    outs = [
        {"value": 3, "scriptPubKey": {"address": "1abc", "type": "pubkeyhash"}},
        {"value": 0, "scriptPubKey": {"type": "nulldata"}},
        {"value": 7, "scriptPubKey": {"type": "scripthash"}},  # no address
    ]
    assert format_outputs_addr(outs) == "1abc:3|OP_RETURN:0|scripthash:7"


def test_format_outputs_addr_nonstandard_passthrough():
    outs = [(9, b"\x00\x01\x02")]
    assert format_outputs_addr(outs) == "nonstandard:000102:9"


def test_format_outputs_empty():
    assert format_outputs_addr([]) == ""
    assert format_outputs_pkhex([]) == ""


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
        format_outputs_addr(parsed["outputs"])
        == f"{SATOSHI_ADDR}:5000000000|OP_RETURN:0"
    )
