"""Tests for the coinbase marker decoders.

Fixture data was captured from historical Bitcoin blocks and is pinned here so
the shipped registry and decoder tests need no scanner or database connection.
"""

from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from stale_blocks_analysis.coinbase_markers import (  # noqa: E402
    AUXPOW_MAGIC,
    classify_op_return,
    classify_scriptsig_extras,
    parse_auxpow_marker,
    parse_bip34_height,
    parse_op_return_payload,
)


# ── BIP-34 height push ──────────────────────────────────────────────────


def test_bip34_decode_early_version_2_block():
    # Block 227,836 follows the last observed version-1 block. Its version-2
    # scriptSig was captured live. Version 1 becomes invalid at 227,931.
    sig = bytes.fromhex(
        "03fc7903062f503253482f04ac204f510858029a11000003550d3363646164312f736c7573682f"
    )
    assert parse_bip34_height(sig) == 227_836


def test_bip34_decode_tip():
    # Block 947,126 — current btc-tx-stats tip; F2Pool coinbase.
    sig_hex = (
        "03b6730e2cfabe6d6d616b4c4498e86ff33f958f578abe1a19f105edf74169"
        "eefa2a37861f6dc5022410000000f09f909f092f4632506f6f6c2f65000000"
        "00000000000000000000000000000000000000000000000000000000000000"
        "000500b4ded530"
    )
    assert parse_bip34_height(bytes.fromhex(sig_hex)) == 947_126


def test_bip34_empty_scriptsig():
    assert parse_bip34_height(b"") is None


def test_bip34_genesis_does_not_look_like_height():
    # Genesis scriptSig is "The Times..." pushed as data, not BIP-34.
    sig = bytes.fromhex(
        "04ffff001d0104455468652054696d65732030332f4a616e2f323030"
        "39204368616e63656c6c6f72206f6e206272696e6b206f6620736563"
        "6f6e64206261696c6f757420666f722062616e6b73"
    )
    # 0x04 = push 4 bytes. The 4 bytes are ffff001d — that's the bits
    # field of the genesis block, which decodes as a (positive) integer
    # via CScriptNum. We accept that the function returns *something*;
    # the upstream caller suppresses BIP-34 markers below the
    # activation height anyway.
    decoded = parse_bip34_height(sig)
    # The point of the test: it should NOT crash and should NOT return
    # 0 (the genesis height) — pre-activation we can't tell BIP-34 from
    # arbitrary miner data.
    assert decoded is not None
    assert decoded != 0


# ── AuxPoW commitment ────────────────────────────────────────────────────


def test_auxpow_block_879999():
    # Block 879,999 — SecPool coinbase. BIP-34 push (4B) + "Mined by SecPool"
    # tag and extranonce in a 24-byte push (1+24B) → AuxPoW magic at offset 29.
    sig = bytes.fromhex(
        "037f6d0d"  # BIP-34 push: height 879,999
        "184d696e656420627920536563506f6f6c4600230388ca0787"  # push 0x18 + pool tag/extranonce
        "fabe6d6d"  # AuxPoW magic
        "3d74053f047dcc08a4706b210ac863cf21829ee9fa6ac5081aae42105c1a5ef9"  # 32B root
        "10000000"  # merkle_size LE = 16
        "00000000"  # merkle_nonce LE = 0
    )
    m = parse_auxpow_marker(sig)
    assert m is not None
    assert m.offset == 29
    assert m.merkle_size == 16
    assert m.merkle_nonce == 0
    assert (
        m.merkle_root.hex()
        == "3d74053f047dcc08a4706b210ac863cf21829ee9fa6ac5081aae42105c1a5ef9"
    )
    assert sig[m.offset : m.offset + 4] == AUXPOW_MAGIC


def test_auxpow_block_947126_tip():
    # Block 947,126 — F2Pool coinbase, AuxPoW at offset 5.
    sig = bytes.fromhex(
        "03b6730e2cfabe6d6d616b4c4498e86ff33f958f578abe1a19f105edf"
        "74169eefa2a37861f6dc5022410000000f09f909f"
    )
    m = parse_auxpow_marker(sig)
    assert m is not None
    assert m.offset == 5
    assert m.merkle_size == 16
    # nonce here is the four bytes f09f909f, LE-decoded.
    assert m.merkle_nonce == int.from_bytes(bytes.fromhex("f09f909f"), "little")


def test_auxpow_absent_in_genesis():
    sig = bytes.fromhex("04ffff001d0104455468652054696d65732030332f4a616e2f323030")
    assert parse_auxpow_marker(sig) is None


def test_auxpow_truncated_returns_none():
    # Magic present but not enough trailing bytes for full commitment.
    sig = AUXPOW_MAGIC + b"\x00" * 30
    assert parse_auxpow_marker(sig) is None


# ── OP_RETURN payload push parsing ──────────────────────────────────────


def test_parse_op_return_direct_push():
    # OP_RETURN <0x24> aa21a9ed <32 bytes>
    script = bytes.fromhex(
        "6a24aa21a9ed7870b3c283be7a53b2bdc0aba0ad1f63385cf6688b7f5faaf00b8061f5681629"
    )
    payload = parse_op_return_payload(script)
    assert payload is not None
    assert payload.startswith(bytes.fromhex("aa21a9ed"))
    assert len(payload) == 36


def test_parse_op_return_pushdata1():
    # Block 947,126 vout=6 — RSK via PUSHDATA1.
    script = bytes.fromhex(
        "6a4c2952534b424c4f434b3a14ca9d5bf8faa395cc12d8cb900117c98"
        "1269a40a2769b3fe6f2db180086085e"
    )
    payload = parse_op_return_payload(script)
    assert payload is not None
    assert payload.startswith(b"RSKBLOCK:")
    assert len(payload) == 0x29  # 41 bytes


# ── OP_RETURN tag classifier ─────────────────────────────────────────────


def test_classify_segwit_commitment():
    script = bytes.fromhex(
        "6a24aa21a9ed7870b3c283be7a53b2bdc0aba0ad1f63385cf6688b7f5faaf00b8061f5681629"
    )
    m = classify_op_return(script, vout=2)
    assert m is not None and m.name == "segwit" and m.klass == "segwit"


def test_classify_rsk_direct_push():
    # Bitcoin block 879,999: direct 41-byte push with the post-RSKIP-110
    # 32-byte compound commitment after the 9-byte "RSKBLOCK:" tag.
    script = bytes.fromhex(
        "6a2952534b424c4f434b3aba19565e040e5d835728c3ec904c7c0c57"
        "424c9e74e052f4635b3f15006d1e5b"
    )
    m = classify_op_return(script, vout=4)
    assert m is not None and m.name == "rsk" and m.klass == "mm_op_return"


def test_classify_rsk_pushdata1():
    # Block 947,126 — RSK via PUSHDATA1 (the real bug-finding fixture).
    script = bytes.fromhex(
        "6a4c2952534b424c4f434b3a14ca9d5bf8faa395cc12d8cb900117c98"
        "1269a40a2769b3fe6f2db180086085e"
    )
    m = classify_op_return(script, vout=6)
    assert m is not None and m.name == "rsk" and m.klass == "mm_op_return"


def test_classify_hathor_op_return():
    # Block 947,126 vout=5 — Hath + 32 bytes.
    script = bytes.fromhex(
        "6a24486174681a79e50421f18ba6dd8c9951366db966628b1f6bd0c1c92b0b3d7d063a5dcd20"
    )
    m = classify_op_return(script, vout=5)
    assert m is not None and m.name == "hathor_op_return" and m.klass == "mm_op_return"


def test_classify_exsat():
    script = bytes.fromhex("6a10455853415401051b0f0e0e0b1f120013")
    m = classify_op_return(script, vout=4)
    assert m is not None and m.name == "exsat" and m.klass == "non_mm_commitment"


def test_classify_core():
    script = bytes.fromhex(
        "6a2d434f524501a37cf4faa0758b26dca666f3e36d42fa15cc0106942c01"
        "262fa046fdb8ba0dfce3753405c74aed0e"
    )
    m = classify_op_return(script, vout=3)
    assert m is not None and m.name == "core"


def test_classify_segwit_test_pre_bip141():
    # F2Pool's pre-BIP141 zero-filled witness commitment: aa21a9ef
    # (note: ef vs ed) followed by 32 zero bytes. Observed 212× across
    # blocks 459,962-459,971 in Mar 2017, before SegWit activation.
    script = bytes.fromhex("6a24aa21a9ef" + "00" * 32)
    m = classify_op_return(script, vout=1)
    assert m is not None and m.name == "segwit_test" and m.klass == "non_mm_commitment"


def test_classify_vcash_braiins_nested():
    # Braiins Pool VCash commitment wrapped in a nested OP_RETURN: the
    # outer push payload begins with `6a 24 b9 e1 1b 6d` (i.e. a full
    # inner OP_RETURN PUSH36 + VCash magic). Observed 885× on Braiins
    # blocks 638,930+.
    script = bytes.fromhex(
        "6a266a24b9e11b6dde0f60424e21007e2523531f70e915d7ace3a7fb4a4b92e"
        "95ffd942ba8a3c1f3"
    )
    m = classify_op_return(script, vout=2)
    assert (
        m is not None and m.name == "vcash_braiins_nested" and m.klass == "mm_op_return"
    )


def test_classify_pool_op_return_1hash():
    # 1Hash's OP_RETURN pool brand. Real payload from block 403,991:
    # "Mined by 1hash.com" (18 bytes) + 14 trailing extranonce-ish bytes.
    script = bytes.fromhex(
        "6a204d696e65642062792031686173682e636f6dabb36b6c7fc012107fc01210623433cf"
    )
    m = classify_op_return(script, vout=1)
    assert (
        m is not None
        and m.name == "pool_op_return:1hash.com"
        and m.klass == "pool_op_return"
    )


def test_classify_ballet_sponsorship():
    # Ballet wallet block-sponsorship promo. Real payload from block 627,061:
    # "Ballet - Bitcoin Block 001".
    script = bytes.fromhex("6a1a" + b"Ballet - Bitcoin Block 001".hex())
    m = classify_op_return(script, vout=1)
    assert (
        m is not None
        and m.name == "ballet_sponsorship"
        and m.klass == "non_mm_commitment"
    )


def test_classify_payload_only_helper():
    # Exercises the helper that powers --reclassify: given a raw payload
    # (without OP_RETURN wrapper or push opcode), returns the matched tag.
    from stale_blocks_analysis.coinbase_markers import classify_payload_only

    # RSKBLOCK: payload (no wrapper).
    rsk_payload = b"RSKBLOCK:" + bytes.fromhex(
        "ba19565e040e5d835728c3ec904c7c0c57424c9e74e052f4635b3f15006d1e5b"
    )
    name, klass = classify_payload_only(rsk_payload)
    assert name == "rsk" and klass == "mm_op_return"

    # Unknown payload — should bucket by first 4 bytes.
    unknown_payload = bytes.fromhex("deadbeefcafef00d")
    name, klass = classify_payload_only(unknown_payload)
    assert name == "unknown:deadbeef" and klass == "unknown"


def test_classify_ocean_ocb1():
    # Ocean.xyz transparent-mining commitment — observed at vout=0 on
    # 99/7127 of recent blocks alongside the Ocean.xyz scriptSig tag.
    script = bytes.fromhex("6a144f434231f7900aa5440000009c0c0000ffebd92c")
    m = classify_op_return(script, vout=0)
    assert m is not None and m.name == "ocean_ocb1" and m.klass == "non_mm_commitment"


def test_classify_sys():
    script = bytes.fromhex(
        "6a277379735c9c54100a4f749daf27f562874aa2540a37a012058689a19a"
        "573287959b676718072200"
    )
    m = classify_op_return(script, vout=7)
    assert m is not None and m.name == "sys"


def test_classify_unknown_returns_prefix_bucket():
    # Random gibberish OP_RETURN — should bucket as unknown:<prefix>.
    script = bytes.fromhex("6a08deadbeefcafef00d")
    m = classify_op_return(script, vout=0)
    assert m is not None and m.name.startswith("unknown:deadbeef")


def test_classify_non_op_return_returns_none():
    # P2PKH script — not an OP_RETURN at all.
    script = bytes.fromhex("76a91400112233445566778899aabbccddeeff0011223388ac")
    assert classify_op_return(script, vout=0) is None


# ── Scriptsig extras (Hathor variant) ───────────────────────────────────


def test_hathor_scriptsig_variant_not_confused_with_pool_tag():
    # A coinbase that doesn't carry the Hathor magic — should return [].
    sig = bytes.fromhex("03b6730e2cfabe6d6d" + "00" * 32 + "00" * 8)
    assert classify_scriptsig_extras(sig, auxpow_offset=5) == []


# ── Sanity: registry consistency ─────────────────────────────────────────


def test_op_return_tags_no_duplicate_names():
    from stale_blocks_analysis.coinbase_markers import OP_RETURN_TAGS

    names = [t.name for t in OP_RETURN_TAGS]
    assert len(names) == len(set(names))
