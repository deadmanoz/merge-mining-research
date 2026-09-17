"""Body authentication retained from the retired annotation overlay."""

import pytest

from stale_blocks_analysis import block_body
from stale_blocks_analysis.bitcoin_binary import sha256d


def test_legacy_sigop_counter_known_scripts() -> None:
    p2pkh = bytes.fromhex("76a914c825a1ecf2a6830c4401620c3a16f1995057c2ab88ac")
    assert block_body.count_legacy_sigops_in_script(p2pkh) == 1
    # OP_CHECKMULTISIG counts the 20-key maximum in inaccurate mode.
    assert block_body.count_legacy_sigops_in_script(b"\x51\x51\xae") == 20
    assert block_body.count_legacy_sigops_in_script(b"\xac\xad") == 2
    # A truncated push ends the walk with the count so far, like Core's GetOp.
    assert block_body.count_legacy_sigops_in_script(b"\xac\x4c") == 1


def test_block_counter_rejects_malformed_bytes() -> None:
    with pytest.raises(ValueError):
        block_body.count_block_legacy_sigops(b"\x00" * 40)
    with pytest.raises(ValueError):
        # 80-byte header + zero tx count.
        block_body.count_block_legacy_sigops(b"\x00" * 80 + b"\x00")


def _craft_one_tx_block() -> bytes:
    """Serialize a minimal 1-transaction block whose header commits to its tx."""
    tx = (
        b"\x01\x00\x00\x00"  # nVersion
        + b"\x01"  # vin count
        + b"\x00" * 32
        + b"\xff\xff\xff\xff"  # coinbase outpoint
        + b"\x00"  # empty scriptSig
        + b"\xff\xff\xff\xff"  # nSequence
        + b"\x01"  # vout count
        + b"\x00" * 8  # value
        + b"\x01\xac"  # scriptPubKey: OP_CHECKSIG (1 legacy sigop)
        + b"\x00" * 4  # nLockTime
    )
    header = b"\x01\x00\x00\x00" + b"\x00" * 32 + sha256d(tx) + b"\x00" * 12
    return header + b"\x01" + tx


def test_parse_block_body_derives_matching_merkle_root() -> None:
    raw = _craft_one_tx_block()
    sigops, merkle_root = block_body.parse_block_body(raw)
    assert sigops == 1
    assert merkle_root == raw[36:68]


def test_merkle_fold_rejects_cve_2012_2459_duplication() -> None:
    """A duplicated final leaf yields the same root; it must fail, not match."""
    a, b, c = (sha256d(bytes([seed])) for seed in (1, 2, 3))
    odd_root = block_body._merkle_root([a, b, c])
    assert odd_root  # the legitimate odd-length fold still derives a root
    with pytest.raises(ValueError, match="CVE-2012-2459"):
        block_body._merkle_root([a, b, c, c])


def _craft_segwit_block(
    tamper_witness: bool = False, extra_coinbase_witness_item: bool = False
) -> bytes:
    """Serialize a 2-tx segwit block with a valid BIP141 witness commitment."""
    witness_item = b"\xab" if tamper_witness else b"\xaa"
    spend = (
        b"\x01\x00\x00\x00"  # nVersion
        + b"\x00\x01"  # segwit marker + flag
        + b"\x01"  # vin count
        + b"\x11" * 32
        + b"\x00\x00\x00\x00"  # outpoint
        + b"\x00"  # empty scriptSig
        + b"\xff\xff\xff\xff"  # nSequence
        + b"\x01"  # vout count
        + b"\x00" * 8  # value
        + b"\x01\xac"  # scriptPubKey: OP_CHECKSIG
        + b"\x01\x01"  # witness: one 1-byte item
        + witness_item
        + b"\x00" * 4  # nLockTime
    )
    spend_txid = sha256d(
        spend[:4] + spend[6 : len(spend) - 7] + spend[len(spend) - 4 :]
    )
    # For the COMMITMENT the untampered wtxid is used, so a tampered witness
    # byte makes the derived commitment disagree with the committed one.
    committed_spend = spend if not tamper_witness else spend.replace(b"\xab", b"\xaa")
    spend_wtxid = sha256d(committed_spend)
    reserved = b"\x00" * 32
    witness_root = block_body._merkle_root([b"\x00" * 32, spend_wtxid])
    commitment = sha256d(witness_root + reserved)
    coinbase = (
        b"\x01\x00\x00\x00"
        + b"\x00\x01"
        + b"\x01"
        + b"\x00" * 32
        + b"\xff\xff\xff\xff"  # null outpoint
        + b"\x01\x51"  # scriptSig: OP_1
        + b"\xff\xff\xff\xff"
        + b"\x02"  # vout count
        + b"\x00" * 8
        + b"\x01\xac"
        + b"\x00" * 8
        + b"\x26"  # 38-byte commitment script
        + b"\x6a\x24\xaa\x21\xa9\xed"
        + commitment
        + (
            # An appended second item is NOT covered by the commitment (the
            # coinbase wtxid leaf is zeroed), so it must be rejected outright.
            b"\x02\x20" + reserved + b"\x01\xff"
            if extra_coinbase_witness_item
            else b"\x01\x20" + reserved  # exactly one 32-byte reserved value
        )
        + b"\x00" * 4
    )
    witness_bytes = 36 if extra_coinbase_witness_item else 34
    coinbase_txid = sha256d(
        coinbase[:4]
        + coinbase[6 : len(coinbase) - witness_bytes - 4]
        + coinbase[len(coinbase) - 4 :]
    )
    merkle_root = block_body._merkle_root([coinbase_txid, spend_txid])
    header = b"\x01\x00\x00\x00" + b"\x00" * 32 + merkle_root + b"\x00" * 12
    return header + b"\x02" + coinbase + spend


def test_segwit_block_witness_commitment_authenticates() -> None:
    raw = _craft_segwit_block()
    sigops, failures = block_body.authenticate_block_body(raw)
    assert failures == []
    assert sigops == 2


def test_tampered_witness_data_fails_commitment_authentication() -> None:
    """Altered witness bytes leave the txid tree intact but must still fail."""
    raw = _craft_segwit_block(tamper_witness=True)
    _sigops, failures = block_body.authenticate_block_body(raw)
    assert any("coinbase commitment" in failure for failure in failures)


def test_surplus_coinbase_witness_item_rejected() -> None:
    """The zeroed coinbase leaf never covers extra items; BIP141 allows one."""
    raw = _craft_segwit_block(extra_coinbase_witness_item=True)
    _sigops, failures = block_body.authenticate_block_body(raw)
    assert any("bad-witness-nonce-size" in failure for failure in failures)


def _strip_witnesses(raw: bytes) -> bytes:
    """Rebuild the crafted 2-tx segwit block with all witness data stripped.

    Legacy txids (and so the header merkle root) are unchanged; only the
    marker, flag, and witness sections disappear. The coinbase's commitment
    output stays in place, exactly the incomplete-body shape the validator
    must reject rather than skip.
    """
    pos = 80
    tx_count, pos = block_body._read_compact_size(raw, pos)
    stripped_txs = []
    for _ in range(tx_count):
        count, txid, wtxid, _outputs, _witness, new_pos = block_body._transaction_at(
            raw, pos
        )
        tx = raw[pos:new_pos]
        # version + body (between marker/flag and witness) + locktime.
        is_segwit = tx[4] == 0x00 and tx[5] == 0x01
        if is_segwit:
            # Recompute the body span exactly as the txid derivation does.
            legacy = _legacy_tx_bytes(tx)
        else:
            legacy = tx
        assert sha256d(legacy) == txid
        stripped_txs.append(legacy)
        pos = new_pos
    return raw[:81] + b"".join(stripped_txs)


def _legacy_tx_bytes(tx: bytes) -> bytes:
    """Strip marker/flag/witness from one serialized segwit transaction."""
    pos = 6  # version + marker + flag
    body_start = pos
    vin_count, pos = block_body._read_compact_size(tx, pos)
    for _ in range(vin_count):
        pos += 36
        script_len, pos = block_body._read_compact_size(tx, pos)
        pos += script_len + 4
    vout_count, pos = block_body._read_compact_size(tx, pos)
    for _ in range(vout_count):
        pos += 8
        script_len, pos = block_body._read_compact_size(tx, pos)
        pos += script_len
    body_end = pos
    return tx[:4] + tx[body_start:body_end] + tx[len(tx) - 4 :]


def test_witness_stripped_body_still_fails_commitment_check() -> None:
    """Stripping every witness must not silently skip commitment validation."""
    raw = _strip_witnesses(_craft_segwit_block())
    _sigops, failures = block_body.authenticate_block_body(raw)
    assert any("bad-witness-nonce-size" in failure for failure in failures)


def test_non_canonical_compact_size_rejected() -> None:
    """A widened-but-equal count encoding must fail, as Core refuses it."""
    raw = _craft_one_tx_block()
    assert raw[80] == 0x01
    widened = raw[:80] + b"\xfd\x01\x00" + raw[81:]
    with pytest.raises(ValueError, match="non-canonical CompactSize"):
        block_body.count_block_legacy_sigops(widened)
