"""Unit tests for merge_stale_sources, the (height, hash) dedup primitive.

Per the research semantics in AGENTS.md: dedup is by (height, hash) not height
alone, so competing same-height stale hashes are both preserved; the primary
(bitcoin-data/stale-blocks) record wins on exact duplicates, carrying AuxPoW
coinbase fields as fallback attribution evidence.
"""

from __future__ import annotations

from stale_blocks_analysis.stale_merge import merge_stale_sources


def _rec(height, hash_, **extra):
    r = {"height": height, "hash": hash_, "source": "x"}
    r.update(extra)
    return r


def test_disjoint_records_all_kept_and_sorted_by_height():
    merged = merge_stale_sources([_rec(200, "b")], [_rec(100, "a")])
    assert [(r["height"], r["hash"]) for r in merged] == [(100, "a"), (200, "b")]


def test_exact_duplicate_primary_wins_and_is_enriched():
    primary = [_rec(100, "a", source="stale-blocks")]  # no _scriptsig_hex
    auxpow = [_rec(100, "a", source="auxpow", _scriptsig_hex="dead", _outputs_str="o")]
    merged = merge_stale_sources(primary, auxpow)
    assert len(merged) == 1
    assert merged[0]["source"] == "stale-blocks"  # primary identity preserved
    assert merged[0]["_scriptsig_hex"] == "dead"  # AuxPoW coinbase carried as fallback
    assert merged[0]["_outputs_str"] == "o"


def test_competing_same_height_hashes_are_both_kept():
    merged = merge_stale_sources([_rec(100, "a")], [_rec(100, "b")])
    assert sorted((r["height"], r["hash"]) for r in merged) == [(100, "a"), (100, "b")]


def test_existing_primary_coinbase_is_not_overwritten():
    primary = [_rec(100, "a", _scriptsig_hex="keep")]
    auxpow = [_rec(100, "a", _scriptsig_hex="new", _outputs_str="o")]
    merged = merge_stale_sources(primary, auxpow)
    assert len(merged) == 1
    assert merged[0]["_scriptsig_hex"] == "keep"


def test_new_auxpow_record_is_added_verbatim():
    primary = [_rec(100, "a")]
    auxpow = [_rec(300, "c", source="auxpow", _scriptsig_hex="cc")]
    merged = merge_stale_sources(primary, auxpow)
    added = [r for r in merged if r["hash"] == "c"]
    assert added and added[0]["source"] == "auxpow"
    assert added[0]["_scriptsig_hex"] == "cc"


def test_empty_auxpow_returns_primary_unchanged():
    primary = [_rec(100, "a"), _rec(50, "z")]
    merged = merge_stale_sources(primary, [])
    assert [(r["height"], r["hash"]) for r in merged] == [(50, "z"), (100, "a")]


def test_tag_stale_blocks_preserves_pretagged_rows(monkeypatch):
    from stale_blocks_analysis import stale_merge

    monkeypatch.setattr(
        stale_merge,
        "identify_pool_detailed",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not be called")),
    )
    rows = [
        {
            "height": 1,
            "hash": "aa",
            "source": "rsk",
            "pool": "HistoricalPool",
            "_scriptsig_hex": "ff",
            "_outputs_str": "x",
        }
    ]
    out = stale_merge.tag_stale_blocks(rows)
    assert out[0]["pool"] == "HistoricalPool"
    assert out[0]["has_bin"] is False
    assert "_scriptsig_hex" not in out[0] and "_outputs_str" not in out[0]


def test_tag_stale_blocks_auxpow_fallback_passes_coinbase_to_identify(monkeypatch):
    from stale_blocks_analysis import stale_merge

    seen = {}

    def fake_identify(sig, outputs=None):
        seen["sig"] = sig
        seen["outputs"] = outputs
        return "FallbackPool", "tag"

    monkeypatch.setattr(stale_merge, "identify_pool_detailed", fake_identify)
    # Height/hash chosen so no BLOCKS_DIR .bin file can exist.
    rows = [
        {
            "height": 999999999,
            "hash": "00" * 32,
            "source": "auxpow",
            "_scriptsig_hex": "deadbeef",
            "_outputs_str": "",
        }
    ]
    out = stale_merge.tag_stale_blocks(rows)
    assert out[0]["pool"] == "FallbackPool"
    assert out[0]["has_bin"] is False
    assert seen["sig"] == bytes.fromhex("deadbeef")
    assert seen["outputs"] is None


def test_exact_duplicate_fills_missing_coinbase_fields_independently():
    primary = [
        {
            "height": 166_343,
            "hash": "aa",
            "source": "namecoin",
            "_scriptsig_hex": "aabb",
            "_outputs_str": "",
        }
    ]
    auxpow = [
        {
            "height": 166_343,
            "hash": "aa",
            "source": "i0coin",
            "_scriptsig_hex": "ccdd",
            "_outputs_str": "raw:76a914",
        }
    ]

    merged = merge_stale_sources(primary, auxpow)

    assert len(merged) == 1
    # The existing scriptSig is never overwritten; the missing outputs are
    # filled from the later observation of the same coinbase.
    assert merged[0]["_scriptsig_hex"] == "aabb"
    assert merged[0]["_outputs_str"] == "raw:76a914"


def test_addr_to_spk_decodes_syscoin_p2pkh_addresses():
    from stale_blocks_analysis.bitcoin_binary import _b58_decode_to_hash160
    from stale_blocks_analysis.coinbase_output_claims import (
        address_to_script_pubkey as _addr_to_spk,
    )

    addr = "SfYHFxiGv4mRtUfQVHxfMWknEt53Bjj286"
    h160 = _b58_decode_to_hash160(addr)
    assert h160 is not None and len(h160) == 20

    spk = _addr_to_spk(addr)
    assert spk == bytes([0x76, 0xA9, 0x14]) + h160 + bytes([0x88, 0xAC])


def test_addr_to_spk_decodes_namecoin_p2sh_and_bech32_addresses():
    from stale_blocks_analysis.bitcoin_binary import _b58_decode_to_hash160
    from stale_blocks_analysis.coinbase_output_claims import (
        address_to_script_pubkey as _addr_to_spk,
    )

    p2sh = "6arxak7yK8CmKEc8M8TqekkAXErtjN5RVt"  # committed Namecoin output
    h160 = _b58_decode_to_hash160(p2sh)
    assert h160 is not None and len(h160) == 20
    assert _addr_to_spk(p2sh) == bytes([0xA9, 0x14]) + h160 + bytes([0x87])

    # Namecoin bech32: same witness program as the bc1 form, and so the
    # same script, but its own checksum over the "nc" prefix.
    nc1 = "nc1qw508d6qejxtdg4y5r3zarvary0c5xw7kttkktk"
    bc1 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert _addr_to_spk(nc1) == _addr_to_spk(bc1)
    assert _addr_to_spk(nc1) is not None and _addr_to_spk(nc1)[:2] == b"\x00\x14"


def test_tag_stale_blocks_uses_auxpow_fallback_when_binary_unparseable(
    tmp_path, monkeypatch
):
    """A file that really contains the named block, and matches the blob
    tracked for it, but whose coinbase does not parse falls back to the
    carried AuxPoW evidence."""
    from stale_blocks_analysis import stale_merge
    from stale_blocks_analysis.bitcoin_binary import sha256d

    # An 80-byte header of arbitrary bytes, addressed by its own hash, so
    # the file genuinely contains the block it names.
    header = bytes(range(80))
    block_hash = sha256d(header)[::-1].hex()
    monkeypatch.setattr(stale_merge, "BLOCKS_DIR", tmp_path)
    payload = header + b"not-a-tx"
    name = f"700000-{block_hash}.bin"
    (tmp_path / name).write_bytes(payload)
    # Authenticated: this test is about an unparseable body, not about a
    # file the manifest does not vouch for.
    blobs = {name: stale_merge._git_blob_sha1(payload)}

    seen = {}

    def fake_identify(sig, outputs=None):
        seen["sig"] = sig
        return "FallbackPool", "tag"

    monkeypatch.setattr(stale_merge, "identify_pool_detailed", fake_identify)
    rows = [
        {
            "height": 700000,
            "hash": block_hash,
            "source": "auxpow",
            "_scriptsig_hex": "deadbeef",
            "_outputs_str": "",
        }
    ]

    # A corrupt tracked file stops a normal run: the filename inventory
    # still reports it present, so a silent fallback would hide it.
    import pytest

    with pytest.raises(ValueError, match="will not parse"):
        stale_merge.tag_stale_blocks(rows, archive_blobs=blobs)

    out = stale_merge.tag_stale_blocks(rows, allow_partial=True, archive_blobs=blobs)

    assert out[0]["pool"] == "FallbackPool"
    # The binary was rejected, so it did not supply this coinbase.
    assert out[0]["has_bin"] is False
    assert seen["sig"] == bytes.fromhex("deadbeef")


def test_tag_stale_blocks_rejects_a_binary_holding_another_block(tmp_path, monkeypatch):
    """A misplaced but parseable file would label a row from the wrong
    block's coinbase, so the archive is checked against the file name."""
    import pytest

    from stale_blocks_analysis import stale_merge

    monkeypatch.setattr(stale_merge, "BLOCKS_DIR", tmp_path)
    payload = bytes(range(80)) + b"x"
    name = f"700000-{'ab' * 32}.bin"
    (tmp_path / name).write_bytes(payload)
    # Tracked and authentic, so only the name-versus-header check can
    # reject it: this is a misplaced file, not a tampered one.
    blobs = {name: stale_merge._git_blob_sha1(payload)}
    rows = [
        {
            "height": 700000,
            "hash": "ab" * 32,
            "source": "auxpow",
            "_scriptsig_hex": "deadbeef",
            "_outputs_str": "",
        }
    ]

    with pytest.raises(ValueError, match="does not contain the block it names"):
        stale_merge.tag_stale_blocks([dict(r) for r in rows], archive_blobs=blobs)

    # Partial mode is the operator accepting degraded evidence, so a
    # misplaced binary falls back like every other rejected one rather
    # than aborting the run.
    monkeypatch.setattr(
        stale_merge, "identify_pool_detailed", lambda *a, **k: ("FallbackPool", "tag")
    )
    out = stale_merge.tag_stale_blocks(
        [dict(r) for r in rows], allow_partial=True, archive_blobs=blobs
    )
    assert out[0]["pool"] == "FallbackPool"
    assert out[0]["has_bin"] is False


def test_primary_exact_duplicates_are_dropped_first_wins():
    primary = [
        {"height": 1, "hash": "aa", "source": "stale-blocks"},
        {"height": 1, "hash": "aa", "source": "stale-blocks-copy"},
        {"height": 2, "hash": "bb", "source": "stale-blocks"},
    ]
    auxpow = [
        {
            "height": 1,
            "hash": "aa",
            "source": "namecoin",
            "_scriptsig_hex": "aabb",
            "_outputs_str": "",
        }
    ]

    merged = merge_stale_sources(primary, auxpow)

    assert [(r["height"], r["hash"]) for r in merged] == [(1, "aa"), (2, "bb")]
    # The kept first copy receives the enrichment.
    assert merged[0]["source"] == "stale-blocks"
    assert merged[0]["_scriptsig_hex"] == "aabb"


def test_addr_to_spk_accepts_uppercase_bech32():
    from stale_blocks_analysis.coinbase_output_claims import (
        address_to_script_pubkey as _addr_to_spk,
    )

    upper = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"
    lower = upper.lower()
    assert _addr_to_spk(upper) == _addr_to_spk(lower)
    assert _addr_to_spk(upper)[:2] == b"\x00\x14"


def test_addr_to_spk_reads_the_version_byte_not_the_leading_character():
    """Namecoin's P2PKH version (52) renders as both 'N' and 'M' depending
    on the payload, so typing by leading character mistyped every 'M'
    address as P2SH: 3,146 outputs in the committed loader inputs. The
    script type comes from the version byte instead."""
    from stale_blocks_analysis.coinbase_output_claims import (
        address_to_script_pubkey as _addr_to_spk,
    )

    p2pkh = b"\x76\xa9\x14"
    p2sh = b"\xa9\x14"

    # Namecoin v52, both spellings, are P2PKH.
    assert _addr_to_spk("MxCo7KsbZLQbfZNdeYvnhaRRr5kvFnGUgU")[:3] == p2pkh
    assert _addr_to_spk("NF3a1m3MzdUh2FgTyVCZezT7BPynKnT7HD")[:3] == p2pkh
    # Namecoin v13 is P2SH.
    assert _addr_to_spk("6arxak7yK8CmKEc8M8TqekkAXErtjN5RVt")[:2] == p2sh
    # Syscoin v63 is P2PKH; Bitcoin v0/v5 are P2PKH/P2SH.
    assert _addr_to_spk("SfYHFxiGv4mRtUfQVHxfMWknEt53Bjj286")[:3] == p2pkh
    assert _addr_to_spk("12dRugNcdxK39288NjcDV4GX7rMsKCGn6B")[:3] == p2pkh
    assert _addr_to_spk("3Awm3FNpmwrbvAFVThRUFqgpbVuqWisni9")[:2] == p2sh


def test_namecoin_m_address_pays_its_registry_pool():
    """An 'M'-spelled Namecoin re-encoding of AntPool's own P2PKH payout
    must resolve to AntPool once the script type is right."""
    import pytest

    from stale_blocks_analysis.config import LOCAL_MINING_POOLS_DIR
    from stale_blocks_analysis.pool_identification import identify_pool
    from stale_blocks_analysis.coinbase_output_claims import (
        address_to_script_pubkey as _addr_to_spk,
    )

    if not (LOCAL_MINING_POOLS_DIR / "pools").is_dir():
        pytest.skip("mining-pools clone not fetched")

    spk = _addr_to_spk("MxCo7KsbZLQbfZNdeYvnhaRRr5kvFnGUgU")
    assert identify_pool(b"no-tag-here", [(0, spk)]) == "AntPool"


def test_namecoin_addresses_spelled_nc1_are_base58_not_bech32():
    """A Namecoin version-52 address can be spelled 'NC1...'. Case-folding
    it into the bech32 branch discarded its payout evidence: 17 outputs in
    the committed inputs are spelled that way."""
    from stale_blocks_analysis.coinbase_output_claims import (
        address_to_script_pubkey as _addr_to_spk,
    )

    spk = _addr_to_spk("NC1hnGBkMuyh7Tk4TqszXXT3a6pxXPCANL")
    assert spk is not None and spk[:3] == b"\x76\xa9\x14"

    # A genuine Namecoin bech32 address still takes the bech32 path.
    bech32 = _addr_to_spk("nc1qw508d6qejxtdg4y5r3zarvary0c5xw7kttkktk")
    assert bech32 is not None and bech32[:2] == b"\x00\x14"


def test_base58_checksum_is_verified():
    """A mistyped address must not decode to a wrong-but-plausible script."""
    from stale_blocks_analysis.coinbase_output_claims import (
        address_to_script_pubkey as _addr_to_spk,
    )

    good = "12dRugNcdxK39288NjcDV4GX7rMsKCGn6B"
    assert _addr_to_spk(good) is not None
    assert _addr_to_spk(good[:-1] + ("C" if good[-1] != "C" else "D")) is None


def test_duplicate_observations_union_their_outputs():
    """Chains describe the same coinbase differently: a Namecoin RPC gives
    decoded addresses (dropping OP_RETURN and P2PK), ixcoin gives raw
    scripts. Keeping only the first list discards evidence another chain
    preserved, so the lists are unioned."""
    primary = [
        {
            "height": 162_012,
            "hash": "aa",
            "source": "namecoin",
            "_scriptsig_hex": "aabb",
            "_outputs_str": "NGDwrUEyBNkfxtrE7SK53f2fcTDq9YRSHC",
        }
    ]
    auxpow = [
        {
            "height": 162_012,
            "hash": "aa",
            "source": "ixcoin",
            "_scriptsig_hex": "aabb",
            "_outputs_str": "6a0b4d696e6564206279205831;41049e4a",
        }
    ]

    merged = merge_stale_sources(primary, auxpow)

    entries = merged[0]["_outputs_str"].split(";")
    assert "NGDwrUEyBNkfxtrE7SK53f2fcTDq9YRSHC" in entries
    assert "6a0b4d696e6564206279205831" in entries
    assert "41049e4a" in entries
    # A repeated observation adds nothing.
    again = merge_stale_sources(merged, auxpow)
    assert again[0]["_outputs_str"] == merged[0]["_outputs_str"]


def test_addr_to_spk_keeps_the_witness_version():
    """A 20-byte program is only P2WPKH at witness v0; reconstructing every
    20-byte program as OP_0 would let a v1 address impersonate a P2WPKH
    marker."""
    from stale_blocks_analysis.coinbase_output_claims import (
        _BECH32_CHARSET,
        address_to_script_pubkey as _addr_to_spk,
    )

    v0 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert _addr_to_spk(v0)[:2] == b"\x00\x14"

    # Same 20-byte program re-encoded at witness v1 must not become OP_0.
    program = _addr_to_spk(v0)[2:]
    acc, bits, values = 0, 0, []
    for byte in program:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            values.append((acc >> bits) & 31)
    data = [1] + values

    def polymod(vals):
        gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
        chk = 1
        for v in vals:
            top = chk >> 25
            chk = (chk & 0x1FFFFFF) << 5 ^ v
            for i in range(5):
                chk ^= gen[i] if ((top >> i) & 1) else 0
        return chk

    hrp = "bc"
    pre = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data
    pm = polymod(pre + [0] * 6) ^ 0x2BC830A3
    checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    v1 = "bc1" + "".join(_BECH32_CHARSET[d] for d in data + checksum)

    assert _addr_to_spk(v1)[:2] == b"\x51\x14"


def test_archive_file_must_match_its_tracked_blob(tmp_path, monkeypatch):
    """The header proves which block a file claims to be, not that its body
    is intact: parse_coinbase only decodes fields, so a replaced body with
    a correct header would supply corrupted tags and payout scripts."""
    import pytest

    from stale_blocks_analysis import stale_merge
    from stale_blocks_analysis.bitcoin_binary import sha256d

    header = bytes(range(80))
    block_hash = sha256d(header)[::-1].hex()
    name = f"700000-{block_hash}.bin"
    monkeypatch.setattr(stale_merge, "BLOCKS_DIR", tmp_path)
    (tmp_path / name).write_bytes(header + b"replaced-body")

    rows = [
        {
            "height": 700000,
            "hash": block_hash,
            "source": "auxpow",
            "_scriptsig_hex": "deadbeef",
            "_outputs_str": "",
        }
    ]
    blobs = {name: "0" * 40}  # what HEAD tracks, which this file is not

    with pytest.raises(ValueError, match="differs from the blob tracked"):
        stale_merge.tag_stale_blocks(list(rows), archive_blobs=blobs)

    monkeypatch.setattr(
        stale_merge, "identify_pool_detailed", lambda *a, **k: ("FallbackPool", "tag")
    )
    out = stale_merge.tag_stale_blocks(
        list(rows), allow_partial=True, archive_blobs=blobs
    )
    assert out[0]["pool"] == "FallbackPool"
    # The binary was rejected, so it did not supply this coinbase.
    assert out[0]["has_bin"] is False


def test_outputs_alone_are_enough_to_identify(monkeypatch):
    """scriptSig and outputs are independently optional evidence, so a
    record carrying only outputs must still reach OP_RETURN and payout
    matching instead of being forced to Unknown."""
    from stale_blocks_analysis import stale_merge

    seen = {}

    def fake_identify(sig, outputs=None):
        seen["sig"], seen["outputs"] = sig, outputs
        return "OutputsOnlyPool", "address"

    monkeypatch.setattr(stale_merge, "identify_pool_detailed", fake_identify)
    rows = [
        {
            "height": 999999999,
            "hash": "cd" * 32,
            "source": "auxpow",
            "_scriptsig_hex": "",
            "_outputs_str": "12dRugNcdxK39288NjcDV4GX7rMsKCGn6B",
        }
    ]

    out = stale_merge.tag_stale_blocks(rows)

    assert out[0]["pool"] == "OutputsOnlyPool"
    assert seen["sig"] == b""
    assert seen["outputs"] is not None


def test_parse_coinbase_rejects_a_truncated_output_script():
    """Slicing past the end of a buffer truncates silently in Python, so a
    block cut short inside a declared scriptPubKey would otherwise return a
    short script and look successfully parsed."""
    import struct

    from stale_blocks_analysis.bitcoin_binary import parse_coinbase

    header = bytes(80)
    tx = (
        bytes(4)  # version
        + b"\x01"  # input count
        + bytes(32)  # prev hash
        + b"\xff\xff\xff\xff"  # prev index
        + b"\x04"  # scriptSig length
        + b"\xaa\xbb\xcc\xdd"  # scriptSig
        + b"\xff\xff\xff\xff"  # sequence
        + b"\x01"  # output count
        + struct.pack("<Q", 5_000_000_000)  # value
        + b"\x19"  # declares a 25-byte scriptPubKey
    )
    complete = tx + b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"

    assert parse_coinbase(header + b"\x01" + complete) is not None
    # One byte of the declared 25-byte script: not a parsed block.
    assert parse_coinbase(header + b"\x01" + tx + b"\x76") is None


def test_untracked_archive_binary_is_not_trusted(tmp_path, monkeypatch):
    """The completeness check compares tracked names, so a stray file
    passes as a complete archive; without this it would be trusted on its
    header alone and could carry a replaced body."""
    import pytest

    from stale_blocks_analysis import stale_merge
    from stale_blocks_analysis.bitcoin_binary import sha256d

    header = bytes(range(80))
    block_hash = sha256d(header)[::-1].hex()
    name = f"700000-{block_hash}.bin"
    monkeypatch.setattr(stale_merge, "BLOCKS_DIR", tmp_path)
    (tmp_path / name).write_bytes(header + b"body")

    rows = [
        {
            "height": 700000,
            "hash": block_hash,
            "source": "auxpow",
            "_scriptsig_hex": "deadbeef",
            "_outputs_str": "",
        }
    ]
    # A non-empty map that does not list this file: the archive is a git
    # checkout, and this binary is not part of it.
    blobs = {"999999-" + "ff" * 32 + ".bin": "0" * 40}

    with pytest.raises(ValueError, match="not tracked at the checkout"):
        stale_merge.tag_stale_blocks(list(rows), archive_blobs=blobs)

    monkeypatch.setattr(
        stale_merge, "identify_pool_detailed", lambda *a, **k: ("FallbackPool", "tag")
    )
    out = stale_merge.tag_stale_blocks(
        list(rows), allow_partial=True, archive_blobs=blobs
    )
    assert out[0]["pool"] == "FallbackPool"


def test_child_chain_bech32_checksums_are_verified():
    """The shared decoder skips the checksum and the padding rule, so a
    mutated address would rebuild the same canonical script and could match
    a real payout marker."""
    from stale_blocks_analysis.coinbase_output_claims import (
        address_to_script_pubkey as _addr_to_spk,
    )

    valid = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert _addr_to_spk(valid) is not None
    assert _addr_to_spk(valid.upper()) == _addr_to_spk(valid)

    # Mutated checksum character.
    assert _addr_to_spk(valid[:-1] + ("q" if valid[-1] != "q" else "p")) is None
    # Mixed case, which BIP-173 forbids because it breaks the checksum.
    assert _addr_to_spk("BC1Q" + valid[4:]) is None
    # A checksum computed over the wrong prefix: this is the bc1 data part
    # spelled nc1, which is how the fold used to accept it.
    assert _addr_to_spk("nc1" + valid[3:]) is None
    # Non-zero padding bits (BIP-173 invalid-address vector).
    assert _addr_to_spk("bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du") is None


def test_binaries_are_unusable_without_a_blob_manifest(tmp_path, monkeypatch):
    """An empty or absent manifest authenticates nothing, so a binary it
    does not cover is as unverified as an untracked one: the header proves
    which block a file claims, never that its body was not replaced."""
    import pytest

    from stale_blocks_analysis import stale_merge
    from stale_blocks_analysis.bitcoin_binary import sha256d

    header = bytes(range(80))
    block_hash = sha256d(header)[::-1].hex()
    monkeypatch.setattr(stale_merge, "BLOCKS_DIR", tmp_path)
    (tmp_path / f"700000-{block_hash}.bin").write_bytes(header + b"body")
    rows = [
        {
            "height": 700000,
            "hash": block_hash,
            "source": "auxpow",
            "_scriptsig_hex": "deadbeef",
            "_outputs_str": "",
        }
    ]

    for manifest in ({}, None):
        with pytest.raises(ValueError, match="cannot be authenticated"):
            stale_merge.tag_stale_blocks(
                [dict(r) for r in rows], archive_blobs=manifest
            )

    monkeypatch.setattr(
        stale_merge, "identify_pool_detailed", lambda *a, **k: ("FallbackPool", "tag")
    )
    out = stale_merge.tag_stale_blocks(
        [dict(r) for r in rows], allow_partial=True, archive_blobs={}
    )
    assert out[0]["pool"] == "FallbackPool"
    assert out[0]["has_bin"] is False
    assert out[0]["_bin_rejected"] is True


def test_child_chain_bech32_requires_an_exact_hrp():
    """An address encoded for the HRP 'bc1evil' checksums against that HRP,
    so a prefix test would decode it into an ordinary Bitcoin script."""
    from stale_blocks_analysis.coinbase_output_claims import (
        address_to_script_pubkey as _addr_to_spk,
    )

    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    def polymod(values):
        gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
        chk = 1
        for v in values:
            top = chk >> 25
            chk = (chk & 0x1FFFFFF) << 5 ^ v
            for i in range(5):
                chk ^= gen[i] if ((top >> i) & 1) else 0
        return chk

    def encode(hrp, program):
        acc = bits = 0
        data = [0]
        for byte in program:
            acc = (acc << 8) | byte
            bits += 8
            while bits >= 5:
                bits -= 5
                data.append((acc >> bits) & 31)
        expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
        pm = polymod(expanded + data + [0] * 6) ^ 1
        checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
        return hrp + "1" + "".join(charset[d] for d in data + checksum)

    program = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
    assert _addr_to_spk(encode("bc", program)) is not None
    assert _addr_to_spk(encode("nc", program)) is not None
    # Valid checksums over prefixes that merely start with bc1/nc1.
    assert _addr_to_spk(encode("bc1evil", program)) is None
    assert _addr_to_spk(encode("nc1evil", program)) is None


def test_unreadable_binary_falls_back_in_partial_mode(tmp_path, monkeypatch):
    """A listed binary can be unreadable or replaced by a directory, which
    partial mode promises to fall back from like any other unusable one."""
    import pytest

    from stale_blocks_analysis import stale_merge

    block_hash = "cd" * 32
    name = f"700000-{block_hash}.bin"
    monkeypatch.setattr(stale_merge, "BLOCKS_DIR", tmp_path)
    (tmp_path / name).mkdir()  # a directory where a file is listed
    blobs = {name: "0" * 40}
    rows = [
        {
            "height": 700000,
            "hash": block_hash,
            "source": "auxpow",
            "_scriptsig_hex": "deadbeef",
            "_outputs_str": "",
        }
    ]

    with pytest.raises(ValueError, match="cannot be read"):
        stale_merge.tag_stale_blocks([dict(r) for r in rows], archive_blobs=blobs)

    monkeypatch.setattr(
        stale_merge, "identify_pool_detailed", lambda *a, **k: ("FallbackPool", "tag")
    )
    out = stale_merge.tag_stale_blocks(
        [dict(r) for r in rows], allow_partial=True, archive_blobs=blobs
    )
    assert out[0]["pool"] == "FallbackPool"
    assert out[0]["has_bin"] is False
    assert out[0]["_bin_rejected"] is True
