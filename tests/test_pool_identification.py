"""Tests for runtime pool identification (stale_blocks_analysis.pool_identification).

Builds a fake `bitcoin-data/mining-pools`-shaped clone under tmp_path for each
test, points the module at it, and resets its lazy runtime caches so every
test starts from a clean slate regardless of execution order.
"""

import json

import pytest

from stale_blocks_analysis import pool_identification as pi
from stale_blocks_analysis.bitcoin_binary import (
    _b58_decode_to_hash160,
    _bech32_decode_to_program,
)


def _reset_runtime(monkeypatch, clone_dir):
    """Point the module at a fresh clone dir and clear the lazy runtime cache."""
    monkeypatch.setattr(pi, "LOCAL_MINING_POOLS_DIR", clone_dir)
    monkeypatch.setattr(pi, "_RUNTIME_POOL_TAGS", None)
    monkeypatch.setattr(pi, "_RUNTIME_OUTPUT_ADDR_POOLS", None)


@pytest.fixture
def pool_clone(tmp_path, monkeypatch):
    """Fresh $LOCAL_MINING_POOLS_DIR-shaped clone dir plus a pool-writing helper.

    Returns (clone_dir, add_pool) where add_pool(filename, *, pool_id, name,
    tags=None, addresses=None, link="") writes one pools/<filename>.json entry
    shaped like the real registry.
    """
    clone_dir = tmp_path / "mining-pools"
    _reset_runtime(monkeypatch, clone_dir)

    def add_pool(filename, *, pool_id, name, tags=None, addresses=None, link=""):
        pools_dir = clone_dir / "pools"
        pools_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "id": pool_id,
            "name": name,
            "addresses": addresses or [],
            "tags": tags or [],
            "link": link,
        }
        (pools_dir / filename).write_text(json.dumps(payload))

    return clone_dir, add_pool


def test_missing_clone_raises_with_instructions(tmp_path, monkeypatch):
    """No clone at all: identify_pool() raises FileNotFoundError with a `git clone` hint."""
    _reset_runtime(monkeypatch, tmp_path / "does-not-exist")

    with pytest.raises(FileNotFoundError) as exc_info:
        pi.identify_pool(b"anything")

    assert "git clone" in str(exc_info.value)


def test_empty_clone_raises(tmp_path, monkeypatch):
    """pools/ exists but has no .json files: still FileNotFoundError."""
    clone_dir = tmp_path / "mining-pools"
    (clone_dir / "pools").mkdir(parents=True)
    _reset_runtime(monkeypatch, clone_dir)

    with pytest.raises(FileNotFoundError):
        pi.identify_pool(b"anything")


def test_scriptsig_tag_match(pool_clone):
    _clone_dir, add_pool = pool_clone
    add_pool("testpool.json", pool_id="testpool", name="TestPool", tags=["/TestPool/"])

    assert pi.identify_pool(b"xx/TestPool/yy") == "TestPool"


@pytest.mark.parametrize("order", ["short_file_first", "long_file_first"])
def test_longest_tag_wins(pool_clone, order):
    """When two distinct tags both occur in the scriptSig, the longer tag's
    owner wins. Runtime tags are sorted by byte length (descending) before
    matching, so this holds regardless of which pool file is written/read
    first."""
    _clone_dir, add_pool = pool_clone
    if order == "short_file_first":
        add_pool("a_shortpool.json", pool_id="short", name="ShortPool", tags=["Pool"])
        add_pool(
            "b_longpool.json", pool_id="long", name="LongPool", tags=["Pool Extra"]
        )
    else:
        add_pool(
            "a_longpool.json", pool_id="long", name="LongPool", tags=["Pool Extra"]
        )
        add_pool("b_shortpool.json", pool_id="short", name="ShortPool", tags=["Pool"])

    # Contains both "Pool" and the longer "Pool Extra".
    assert pi.identify_pool(b"sig with Pool Extra embedded") == "LongPool"


def test_op_return_tag_scan(pool_clone):
    """A tag absent from the scriptSig but present in an OP_RETURN output
    is still matched (step 2 of identify_pool)."""
    _clone_dir, add_pool = pool_clone
    add_pool("opret.json", pool_id="opret", name="OpReturnPool", tags=["TAGX"])

    outputs = [(0, b"\x6a" + b"TAGX")]  # OP_RETURN push containing the tag
    assert pi.identify_pool(b"no tag in here", outputs) == "OpReturnPool"


def test_payout_address_p2sh_match(pool_clone):
    """When the scriptSig matches nothing, a P2SH payout address match identifies the pool."""
    _clone_dir, add_pool = pool_clone
    addr = "3Awm3FNpmwrbvAFVThRUFqgpbVuqWisni9"
    add_pool("addrpool.json", pool_id="addrpool", name="AddrPool", addresses=[addr])

    h160 = _b58_decode_to_hash160(addr)
    assert h160 is not None and len(h160) == 20
    spk = bytes([0xA9, 0x14]) + h160 + bytes([0x87])

    assert pi.identify_pool(b"nomatch", [(0, spk)]) == "AddrPool"


def test_p2wpkh_20_byte_match(pool_clone):
    """A 20-byte P2WPKH witness program matches; a 32-byte P2WSH-shaped
    program at the same address never matches (only 20-byte hash160 lookups
    are supported).

    The BIP-173 test vector bc1qw508d6qejxtdg4y5r3zarvaryc5xw7kv8f3t4 decodes
    to a 19-byte program with this repo's _bech32_decode_to_program (its
    checksum-stripping does not treat that vector's specific padding the way
    a spec-complete decoder would), so it is unsuitable here. Using a real
    bc1q payout address from the local mining-pools registry instead, which
    round-trips to a proper 20-byte program.
    """
    _clone_dir, add_pool = pool_clone
    addr = "bc1qjl8uwezzlech723lpnyuza0h2cdkvxvh54v3dn"
    program = _bech32_decode_to_program(addr)
    assert program is not None and len(program) == 20

    add_pool("bechpool.json", pool_id="bechpool", name="BechPool", addresses=[addr])

    spk_p2wpkh = b"\x00\x14" + program
    assert pi.identify_pool(b"nomatch", [(0, spk_p2wpkh)]) == "BechPool"

    spk_p2wsh = b"\x00\x20" + b"\x00" * 32
    assert pi.identify_pool(b"nomatch", [(0, spk_p2wsh)]) == "Unknown"


def test_unknown_when_nothing_matches(pool_clone):
    _clone_dir, add_pool = pool_clone
    add_pool("somepool.json", pool_id="some", name="SomePool", tags=["SomeTag"])

    # Taproot-shaped output (OP_1 push of a 32-byte program) matches nothing.
    assert pi.identify_pool(b"random", [(0, b"\x51\x20" + b"\x00" * 32)]) == "Unknown"
    # No scriptSig at all short-circuits before the pool tables are touched.
    assert pi.identify_pool(None) == "Unknown"
    assert pi.identify_pool(b"") == "Unknown"


def test_tag_conflict_warns(pool_clone, capsys):
    """Two pool files claiming the same tag emit a warning naming the tag on
    stderr. The winner is deterministic: fetch_known_pools() processes files
    in sorted-filename order and each later file overwrites the dict entry
    for a shared key, so the alphabetically LAST file's pool wins (not the
    first, despite the "first pool file wins" intuition one might expect from
    a naive "first match sticks" reading of the loop)."""
    _clone_dir, add_pool = pool_clone
    add_pool("a_alpha.json", pool_id="alpha", name="AlphaPool", tags=["SharedTag"])
    add_pool("b_beta.json", pool_id="beta", name="BetaPool", tags=["SharedTag"])

    result = pi.identify_pool(b"xxSharedTagxx")
    captured = capsys.readouterr()

    assert "SharedTag" in captured.err
    assert result == "BetaPool"


def test_local_override_never_displaces_upstream(tmp_path, monkeypatch):
    from stale_blocks_analysis import pool_identification as pi
    from stale_blocks_analysis.bitcoin_binary import _b58_decode_to_hash160

    upstream_addr = "3Awm3FNpmwrbvAFVThRUFqgpbVuqWisni9"
    h160 = _b58_decode_to_hash160(upstream_addr)
    pools = tmp_path / "pools"
    pools.mkdir()
    (pools / "upstream.json").write_text(
        '{"id": "up", "name": "UpstreamPool", '
        f'"addresses": ["{upstream_addr}"], "tags": [], "link": ""}}'.replace("}}", "}")
    )
    monkeypatch.setattr(pi, "LOCAL_MINING_POOLS_DIR", tmp_path)
    local_only = bytes.fromhex("00" * 20)
    monkeypatch.setattr(
        pi,
        "LOCAL_OUTPUT_ADDR_POOLS",
        {h160: "LocalCollider", local_only: "LocalOnly"},
    )
    monkeypatch.setattr(pi, "_RUNTIME_POOL_TAGS", None)
    monkeypatch.setattr(pi, "_RUNTIME_OUTPUT_ADDR_POOLS", None)

    spk_upstream = bytes([0xA9, 0x14]) + h160 + bytes([0x87])
    spk_local = bytes([0x76, 0xA9, 0x14]) + local_only + bytes([0x88, 0xAC])

    assert pi.identify_pool(b"no-tag", [(0, spk_upstream)]) == "UpstreamPool"
    assert pi.identify_pool(b"no-tag", [(0, spk_local)]) == "LocalOnly"


def test_malformed_registry_file_fails_closed(tmp_path, monkeypatch):
    import pytest

    from stale_blocks_analysis import pool_identification as pi

    pools = tmp_path / "pools"
    pools.mkdir()
    (pools / "good.json").write_text(
        '{"id": "g", "name": "GoodPool", "addresses": [], "tags": ["/Good/"]}'
    )
    (pools / "broken.json").write_text('{"name": "BrokenPool", "tags": [')
    monkeypatch.setattr(pi, "LOCAL_MINING_POOLS_DIR", tmp_path)
    monkeypatch.setattr(pi, "_RUNTIME_POOL_TAGS", None)
    monkeypatch.setattr(pi, "_RUNTIME_OUTPUT_ADDR_POOLS", None)

    with pytest.raises(ValueError, match="broken.json"):
        pi.identify_pool(b"xx/Good/yy")


def test_non_array_registry_fields_fail_closed(tmp_path, monkeypatch):
    import pytest

    from stale_blocks_analysis import pool_identification as pi

    pools = tmp_path / "pools"
    pools.mkdir()
    (pools / "bad.json").write_text(
        '{"id": "b", "name": "BadPool", "addresses": [], "tags": "/BadPool/"}'
    )
    monkeypatch.setattr(pi, "LOCAL_MINING_POOLS_DIR", tmp_path)
    monkeypatch.setattr(pi, "_RUNTIME_POOL_TAGS", None)
    monkeypatch.setattr(pi, "_RUNTIME_OUTPUT_ADDR_POOLS", None)

    with pytest.raises(ValueError, match="array of strings"):
        pi.identify_pool(b"anything")


def test_reset_runtime_pool_tables_picks_up_registry_edits(tmp_path, monkeypatch):
    from stale_blocks_analysis import pool_identification as pi

    first = tmp_path / "first"
    (first / "pools").mkdir(parents=True)
    (first / "pools" / "p.json").write_text(
        '{"id": "p", "name": "FirstPool", "addresses": [], "tags": ["/Tag/"]}'
    )
    second = tmp_path / "second"
    (second / "pools").mkdir(parents=True)
    (second / "pools" / "p.json").write_text(
        '{"id": "p", "name": "SecondPool", "addresses": [], "tags": ["/Tag/"]}'
    )

    monkeypatch.setattr(pi, "LOCAL_MINING_POOLS_DIR", first)
    monkeypatch.setattr(pi, "_RUNTIME_POOL_TAGS", None)
    monkeypatch.setattr(pi, "_RUNTIME_OUTPUT_ADDR_POOLS", None)
    assert pi.identify_pool(b"xx/Tag/yy") == "FirstPool"

    # A registry change without a reset keeps serving the cached tables.
    monkeypatch.setattr(pi, "LOCAL_MINING_POOLS_DIR", second)
    assert pi.identify_pool(b"xx/Tag/yy") == "FirstPool"

    pi.reset_runtime_pool_tables()
    assert pi.identify_pool(b"xx/Tag/yy") == "SecondPool"
