from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from stale_blocks_analysis import config  # noqa: E402
from stale_blocks_analysis.config import (  # noqa: E402
    CHAIN_SPECS,
    CHAINS_BY_AUXPOW_ACTIVATION,
    DATA_DIR,
    HISTORICAL_CHILD_HEADER_CHAINS,
    ChainSpec,
)

# Chains the project considers integrated.
INTEGRATED_KEYS = {
    "namecoin",
    "geistgeld",
    "i0coin",
    "coiledcoin",
    "ixcoin",
    "devcoin",
    "groupcoin",
    "huntercoin",
    "unobtanium",
    "crown",
    "myriadcoin",
    "argentum",
    "emercoin",
    "terracoin",
    "rsk",
    "bitmark",
    "xaya",
    "elastos",
    "syscoin",
    "hathor",
    "bitcoin-vault",
    "elcash",
    "fractal",
    "sixeleven",
    "lyncoin",
    "doichain",
}

COINBASE_MODE_KEYS = {
    k for k, s in CHAIN_SPECS.items() if s.attribution_mode == "coinbase"
}


def test_chain_specs_covers_integrated_chains() -> None:
    missing = INTEGRATED_KEYS - set(CHAIN_SPECS)
    assert not missing, f"CHAIN_SPECS missing integrated chains: {sorted(missing)}"


def test_historical_child_header_keys_match_chain_specs() -> None:
    missing = set(HISTORICAL_CHILD_HEADER_CHAINS) - set(CHAIN_SPECS)
    assert not missing, (
        f"historical child-header keys missing from CHAIN_SPECS: {sorted(missing)}"
    )


def test_keys_match_key_field() -> None:
    for key, spec in CHAIN_SPECS.items():
        assert isinstance(spec, ChainSpec)
        assert spec.key == key, f"dict key {key!r} != spec.key {spec.key!r}"


def test_xaya_uses_powdata_nbits_and_other_specs_use_header_nbits() -> None:
    assert CHAIN_SPECS["xaya"].child_nbits_from_header is False
    assert all(
        spec.child_nbits_from_header
        for key, spec in CHAIN_SPECS.items()
        if key != "xaya"
    )


def test_all_specs_present_in_activation_order() -> None:
    activation_keys = {k for k, _ in CHAINS_BY_AUXPOW_ACTIVATION}
    # Every spec key must be a known chronological-ordering key, and vice-versa
    # for the integrated set.
    for key in CHAIN_SPECS:
        assert key in activation_keys, f"{key} not in CHAINS_BY_AUXPOW_ACTIVATION"
    for key in INTEGRATED_KEYS:
        assert key in activation_keys, f"{key} missing from activation ordering"


def test_height_column_nonempty_and_stripped_for_every_spec() -> None:
    # Every chain (including the non-coinbase rsk/hathor) carries its own
    # height column in the committed validated CSVs; it must be a non-empty,
    # already-stripped string. INTEGRATED_KEYS is a subset of CHAIN_SPECS, so
    # iterating the full registry covers both the integrated and coinbase sets.
    assert COINBASE_MODE_KEYS, "expected at least one coinbase-mode chain"
    for key in CHAIN_SPECS:
        col = CHAIN_SPECS[key].height_column
        assert col, f"{key}: expected a non-empty height_column"
        assert isinstance(col, str) and col.strip() == col


def test_chain_id_is_int_where_known() -> None:
    for key, spec in CHAIN_SPECS.items():
        if spec.chain_id is not None:
            assert isinstance(spec.chain_id, int), f"{key}: chain_id must be int"
            assert not isinstance(spec.chain_id, bool)
            assert spec.chain_id > 0, f"{key}: chain_id must be positive"


def test_known_chain_ids_match_docs() -> None:
    # Spot-check a representative subset against docs/chains/<chain>.md values.
    expected = {
        "namecoin": 1,
        "i0coin": 2,
        "ixcoin": 3,
        "devcoin": 4,
        "huntercoin": 6,
        "syscoin": 16,
        "coiledcoin": 16,
        "crown": 20,
        "terracoin": 50,
        "myriadcoin": 90,
        "bitmark": 91,
        "unobtanium": 117,
        "elastos": 1224,
        "argentum": 1187,
        "emercoin": 666,
        "xaya": 1829,
        "bitcoin-vault": 1638,
        "fractal": 8228,
        "sixeleven": 1,
        "lyncoin": 0x0B0D,
        "doichain": 2,
    }
    for key, cid in expected.items():
        assert CHAIN_SPECS[key].chain_id == cid, f"{key}: chain_id mismatch"


def test_attribution_modes() -> None:
    assert CHAIN_SPECS["rsk"].attribution_mode == "miner_address"
    assert CHAIN_SPECS["hathor"].attribution_mode == "rest"
    # Everything else is coinbase.
    for key, spec in CHAIN_SPECS.items():
        if key in ("rsk", "hathor"):
            continue
        assert spec.attribution_mode == "coinbase", f"{key}: expected coinbase mode"
        assert spec.chain_id is not None or key in (
            "geistgeld",
            "groupcoin",
        ), f"{key}: coinbase chain should have a known chain_id unless JSON-dump"


def test_paths_under_repo_data_dir() -> None:
    for key, spec in CHAIN_SPECS.items():
        for label, path in (
            ("input_csv", spec.input_csv),
            ("output_csv", spec.output_csv),
            ("validated_csv", spec.validated_csv),
        ):
            assert isinstance(path, Path), f"{key}.{label} must be a Path"
            # Resolve to be robust against symlinks / relative parts.
            resolved = path.resolve()
            data_resolved = DATA_DIR.resolve()
            assert (
                data_resolved in resolved.parents or resolved.parent == data_resolved
            ), f"{key}.{label} ({resolved}) is not under DATA_DIR ({data_resolved})"


def test_validated_csv_reuses_existing_constants() -> None:
    # The validated_csv defaults must be the existing module-level *_CSV
    # constants so the two never drift.
    assert CHAIN_SPECS["namecoin"].validated_csv == config.AUXPOW_CSV
    assert CHAIN_SPECS["syscoin"].validated_csv == config.SYSCOIN_CSV
    assert CHAIN_SPECS["rsk"].validated_csv == config.RSK_CSV
    assert CHAIN_SPECS["bitcoin-vault"].validated_csv == config.BITCOIN_VAULT_CSV
    assert CHAIN_SPECS["fractal"].validated_csv == config.FRACTAL_CSV
    assert CHAIN_SPECS["xaya"].validated_csv == config.XAYA_CSV
    assert CHAIN_SPECS["sixeleven"].validated_csv == config.SIXELEVEN_CSV
    assert CHAIN_SPECS["lyncoin"].validated_csv == config.LYNCOIN_CSV
    assert CHAIN_SPECS["doichain"].validated_csv == config.DOICHAIN_CSV


def test_activation_height_int_or_none() -> None:
    for key, spec in CHAIN_SPECS.items():
        if spec.activation_height is not None:
            assert isinstance(spec.activation_height, int)
            assert not isinstance(spec.activation_height, bool)
            assert spec.activation_height >= 1, f"{key}: activation_height must be >= 1"
    # These recoveries do not have a verified numeric activation constant.
    assert CHAIN_SPECS["huntercoin"].activation_height is None
    assert CHAIN_SPECS["rsk"].activation_height is None
    assert CHAIN_SPECS["hathor"].activation_height is None
    assert CHAIN_SPECS["elastos"].activation_height is None


def test_chainspec_is_frozen() -> None:
    spec = CHAIN_SPECS["syscoin"]
    with pytest.raises(Exception):
        spec.chain_id = 999  # type: ignore[misc]
