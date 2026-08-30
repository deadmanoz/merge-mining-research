from __future__ import annotations

import csv
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "analysis" / "classify_btc_stale_relevance.py"
ANALYSIS_DIR = SCRIPT_PATH.parent

_original_sys_path = list(sys.path)
if str(ANALYSIS_DIR) not in sys.path:
    sys.path.insert(0, str(ANALYSIS_DIR))
spec = importlib.util.spec_from_file_location(
    "classify_btc_stale_relevance_under_test", SCRIPT_PATH
)
classifier = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = classifier
try:
    assert spec.loader is not None
    spec.loader.exec_module(classifier)
finally:
    sys.path = _original_sys_path


EASY_BITS = "1d00ffff"
NON_BTC_BITS = "1d00aaaa"
PREV_HASH = "f" * 64
EXCLUDED_HASH = "000000000000000010d43fb3f8d02cab156f333f2bfc172de9e6d87359118a1a"


def test_parser_uses_committed_epoch_reference_by_default() -> None:
    args = classifier.build_parser().parse_args([])
    assert args.epoch_reference_dir == PROJECT_ROOT / "data" / "bitcoin-epoch-reference"


def test_discover_sources_uses_publication_full_inventory_override(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    archive = tmp_path / "archive"
    publication = archive / "doichain/classified/doichain_stale_blocks.csv"
    publication.parent.mkdir(parents=True)
    publication.write_text("classification\n")
    full_inventory = archive / "doichain/2026-06-24-redo/doichain_stale_blocks.csv"
    full_inventory.parent.mkdir(parents=True)
    full_inventory.write_text("classification\nunknown\n")
    second_archive = tmp_path / "second-archive"
    second_inventory = (
        second_archive / "doichain/2026-06-24-redo/doichain_stale_blocks.csv"
    )
    second_inventory.parent.mkdir(parents=True)
    second_inventory.write_text("classification\ncanonical\n")
    generic_inventory = archive / "namecoin/classified/namecoin_stale_blocks.csv"
    generic_inventory.parent.mkdir(parents=True)
    generic_inventory.write_text("classification\nunknown\n")
    second_generic = second_archive / "namecoin/classified/namecoin_stale_blocks.csv"
    second_generic.parent.mkdir(parents=True)
    second_generic.write_text("classification\ncanonical\n")
    unknown_inventory = archive / "namecoin/namecoin_unknown_blocks.csv"
    unknown_inventory.parent.mkdir(parents=True, exist_ok=True)
    unknown_inventory.write_text("classification\nunknown\n")
    second_unknown = second_archive / "namecoin/namecoin_unknown_blocks.csv"
    second_unknown.parent.mkdir(parents=True, exist_ok=True)
    second_unknown.write_text("classification\ncanonical\n")

    _chains, full_files, unknown_files, _validated, _archives = (
        classifier.discover_sources(data_dir, [archive, second_archive])
    )

    assert full_files["doichain"] == full_inventory
    assert full_files["namecoin"] == generic_inventory
    assert unknown_files["namecoin"] == unknown_inventory


def _hash(n: int) -> str:
    return f"{n:064x}"


def _bip34_script(height: int) -> str:
    raw = height.to_bytes(max(1, (height.bit_length() + 7) // 8), "little")
    if raw[-1] & 0x80:
        raw += b"\x00"
    return bytes([len(raw)]).hex() + raw.hex()


def _epoch_start(height: int) -> str:
    return str((height // 2016) * 2016)


def _epoch_headers_for_height(
    height: int, bits: str = EASY_BITS
) -> list[dict[str, object]]:
    epoch_start = int(_epoch_start(height))
    return [
        {"height": epoch_start, "time": 0, "bits": bits},
        {"height": epoch_start + 2016, "time": 2_000_000, "bits": bits},
    ]


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _run_classifier(
    tmp_path: Path,
    files: dict[str, list[dict[str, str]]],
    *,
    archive_files: dict[str, list[dict[str, str]]] | None = None,
    epoch_bits: dict[str, str] | None = None,
    epoch_headers: list[dict[str, object]] | None = None,
    cache_files: dict[str, object] | None = None,
    check_mainchain: bool = False,
    max_mainchain_rpc: int = 5000,
) -> tuple[list[dict[str, str]], dict]:
    data_dir = tmp_path / "data"
    chain_archive_dir = tmp_path / "chain-archive" / "chains"
    cache_dir = tmp_path / "cache"
    results_dir = tmp_path / "results" / "analysis" / "btc-stale-relevance"
    data_dir.mkdir(parents=True)
    cache_dir.mkdir()
    for relative, rows in files.items():
        # Committed validated-stale inputs live under data/validated-stales/;
        # scratch stale/unknown/canonical inventories stay at the data root.
        if relative.endswith("_validated_stales.csv") and "/" not in relative:
            relative = f"validated-stales/{relative}"
        _write_csv(data_dir / relative, rows)
    for relative, rows in (archive_files or {}).items():
        _write_csv(chain_archive_dir / relative, rows)
    (cache_dir / "btc_nbits_by_epoch.json").write_text(
        json.dumps({"0": EASY_BITS} if epoch_bits is None else epoch_bits) + "\n"
    )
    (cache_dir / "btc_epoch_headers.json").write_text(
        json.dumps(
            [
                {"height": 0, "time": 0, "bits": EASY_BITS},
                {"height": 2016, "time": 1_000_000, "bits": EASY_BITS},
                {"height": 4032, "time": 2_000_000, "bits": EASY_BITS},
            ]
            if epoch_headers is None
            else epoch_headers
        )
        + "\n"
    )
    for filename, payload in (cache_files or {}).items():
        (cache_dir / filename).write_text(json.dumps(payload) + "\n")
    args = SimpleNamespace(
        data_dir=data_dir,
        chain_archive_dirs=[chain_archive_dir] if archive_files else [],
        results_dir=results_dir,
        cache_dir=cache_dir,
        check_mainchain=check_mainchain,
        rpc_url="http://127.0.0.1:8332",
        rpc_user=None,
        rpc_pass=None,
        rpc_batch_size=500,
        max_mainchain_rpc=max_mainchain_rpc,
        # Fixtures carry no upstream clone; the missing-upstream gate is
        # exercised by its own dedicated test below.
        allow_missing_upstream=True,
    )
    summary = classifier.run(args)
    with (results_dir / classifier.OUTPUT_INVENTORY).open(newline="") as f:
        rows = list(csv.DictReader(f))
    return rows, summary


def test_valid_direct_stale_is_confirmed(tmp_path: Path):
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "xaya_validated_stales.csv": [
                {
                    "btc_header_hash": _hash(1),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "stale",
                    "validation_status": "VALID",
                }
            ]
        },
    )

    assert rows[0]["btc_stale_relevance"] == ""
    assert rows[0]["relevance_reason"] == "valid_direct_stale"


@pytest.mark.parametrize(
    "status",
    ("", "VALIDATION_FAILED", "VALID_BOGUS", "VALID invented"),
)
def test_direct_stale_requires_an_exact_accepted_status(
    tmp_path: Path, status: str
) -> None:
    assert not classifier.validation_allows_direct_stale(status)
    assert classifier.validation_rejects(status)

    rows, summary = _run_classifier(
        tmp_path,
        {
            "xaya_validated_stales.csv": [
                {
                    "btc_header_hash": _hash(1),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "stale",
                    "validation_status": status,
                }
            ]
        },
    )

    assert rows[0]["btc_stale_relevance"] == "excluded"
    assert rows[0]["relevance_reason"] == "validation_rejected"
    assert summary["unique_confirmed_btc_stale"]["global_unique_hashes"] == 0


def test_post_bch_direct_stale_status_is_exactly_accepted() -> None:
    status = "VALID (post-BCH, difficulty matches BTC)"

    assert classifier.validation_allows_direct_stale(status)
    assert not classifier.validation_rejects(status)


@pytest.mark.skipif(
    not (
        PROJECT_ROOT / "data" / "validated-stales" / "argentum_validated_stales.csv"
    ).exists(),
    reason="per-chain validated-stale datasets are added in the data pass",
)
def test_real_validated_stale_fixture_survives_pow_gate(tmp_path: Path):
    with (
        PROJECT_ROOT / "data" / "validated-stales" / "argentum_validated_stales.csv"
    ).open(newline="") as f:
        fixture = next(csv.DictReader(f))
    assert (
        fixture["btc_header_hash"]
        == "00000000000000000014ff91181fe426c7d68fa10d333d4349b1a0b519d0863c"
    )

    rows, _summary = _run_classifier(
        tmp_path,
        {
            "argentum_validated_stales.csv": [
                {
                    "btc_header_hash": fixture["btc_header_hash"],
                    "btc_prev_hash": fixture["btc_prev_hash"],
                    "btc_time": fixture["btc_time"],
                    "btc_bits": fixture["btc_bits"],
                    "classification": "stale",
                    "validation_status": fixture["validation_status"],
                }
            ]
        },
    )

    assert rows[0]["self_pow_valid"] == "true"
    assert rows[0]["btc_stale_relevance"] == ""
    assert rows[0]["relevance_reason"] == "valid_direct_stale"


def test_valid_stale_descendant_is_confirmed(tmp_path: Path):
    with (PROJECT_ROOT / "data/stale_descendants.csv").open(newline="") as handle:
        parent = next(csv.DictReader(handle))
    rows, _summary = _run_classifier(
        tmp_path,
        {"stale_descendants.csv": [parent]},
    )

    assert rows[0]["btc_stale_relevance"] == ""
    assert rows[0]["relevance_reason"] == "valid_stale_descendant"


def test_rejected_stale_descendant_fails_at_canonical_loader(tmp_path: Path):
    with (PROJECT_ROOT / "data/stale_descendants.csv").open(newline="") as handle:
        parent = next(csv.DictReader(handle))
    parent["validation_status"] = "REJECTED_bip34_height_mismatch"

    with pytest.raises(ValueError, match="parent verdict is not accepted"):
        _run_classifier(tmp_path, {"stale_descendants.csv": [parent]})


def test_rsk_unknown_row_timestamp_epoch_match_is_weak(tmp_path: Path):
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "rsk_stale_blocks.csv": [
                {
                    "btc_stale_height": "300000",
                    "btc_header_hash": _hash(4),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "rsk_height": "100",
                    "rsk_miner": "0xabc",
                    "pool_label": "Pool",
                    "is_uncle": "false",
                    "classification": "unknown",
                }
            ]
        },
    )

    assert rows[0]["btc_stale_relevance"] == "weak_btc_orphan"
    assert rows[0]["strict_height_source"] == ""
    assert rows[0]["rsk_height"] == "100"


def test_private_chain_archive_full_inventory_is_processed(tmp_path: Path):
    rows, summary = _run_classifier(
        tmp_path,
        {},
        archive_files={
            "namecoin/classified/namecoin_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(40),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "coinbase_scriptsig_hex": _bip34_script(300000),
                    "classification": "unknown",
                }
            ]
        },
        epoch_bits={_epoch_start(300000): EASY_BITS},
        epoch_headers=_epoch_headers_for_height(300000),
    )

    assert rows[0]["chain"] == "namecoin"
    assert rows[0]["source_path"].endswith(
        "namecoin/classified/namecoin_stale_blocks.csv"
    )
    assert rows[0]["btc_stale_relevance"] == "strict_btc_orphan"
    assert rows[0]["relevance_reason"] == "strict_height_nbits_match"
    assert summary["input_files"]["chain_archive_dirs"]
    assert "namecoin" in summary["input_files"]["full_inventory_paths"]


def test_rsk_unknown_row_non_btc_epoch_bits_is_excluded(tmp_path: Path):
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "rsk_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(5),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": NON_BTC_BITS,
                    "classification": "unknown",
                }
            ]
        },
    )

    assert rows[0]["btc_stale_relevance"] == "excluded"
    assert rows[0]["relevance_reason"] == "non_btc_epoch_bits"


def test_standard_unknown_row_decoded_bip34_height_match_is_strict(tmp_path: Path):
    height = 300_000
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "namecoin_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(6),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "coinbase_scriptsig_hex": _bip34_script(height),
                    "classification": "unknown",
                }
            ]
        },
        epoch_bits={_epoch_start(height): EASY_BITS},
        epoch_headers=_epoch_headers_for_height(height),
    )

    assert rows[0]["btc_stale_relevance"] == "strict_btc_orphan"
    assert rows[0]["strict_height_source"] == "coinbase_bip34_height"
    assert rows[0]["expected_nbits_by_height"] == EASY_BITS


def test_unknown_classifier_status_does_not_reject_strict_evidence(tmp_path: Path):
    height = 300_000
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "elastos_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(60),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "coinbase_scriptsig_hex": _bip34_script(height),
                    "classification": "unknown",
                    "validation_status": "UNKNOWN",
                }
            ]
        },
        epoch_bits={_epoch_start(height): EASY_BITS},
        epoch_headers=_epoch_headers_for_height(height),
    )

    assert rows[0]["btc_stale_relevance"] == "strict_btc_orphan"
    assert rows[0]["relevance_reason"] == "strict_height_nbits_match"


def test_standard_unknown_row_decoded_bip34_height_mismatch_is_excluded(tmp_path: Path):
    height = 300_000
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "namecoin_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(7),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": NON_BTC_BITS,
                    "coinbase_scriptsig_hex": _bip34_script(height),
                    "classification": "unknown",
                }
            ]
        },
        epoch_bits={_epoch_start(height): EASY_BITS},
        epoch_headers=_epoch_headers_for_height(height),
    )

    assert rows[0]["btc_stale_relevance"] == "excluded"
    assert rows[0]["relevance_reason"] == "non_btc_epoch_bits"
    assert rows[0]["strict_height_source"] == "coinbase_bip34_height"


def test_standard_unknown_row_column_bip34_height_sets_output_height(tmp_path: Path):
    btc_height = 300_000
    bip34_height = 302_016
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "namecoin_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(8),
                    "btc_prev_hash": PREV_HASH,
                    "btc_height": str(btc_height),
                    "btc_bip34_height": str(bip34_height),
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "unknown",
                }
            ]
        },
        epoch_bits={_epoch_start(bip34_height): EASY_BITS},
        epoch_headers=_epoch_headers_for_height(bip34_height),
    )

    assert rows[0]["btc_stale_relevance"] == "strict_btc_orphan"
    assert rows[0]["strict_height_source"] == "btc_bip34_height"
    assert rows[0]["btc_height"] == str(bip34_height)


def test_decoded_bip34_height_time_epoch_mismatch_falls_back_to_weak(tmp_path: Path):
    height = 300_000
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "namecoin_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(35),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "coinbase_scriptsig_hex": _bip34_script(height),
                    "classification": "unknown",
                }
            ]
        },
        epoch_bits={_epoch_start(height): EASY_BITS},
        epoch_headers=[
            {"height": 400_000, "time": 0, "bits": EASY_BITS},
            {"height": 402_016, "time": 2_000_000, "bits": EASY_BITS},
        ],
    )

    assert rows[0]["btc_stale_relevance"] == "weak_btc_orphan"
    assert rows[0]["strict_height_source"] == ""
    assert rows[0]["notes"] == "coinbase_bip34_height_time_epoch_mismatch"


def test_decoded_bip34_height_after_time_cache_range_is_pending(tmp_path: Path):
    # The row's timestamp is past the epoch-header table's coverage, so the
    # decoded height cannot be cross-checked against a time epoch and no
    # final verdict is possible: pending (monitor-aligned), not excluded.
    height = 300_000
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "namecoin_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(37),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "2000",
                    "btc_bits": EASY_BITS,
                    "coinbase_scriptsig_hex": _bip34_script(height),
                    "classification": "unknown",
                }
            ]
        },
        epoch_bits={_epoch_start(height): EASY_BITS},
        epoch_headers=[
            {"height": int(_epoch_start(height)), "time": 1000, "bits": EASY_BITS}
        ],
    )

    assert rows[0]["btc_stale_relevance"] == "pending"
    assert rows[0]["relevance_reason"] == "above_nbits_time_horizon"
    assert rows[0]["strict_height_source"] == ""
    assert rows[0]["notes"] == "coinbase_bip34_height_time_epoch_unavailable"


def test_hathor_canonical_is_excluded(tmp_path: Path):
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "hathor_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(25),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "full_coinbase_hex": "00",
                    "classification": "canonical",
                }
            ]
        },
    )

    assert rows[0]["btc_stale_relevance"] == "excluded"
    assert rows[0]["relevance_reason"] == "source_canonical"
    assert rows[0]["source_schema"] == "hathor"


def test_hathor_coinbase_bip34_height_can_be_strict(tmp_path: Path):
    height = 300_000
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "hathor_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(250),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1500",
                    "btc_bits": EASY_BITS,
                    "coinbase_scriptsig_hex": _bip34_script(height),
                    "classification": "unknown",
                }
            ]
        },
        epoch_bits={_epoch_start(height): EASY_BITS},
        epoch_headers=_epoch_headers_for_height(height),
    )

    assert rows[0]["btc_stale_relevance"] == "strict_btc_orphan"
    assert rows[0]["relevance_reason"] == "strict_height_nbits_match"
    assert rows[0]["strict_height_source"] == "coinbase_bip34_height"
    assert rows[0]["btc_height"] == str(height)
    assert rows[0]["source_schema"] == "hathor"


def test_malformed_header_hash_is_excluded(tmp_path: Path):
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "xaya_stale_blocks.csv": [
                {
                    "btc_header_hash": "not-a-hash",
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "unknown",
                }
            ]
        },
    )

    assert rows[0]["btc_stale_relevance"] == "excluded"
    assert rows[0]["relevance_reason"] == "malformed_header_hash"


def test_malformed_prev_hash_is_excluded(tmp_path: Path):
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "rsk_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(17),
                    "btc_prev_hash": "not-a-hash",
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "unknown",
                }
            ]
        },
    )

    assert rows[0]["btc_stale_relevance"] == "excluded"
    assert rows[0]["relevance_reason"] == "malformed_prev_hash"


def test_pow_target_mismatch_is_excluded(tmp_path: Path):
    target = classifier.rec.compact_target(NON_BTC_BITS)
    assert target is not None
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "rsk_stale_blocks.csv": [
                {
                    "btc_header_hash": f"{target + 1:064x}",
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": NON_BTC_BITS,
                    "classification": "unknown",
                }
            ]
        },
    )

    assert rows[0]["btc_stale_relevance"] == "excluded"
    assert rows[0]["relevance_reason"] == "pow_target_mismatch"


def test_non_descendant_rejected_stale_is_validation_rejected(tmp_path: Path):
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "xaya_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(18),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "stale",
                    "validation_status": "REJECTED_bch_parent",
                }
            ]
        },
    )

    assert rows[0]["btc_stale_relevance"] == "excluded"
    assert rows[0]["relevance_reason"] == "validation_rejected"


def test_source_stale_with_failed_pow_is_excluded(tmp_path: Path):
    target = classifier.rec.compact_target(NON_BTC_BITS)
    assert target is not None
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "xaya_stale_blocks.csv": [
                {
                    "btc_header_hash": f"{target + 1:064x}",
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": NON_BTC_BITS,
                    "classification": "stale",
                    "validation_status": "VALID",
                }
            ]
        },
    )

    assert rows[0]["btc_stale_relevance"] == "excluded"
    assert rows[0]["relevance_reason"] == "pow_target_mismatch"


def test_bits_absent_pow_valid_true_allows_stale_confirmation(tmp_path: Path):
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "xaya_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(32),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "pow_valid": "true",
                    "classification": "stale",
                    "validation_status": "VALID",
                }
            ]
        },
    )

    assert rows[0]["self_pow_valid"] == "true"
    assert rows[0]["btc_stale_relevance"] == ""
    assert rows[0]["relevance_reason"] == "valid_direct_stale"


def test_bits_absent_pow_valid_false_excludes_row(tmp_path: Path):
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "xaya_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(33),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "pow_valid": "false",
                    "classification": "stale",
                    "validation_status": "VALID",
                }
            ]
        },
    )

    assert rows[0]["self_pow_valid"] == "false"
    assert rows[0]["btc_stale_relevance"] == "excluded"
    assert rows[0]["relevance_reason"] == "pow_target_mismatch"


def test_bits_absent_without_pow_valid_excludes_row(tmp_path: Path):
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "xaya_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(34),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "classification": "stale",
                    "validation_status": "VALID",
                }
            ]
        },
    )

    assert rows[0]["self_pow_valid"] == "false"
    assert rows[0]["btc_stale_relevance"] == "excluded"
    assert rows[0]["relevance_reason"] == "pow_target_mismatch"


def test_source_stale_marked_mainchain_by_cache_is_excluded(tmp_path: Path):
    block_hash = _hash(31)
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "xaya_stale_blocks.csv": [
                {
                    "btc_header_hash": block_hash,
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "stale",
                    "validation_status": "VALID",
                }
            ]
        },
        cache_files={
            "shadow-resolver-mainchain-cache.json": {
                block_hash: {"exists": True, "on_mainchain": True}
            }
        },
    )

    assert rows[0]["btc_stale_relevance"] == "excluded"
    assert rows[0]["relevance_reason"] == "known_mainchain"


def test_source_near_is_excluded(tmp_path: Path):
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "xaya_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(19),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "near",
                }
            ]
        },
    )

    assert rows[0]["btc_stale_relevance"] == "excluded"
    assert rows[0]["relevance_reason"] == "source_near"


def test_upstream_known_stale_membership_excludes_unknown_row_without_outputting_upstream_row(
    tmp_path: Path,
):
    stale_hash = _hash(20)
    rows, summary = _run_classifier(
        tmp_path,
        {
            "stale-blocks/stale-blocks.csv": [
                {"hash": stale_hash, "height": "300000", "header": ""}
            ],
            "rsk_stale_blocks.csv": [
                {
                    "btc_header_hash": stale_hash,
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "unknown",
                }
            ],
        },
    )

    assert len(rows) == 1
    assert rows[0]["source_path"].endswith("rsk_stale_blocks.csv")
    assert rows[0]["btc_stale_relevance"] == "excluded"
    assert rows[0]["relevance_reason"] == "known_stale_hash"
    upstream = [
        source
        for source in summary["known_stale_membership"]["sources"]
        if source["source"] == "upstream"
    ][0]
    assert upstream["rows_loaded"] == 1


def test_legacy_orphan_classification_uses_unknown_path(tmp_path: Path):
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "rsk_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(26),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    # legacy artifacts wrote "orphan" for the unknown state
                    "classification": "orphan",
                }
            ]
        },
    )

    assert rows[0]["btc_stale_relevance"] == "weak_btc_orphan"


def test_blank_classification_uses_unknown_path(tmp_path: Path):
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "rsk_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(27),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "",
                }
            ]
        },
    )

    assert rows[0]["source_classification"] == "unknown"
    assert rows[0]["btc_stale_relevance"] == "weak_btc_orphan"


def test_summary_deduplicates_confirmed_hash_without_blank_height_conflict(
    tmp_path: Path,
):
    duplicate_hash = _hash(9)
    _rows, summary = _run_classifier(
        tmp_path,
        {
            "xaya_stale_blocks.csv": [
                {
                    "btc_header_hash": duplicate_hash,
                    "btc_prev_hash": PREV_HASH,
                    "btc_height": "300000",
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "stale",
                    "validation_status": "VALID",
                }
            ],
            "hathor_stale_blocks.csv": [
                {
                    "btc_header_hash": duplicate_hash,
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "stale",
                    "validation_status": "VALID",
                }
            ],
        },
    )

    assert summary["unique_confirmed_btc_stale"]["global_unique_hashes"] == 1
    assert summary["unique_confirmed_btc_stale"]["height_conflicts"] == []


def test_unresolved_decoded_bip34_height_can_fall_back_to_weak(tmp_path: Path):
    height_without_cache_entry = 999_999
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "namecoin_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(10),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "coinbase_scriptsig_hex": _bip34_script(height_without_cache_entry),
                    "classification": "unknown",
                }
            ]
        },
        epoch_bits={"0": EASY_BITS, "1001952": EASY_BITS},
        epoch_headers=_epoch_headers_for_height(height_without_cache_entry),
    )

    assert rows[0]["btc_stale_relevance"] == "weak_btc_orphan"
    assert rows[0]["strict_height_source"] == ""
    assert rows[0]["notes"] == "coinbase_bip34_height_unresolved"
    assert rows[0]["btc_height"] == ""


def test_out_of_range_decoded_bip34_height_is_pending(tmp_path: Path):
    # Monitor-aligned horizon semantics: a decoded strict height above the
    # nBits table's covered maximum has no final verdict yet. It must stay
    # `pending` (re-classifiable when the table is extended), not fall back
    # to the timestamp-based weak path.
    out_of_range_height = 999_999
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "namecoin_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(27),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "coinbase_scriptsig_hex": _bip34_script(out_of_range_height),
                    "classification": "unknown",
                }
            ]
        },
        epoch_bits={"0": EASY_BITS},
        epoch_headers=_epoch_headers_for_height(out_of_range_height),
    )

    assert rows[0]["btc_stale_relevance"] == "pending"
    assert rows[0]["relevance_reason"] == "above_nbits_height_horizon"
    assert rows[0]["strict_height_source"] == ""
    assert rows[0]["notes"] == "coinbase_bip34_height_out_of_epoch_cache_range"
    assert rows[0]["btc_height"] == ""


def test_timestamp_above_epoch_table_horizon_is_pending(tmp_path: Path):
    # Monitor-aligned horizon semantics: a timestamp past the epoch-header
    # table's covered maximum is `pending`, not excluded. The default test
    # table covers times 0..2_000_000.
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "rsk_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(29),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "5000000",
                    "btc_bits": EASY_BITS,
                    "classification": "unknown",
                }
            ]
        },
    )

    assert rows[0]["btc_stale_relevance"] == "pending"
    assert rows[0]["relevance_reason"] == "above_nbits_time_horizon"


def test_timestamp_below_epoch_table_floor_stays_excluded(tmp_path: Path):
    # Below-floor timestamps keep the excluded verdict (only the above-horizon
    # side is pending); the default test table starts at time 0, so use a
    # table with a later floor.
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "rsk_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(30),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "500",
                    "btc_bits": EASY_BITS,
                    "classification": "unknown",
                }
            ]
        },
        epoch_headers=[
            {"height": 2016, "time": 1_000_000, "bits": EASY_BITS},
            {"height": 4032, "time": 2_000_000, "bits": EASY_BITS},
        ],
    )

    assert rows[0]["btc_stale_relevance"] == "excluded"
    assert rows[0]["relevance_reason"] == "insufficient_evidence"


def test_missing_epoch_headers_cache_excludes_timestamp_only_unknown_row(
    tmp_path: Path,
):
    rows, summary = _run_classifier(
        tmp_path,
        {
            "rsk_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(28),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "unknown",
                }
            ]
        },
        epoch_headers=[],
    )

    assert rows[0]["btc_stale_relevance"] == "excluded"
    assert rows[0]["relevance_reason"] == "insufficient_epoch_cache"
    assert summary["epoch_caches"]["weak_orphan_computation"] == (
        "not_computed_missing_epoch_cache"
    )


def test_xaya_coinbase_scriptsig_is_not_strict_height_evidence(tmp_path: Path):
    altchain_height_inside_btc_range = 300_000
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "xaya_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(11),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "coinbase_scriptsig_hex": _bip34_script(
                        altchain_height_inside_btc_range
                    ),
                    "classification": "unknown",
                }
            ]
        },
        epoch_bits={_epoch_start(altchain_height_inside_btc_range): EASY_BITS},
    )

    assert rows[0]["btc_stale_relevance"] == "weak_btc_orphan"
    assert rows[0]["strict_height_source"] == ""
    assert rows[0]["btc_height"] == ""
    assert rows[0]["source_schema"] == "xaya"
    assert rows[0]["notes"] == ""


def test_non_allowlisted_coinbase_scriptsig_chain_warns(tmp_path: Path):
    rows, summary = _run_classifier(
        tmp_path,
        {
            "futurechain_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(39),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "coinbase_scriptsig_hex": _bip34_script(300_000),
                    "classification": "unknown",
                }
            ]
        },
    )

    assert rows[0]["source_schema"] == "standard"
    assert summary["strict_coinbase_height_allowlist_warnings"] == [
        {
            "chain": "futurechain",
            "warning": (
                "coinbase_scriptsig_hex present but chain is not enabled for "
                "BTC coinbase BIP34 strict-height decoding"
            ),
        }
    ]


def test_weak_orphan_accepts_neighbor_epoch_bits(tmp_path: Path):
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "rsk_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(12),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1500",
                    "btc_bits": "1d00cccc",
                    "classification": "unknown",
                }
            ]
        },
        epoch_headers=[
            {"height": 0, "time": 0, "bits": "1d00aaaa"},
            {"height": 2016, "time": 1000, "bits": "1d00bbbb"},
            {"height": 4032, "time": 2000, "bits": "1d00cccc"},
            {"height": 6048, "time": 3000, "bits": "1d00dddd"},
        ],
    )

    assert rows[0]["btc_stale_relevance"] == "weak_btc_orphan"
    assert rows[0]["expected_nbits_by_time"] == "1d00bbbb"
    assert rows[0]["allowed_nbits_by_time_pm1_epoch"] == "1d00aaaa|1d00bbbb|1d00cccc"


def test_weak_orphan_rejects_bits_two_epochs_away(tmp_path: Path):
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "rsk_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(13),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1500",
                    "btc_bits": "1d00dddd",
                    "classification": "unknown",
                }
            ]
        },
        epoch_headers=[
            {"height": 0, "time": 0, "bits": "1d00aaaa"},
            {"height": 2016, "time": 1000, "bits": "1d00bbbb"},
            {"height": 4032, "time": 2000, "bits": "1d00cccc"},
            {"height": 6048, "time": 3000, "bits": "1d00dddd"},
        ],
    )

    assert rows[0]["btc_stale_relevance"] == "excluded"
    assert rows[0]["relevance_reason"] == "non_btc_epoch_bits"


def test_weak_orphan_does_not_treat_sparse_cache_neighbor_as_pm1_epoch(tmp_path: Path):
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "rsk_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(30),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1500",
                    "btc_bits": "1d00dddd",
                    "classification": "unknown",
                }
            ]
        },
        epoch_headers=[
            {"height": 0, "time": 0, "bits": "1d00aaaa"},
            {"height": 2016, "time": 1000, "bits": "1d00bbbb"},
            {"height": 6048, "time": 2000, "bits": "1d00dddd"},
        ],
    )

    assert rows[0]["btc_stale_relevance"] == "excluded"
    assert rows[0]["relevance_reason"] == "non_btc_epoch_bits"
    assert rows[0]["allowed_nbits_by_time_pm1_epoch"] == "1d00aaaa|1d00bbbb"


def test_weak_orphan_after_time_cache_range_is_pending(tmp_path: Path):
    # Timestamp past the epoch-header table's coverage: pending
    # (monitor-aligned horizon semantics), not excluded.
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "rsk_stale_blocks.csv": [
                {
                    "btc_header_hash": _hash(38),
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "4000",
                    "btc_bits": EASY_BITS,
                    "classification": "unknown",
                }
            ]
        },
        epoch_headers=[
            {"height": 0, "time": 0, "bits": EASY_BITS},
            {"height": 2016, "time": 1000, "bits": EASY_BITS},
        ],
    )

    assert rows[0]["btc_stale_relevance"] == "pending"
    assert rows[0]["relevance_reason"] == "above_nbits_time_horizon"
    assert rows[0]["expected_nbits_by_time"] == ""
    assert rows[0]["allowed_nbits_by_time_pm1_epoch"] == ""


def test_cache_on_mainchain_excludes_otherwise_weak_orphan(tmp_path: Path):
    block_hash = _hash(14)
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "rsk_stale_blocks.csv": [
                {
                    "btc_header_hash": block_hash,
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "unknown",
                }
            ]
        },
        cache_files={
            "shadow-resolver-mainchain-cache.json": {
                block_hash: {"exists": True, "on_mainchain": True, "confirmations": 10}
            }
        },
    )

    assert rows[0]["btc_stale_relevance"] == "excluded"
    assert rows[0]["relevance_reason"] == "known_mainchain"
    assert rows[0]["known_mainchain"] == "true"
    assert rows[0]["mainchain_verification_status"] == "cache_on_mainchain"


def test_null_mainchain_cache_stays_not_checked_and_allows_weak_orphan(tmp_path: Path):
    block_hash = _hash(15)
    rows, summary = _run_classifier(
        tmp_path,
        {
            "rsk_stale_blocks.csv": [
                {
                    "btc_header_hash": block_hash,
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "unknown",
                }
            ]
        },
        cache_files={"shadow-resolver-mainchain-cache.json": {block_hash: None}},
    )

    assert rows[0]["btc_stale_relevance"] == "weak_btc_orphan"
    assert rows[0]["known_mainchain"] == "false"
    assert rows[0]["mainchain_verification_status"] == "not_checked"
    assert summary["mainchain_caches"][0]["unknown_entries"] == 1


def test_null_cache_entry_does_not_override_prior_mainchain_verdict(tmp_path: Path):
    block_hash = _hash(16)
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "rsk_stale_blocks.csv": [
                {
                    "btc_header_hash": block_hash,
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "unknown",
                }
            ]
        },
        cache_files={
            "shadow-resolver-mainchain-cache.json": {
                block_hash: {"exists": True, "on_mainchain": True}
            },
            "orphan_origin_btc_headers_by_hash.json": {block_hash: None},
        },
    )

    assert rows[0]["btc_stale_relevance"] == "excluded"
    assert rows[0]["relevance_reason"] == "known_mainchain"
    assert rows[0]["mainchain_verification_status"] == "cache_on_mainchain"


def test_same_chain_full_and_validated_rows_count_source_rows_but_dedup_hash(
    tmp_path: Path,
):
    duplicate_hash = _hash(36)
    rows, summary = _run_classifier(
        tmp_path,
        {
            "xaya_stale_blocks.csv": [
                {
                    "btc_header_hash": duplicate_hash,
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "stale",
                    "validation_status": "VALID",
                }
            ],
            "xaya_validated_stales.csv": [
                {
                    "btc_header_hash": duplicate_hash,
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "stale",
                    "validation_status": "VALID",
                }
            ],
        },
    )

    confirmed_rows = [
        row
        for row in rows
        if row["btc_stale_relevance"] == ""
        and row["relevance_reason"] == "valid_direct_stale"
    ]
    xaya_unique = [
        row
        for row in summary["unique_confirmed_btc_stale"]["per_chain_unique_hashes"]
        if row["chain"] == "xaya"
    ][0]
    xaya_confirmed_count = [
        row
        for row in summary["row_counts"]["by_chain_and_relevance"]
        if row["chain"] == "xaya" and row["btc_stale_relevance"] == "confirmed"
    ][0]

    assert len(confirmed_rows) == 2
    assert summary["unique_confirmed_btc_stale"]["global_unique_hashes"] == 1
    assert xaya_unique["unique_hashes"] == 1
    assert xaya_confirmed_count["count"] == 2


def test_archive_valid_stale_applies_consensus_exclusion_overlay(tmp_path: Path):
    rows, summary = _run_classifier(
        tmp_path,
        {},
        archive_files={
            "namecoin/classified/namecoin_stale_blocks.csv": [
                {
                    "btc_stale_height": "331735",
                    "btc_hash": EXCLUDED_HASH,
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1417032925",
                    "btc_bits_hex": EASY_BITS,
                    "classification": "stale",
                    "validation_status": "VALID",
                }
            ]
        },
    )

    assert rows == []
    assert summary["unique_confirmed_btc_stale"]["global_unique_hashes"] == 0
    assert summary["row_counts"]["processed_by_source_file"] == []


def test_archive_header_hash_applies_consensus_exclusion_overlay(tmp_path: Path):
    with (PROJECT_ROOT / "data/error-blocks/error_blocks.csv").open(newline="") as f:
        error_row = next(
            row for row in csv.DictReader(f) if row["hash"] == EXCLUDED_HASH
        )

    rows, summary = _run_classifier(
        tmp_path,
        {},
        archive_files={
            "namecoin/classified/namecoin_stale_blocks.csv": [
                {
                    "btc_stale_height": error_row["height"],
                    "btc_hash": "malformed",
                    "btc_header_hex": error_row["btc_header_hex"],
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1417032925",
                    "btc_bits_hex": EASY_BITS,
                    "classification": "unknown",
                }
            ]
        },
    )

    assert rows == []
    assert summary["row_counts"]["processed_by_source_file"] == []


def test_classifier_uses_data_dir_error_block_catalogue(tmp_path: Path):
    excluded_hash = _hash(31)
    rows, summary = _run_classifier(
        tmp_path,
        {
            "error-blocks/error_blocks.csv": [
                {
                    "height": "331735",
                    "hash": excluded_hash,
                    "classification": "error_block",
                }
            ]
        },
        archive_files={
            "namecoin/classified/namecoin_stale_blocks.csv": [
                {
                    "btc_stale_height": "331735",
                    "btc_hash": excluded_hash,
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1417032925",
                    "btc_bits_hex": EASY_BITS,
                    "classification": "stale",
                    "validation_status": "VALID",
                }
            ]
        },
    )

    assert rows == []
    assert summary["row_counts"]["processed_by_source_file"] == []


@pytest.mark.parametrize("source_height", ["331736", ""])
def test_classifier_excludes_error_parent_when_legacy_height_is_wrong_or_blank(
    tmp_path: Path,
    source_height: str,
) -> None:
    excluded_hash = _hash(31)
    included_hash = _hash(32)
    rows, _summary = _run_classifier(
        tmp_path,
        {
            "error-blocks/error_blocks.csv": [
                {
                    "height": "331735",
                    "hash": excluded_hash,
                    "classification": "error_block",
                }
            ]
        },
        archive_files={
            "namecoin/classified/namecoin_stale_blocks.csv": [
                {
                    "btc_stale_height": source_height,
                    "btc_hash": excluded_hash,
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1417032925",
                    "btc_bits_hex": EASY_BITS,
                    "classification": "unknown",
                },
                {
                    "btc_stale_height": source_height,
                    "btc_hash": included_hash,
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1417032925",
                    "btc_bits_hex": EASY_BITS,
                    "classification": "unknown",
                },
            ]
        },
    )

    assert {row["btc_header_hash"] for row in rows} == {included_hash}


def test_check_mainchain_uses_rpc_results_and_truncation(tmp_path: Path, monkeypatch):
    on_chain_hash = _hash(21)
    off_chain_hash = _hash(22)
    calls: list[tuple[list[str], object, int]] = []

    def fake_fetch(hashes, rpc, batch_size):
        query = list(hashes)
        calls.append((query, rpc, batch_size))
        return {
            on_chain_hash: {"exists": True, "on_mainchain": True, "confirmations": 6},
            off_chain_hash: {
                "exists": True,
                "on_mainchain": False,
                "confirmations": -1,
            },
        }

    monkeypatch.setattr(classifier.rec, "fetch_mainchain_status", fake_fetch)
    rows, summary = _run_classifier(
        tmp_path,
        {
            "rsk_stale_blocks.csv": [
                {
                    "btc_header_hash": on_chain_hash,
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "unknown",
                },
                {
                    "btc_header_hash": off_chain_hash,
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "unknown",
                },
            ]
        },
        check_mainchain=True,
        max_mainchain_rpc=2,
    )

    by_hash = {row["btc_header_hash"]: row for row in rows}
    assert len(calls) == 1
    queried, rpc_arg, batch_size = calls[0]
    assert queried == [on_chain_hash, off_chain_hash]
    assert batch_size == 500
    assert isinstance(rpc_arg, classifier.BtcRpc)
    assert by_hash[on_chain_hash]["btc_stale_relevance"] == "excluded"
    assert by_hash[on_chain_hash]["relevance_reason"] == "known_mainchain"
    assert by_hash[on_chain_hash]["mainchain_verification_status"] == "rpc_on_mainchain"
    assert by_hash[off_chain_hash]["btc_stale_relevance"] == "weak_btc_orphan"
    assert (
        by_hash[off_chain_hash]["mainchain_verification_status"] == "rpc_not_mainchain"
    )
    assert summary["mainchain_rpc_check"]["candidate_hashes"] == 2
    assert summary["mainchain_rpc_check"]["queried_hashes"] == 2
    assert summary["mainchain_rpc_check"]["truncated"] is False


def test_check_mainchain_respects_max_rpc_limit(tmp_path: Path, monkeypatch):
    first_hash = _hash(23)
    second_hash = _hash(24)
    seen_queries: list[list[str]] = []

    def fake_fetch(hashes, _rpc, _batch_size):
        query = list(hashes)
        seen_queries.append(query)
        return {first_hash: {"exists": True, "on_mainchain": True, "confirmations": 1}}

    monkeypatch.setattr(classifier.rec, "fetch_mainchain_status", fake_fetch)
    rows, summary = _run_classifier(
        tmp_path,
        {
            "rsk_stale_blocks.csv": [
                {
                    "btc_header_hash": first_hash,
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "unknown",
                },
                {
                    "btc_header_hash": second_hash,
                    "btc_prev_hash": PREV_HASH,
                    "btc_time": "1000000",
                    "btc_bits": EASY_BITS,
                    "classification": "unknown",
                },
            ]
        },
        check_mainchain=True,
        max_mainchain_rpc=1,
    )

    by_hash = {row["btc_header_hash"]: row for row in rows}
    assert seen_queries == [[first_hash]]
    assert by_hash[first_hash]["mainchain_verification_status"] == "rpc_on_mainchain"
    assert by_hash[second_hash]["mainchain_verification_status"] == "not_checked"
    assert summary["mainchain_rpc_check"]["candidate_hashes"] == 2
    assert summary["mainchain_rpc_check"]["queried_hashes"] == 1
    assert summary["mainchain_rpc_check"]["truncated"] is True


def test_missing_upstream_dataset_fails_loudly(tmp_path: Path):
    # A run without data/stale-blocks/stale-blocks.csv must refuse to
    # proceed unless --allow-missing-upstream is passed: with an empty
    # known-stale membership, upstream-known stales would be admitted as
    # strict/weak orphans (this shipped three known stales as "new orphans"
    # once, from a snapshot lacking the gitignored clone).
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    args = SimpleNamespace(
        data_dir=data_dir,
        chain_archive_dirs=[],
        results_dir=tmp_path / "results",
        cache_dir=tmp_path / "cache",
        check_mainchain=False,
        rpc_url="http://127.0.0.1:8332",
        rpc_user=None,
        rpc_pass=None,
        rpc_batch_size=500,
        max_mainchain_rpc=0,
        allow_missing_upstream=False,
    )
    with pytest.raises(SystemExit, match="upstream stale-blocks dataset missing"):
        classifier.run(args)
