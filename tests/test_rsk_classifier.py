from __future__ import annotations

import csv
import importlib.util
import json
import shutil
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from stale_blocks_analysis.auxpow_parse import CHILD_HEADER_FIELDS
from stale_blocks_analysis.config import BIP65_HEIGHT
from stale_blocks_analysis.auxpow_chainid import (
    hash_from_header_bytes,
    hash_to_display_hex,
)
from stale_blocks_analysis.auxpow_parse import ChildHeaderValidationError
from stale_blocks_analysis.evidence_hydration import (
    ChildIdentityIndex,
    hydrate_child_identity,
    load_child_identity,
)
from stale_blocks_analysis.evidence_normalization import (
    iter_source_rows,
    normalize_evidence_row,
)
from stale_blocks_analysis.evidence_sources import EvidenceSource
from stale_blocks_analysis import rsk_extraction as extraction
from stale_blocks_analysis import rsk_classifier_artifacts as artifacts
from stale_blocks_analysis.monitor_exports import build_monitor_evidence_exports
from stale_blocks_analysis.rsk_classifier_artifacts import (
    publish_output_family,
    validate_classifier_manifest_for_artifact,
)
from stale_blocks_analysis.rsk_sidecar import validate_rsk_sidecar_cells


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "classify"
    / "classify_rsk_stales.py"
)
SPEC = importlib.util.spec_from_file_location("classify_rsk_stales", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
rsk = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = rsk
SPEC.loader.exec_module(rsk)

RSK_CHILD_HASH = bytes(range(32)).hex()
OTHER_RSK_CHILD_HASH = bytes(range(32, 64)).hex()


BLOCK_HASH = "11" * 32


def _header(
    prev_hash: str,
    nonce: int,
    bits: int = 0x207FFFFF,
    time: int = 1_700_000_000,
) -> str:
    return (
        struct.pack("<i", 4)
        + bytes.fromhex(prev_hash)[::-1]
        + b"\x11" * 32
        + struct.pack("<I", time)
        + struct.pack("<I", bits)
        + struct.pack("<I", nonce)
    ).hex()


def _header_row(header_hex: str) -> dict[str, str]:
    raw = bytes.fromhex(header_hex)
    return {
        "btc_header_hash": hash_to_display_hex(hash_from_header_bytes(raw)),
        "btc_prev_hash": (raw[4:36][::-1]).hex(),
        "btc_time": str(int.from_bytes(raw[68:72], "little")),
        "btc_bits": f"{int.from_bytes(raw[72:76], 'little'):08x}",
        "btc_header_hex": header_hex,
    }


def _response(*, confirmations: int, height: int = 100) -> dict:
    return {
        "id": 0,
        "result": {
            "hash": BLOCK_HASH,
            "height": height,
            "confirmations": confirmations,
        },
        "error": None,
    }


def test_active_header_distinguishes_active_and_known_side_chain() -> None:
    assert rsk.active_header(_response(confirmations=1), BLOCK_HASH)["height"] == 100
    assert rsk.active_header(_response(confirmations=-1), BLOCK_HASH) is None


def test_rpc_args_use_shared_public_configuration(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "stale_blocks_analysis.btc_rpc._COOKIE_PATHS",
        [str(tmp_path / "no-cookie")],
    )
    monkeypatch.setattr(
        "stale_blocks_analysis.btc_rpc._CONF_PATHS",
        [str(tmp_path / "no-conf")],
    )
    monkeypatch.setenv("BTC_RPC_URL", "http://127.0.0.1:18443")
    monkeypatch.setenv("BITCOIN_RPC_USER", "rsk-user")
    monkeypatch.setenv("BITCOIN_RPC_PASSWORD", "rsk-password")

    args = rsk.parse_args([])
    client = rsk.rpc_from_args(args)

    assert args.rpc_url == "http://127.0.0.1:18443"
    assert client.url == args.rpc_url
    assert client.auth == ("rsk-user", "rsk-password")
    assert not hasattr(rsk, "AUTH")


def test_active_header_requires_valid_height_and_matching_hash() -> None:
    bad_height = _response(confirmations=1)
    bad_height["result"]["height"] = "100"
    with pytest.raises(ValueError, match="valid height"):
        rsk.active_header(bad_height, BLOCK_HASH, require_height=True)

    mismatched = _response(confirmations=1)
    mismatched["result"]["hash"] = "22" * 32
    with pytest.raises(ValueError, match="hash mismatch"):
        rsk.active_header(mismatched, BLOCK_HASH)


def test_canonical_hash_rejects_rpc_errors_and_malformed_results() -> None:
    assert rsk.canonical_hash({"result": BLOCK_HASH, "error": None}, 100) == BLOCK_HASH
    with pytest.raises(RuntimeError, match="getblockhash failed"):
        rsk.canonical_hash(
            {"result": None, "error": {"code": -8, "message": "out of range"}},
            100,
        )
    with pytest.raises(ValueError, match="malformed hash"):
        rsk.canonical_hash({"result": "not-a-hash", "error": None}, 100)


def test_stale_validation_rejects_signed_negative_post_bip65_version() -> None:
    row = {
        "btc_bits": "17275a1f",
        "btc_header_hex": (bytes.fromhex("000000a0") + b"\x00" * 76).hex(),
    }

    row["btc_time"] = "1001"
    error = rsk.stale_validation_error(row, BIP65_HEIGHT, "17275a1f", 1000)

    assert error is not None
    assert "required 4 after BIP65" in error


def test_stale_validation_rejects_median_time_past_failure() -> None:
    row = {
        "btc_bits": "17275a1f",
        "btc_time": "1000",
        "btc_header_hex": (bytes.fromhex("00000020") + b"\x00" * 76).hex(),
    }

    error = rsk.stale_validation_error(row, BIP65_HEIGHT, "17275a1f", 1000)

    assert error is not None
    assert "median-time-past" in error


def test_rejected_rows_route_to_error_block_or_unknown() -> None:
    # One height past BIP65 (and not a retarget-epoch start), so the version
    # minimum is 4 and the unapplied-retarget rule is not in play.
    height = BIP65_HEIGHT + 1
    parent_mtp = 1_700_000_000

    # Proven consensus violation: header time is not above the parent's MTP.
    violation = _header_row(_header("22" * 32, 1, time=parent_mtp))
    # Contamination: full proof of work, but not Bitcoin's difficulty here.
    contamination = _header_row(
        _header("22" * 32, 2, bits=0x1D00FFFF, time=parent_mtp + 1)
    )
    clean = _header_row(_header("22" * 32, 3, time=parent_mtp + 1))

    verified, stale_rows, error_blocks, rerouted_unknowns = rsk.gate_and_route(
        [
            (height, violation, parent_mtp),
            (height, contamination, parent_mtp),
            (height, clean, parent_mtp),
        ],
        {height: "207fffff"},
    )

    assert [row for _, row in error_blocks] == [violation]
    assert "median-time-past" in violation["validation_status"]
    assert [row for _, row in rerouted_unknowns] == [contamination]
    assert [row for _, row in stale_rows] == [clean]
    assert [row for _, row in verified] == [clean]
    assert clean["validation_status"] == "VALID"


def test_row_to_out_preserves_miner_evidence_without_pool_attribution() -> None:
    row = {
        "btc_header_hash": "11" * 32,
        "btc_prev_hash": "22" * 32,
        "btc_time": "1000",
        "btc_bits": "17275a1f",
        "rsk_height": "123",
        "rsk_timestamp": "1001",
        "rsk_miner": "33" * 20,
        "merge_mining_hash": "44" * 32,
        "btc_header_hex": "00" * 80,
        "coinbase_op_return": "",
        "coinbase_ascii_strings": "",
    }

    output = rsk.row_to_out(row, "unknown")

    assert output["rsk_miner"] == row["rsk_miner"]
    assert "pool_label" not in output
    assert "pool_label" not in rsk.OUT_COLS


def test_candidate_header_is_corroborated_and_self_pow_checked() -> None:
    passing = next(
        row
        for nonce in range(10_000)
        if rsk.validate_candidate_header(
            row := _header_row(_header("22" * 32, nonce)), nonce + 2
        )["meets_pow"]
    )
    assert rsk.validate_candidate_header(passing, 2)["meets_pow"] is True

    mismatched = dict(passing)
    mismatched["btc_prev_hash"] = "33" * 32
    with pytest.raises(ValueError, match="btc_prev_hash does not match"):
        rsk.validate_candidate_header(mismatched, 2)

    failing = next(
        row
        for nonce in range(10_000)
        if not rsk.validate_candidate_header(
            row := _header_row(_header("22" * 32, nonce)), nonce + 2
        )["meets_pow"]
    )
    assert rsk.validate_candidate_header(failing, 2)["meets_pow"] is False


def test_validated_rows_apply_exact_key_exclusions_and_historical_labels() -> None:
    base = {
        "btc_header_hash": "11" * 32,
        "btc_prev_hash": "22" * 32,
        "btc_time": "1000",
        "btc_bits": "17275a1f",
        "btc_header_hex": "00" * 80,
        "rsk_height": "123",
        "rsk_timestamp": "1001",
        "rsk_miner": "AA" * 20,
        "merge_mining_hash": "44" * 32,
        "coinbase_op_return": "",
        "coinbase_ascii_strings": "",
        "expected_nbits": "17275a1f",
    }
    other = {**base, "btc_header_hash": "33" * 32, "rsk_height": "124"}

    rows = rsk.build_validated_rows(
        [(500, base), (501, other)],
        {("aa" * 20): "Historical Pool"},
        {(500, "11" * 32)},
    )

    assert len(rows) == 1
    assert rows[0]["btc_height"] == "501"
    assert rows[0]["validation_status"] == "VALID"
    assert rows[0]["pool_label"] == "Historical Pool"
    assert list(rows[0]) == rsk.VALIDATED_COLS


def test_validated_cols_match_the_committed_loader_input_schema() -> None:
    """The emitted schema must equal the committed CSV's, not just itself.

    `data/validated-stales/rsk_validated_stales.csv` gained the four
    child-identity columns when the uniform child-identity contract landed,
    but `VALIDATED_COLS` was not updated with it. Re-running the classifier
    would then have silently rewritten a published loader input with a
    narrower schema. Compare against the committed header so the pairing
    cannot drift again.
    """
    committed = (
        Path(__file__).resolve().parents[1]
        / "data"
        / "validated-stales"
        / "rsk_validated_stales.csv"
    )
    with committed.open(newline="") as handle:
        header = next(csv.reader(handle))
    assert rsk.VALIDATED_COLS == header
    for field in CHILD_HEADER_FIELDS:
        assert field in rsk.VALIDATED_COLS


def test_canonical_companion_uses_the_private_rsk_inventory_contract() -> None:
    base = {
        "btc_header_hash": "11" * 32,
        "btc_prev_hash": "22" * 32,
        "btc_time": "1000",
        "btc_bits": "17275a1f",
        "btc_header_hex": "00" * 80,
        "rsk_height": "124",
        "rsk_timestamp": "1001",
        "rsk_hash": RSK_CHILD_HASH,
        "rsk_miner": "33" * 20,
        "merge_mining_hash": "44" * 32,
        "merge_mining_merkle_proof": "0405",
        "coinbase_tail_hex": "aabb",
        "coinbase_op_return": "",
        "coinbase_ascii_strings": "",
        "is_uncle": "1",
        "uncle_index": "0",
        "uncle_parent_height": "125",
    }
    earlier = {
        **base,
        "btc_header_hash": "55" * 32,
        "rsk_height": "123",
        "rsk_hash": OTHER_RSK_CHILD_HASH,
        "is_uncle": "0",
        "uncle_index": "",
        "uncle_parent_height": "",
    }
    rows = rsk.build_canonical_output_rows([(700_001, base), (700_000, earlier)])

    assert list(rows[0]) == rsk.OUT_COLS
    assert [row["btc_stale_height"] for row in rows] == [700000, 700001]
    assert [row["classification"] for row in rows] == ["canonical", "canonical"]
    assert all(not row["validation_status"] for row in rows)
    assert all(not row["expected_nbits"] for row in rows)
    assert rows[1]["is_uncle"] == "1"
    assert rows[1]["rsk_block_hash"] == RSK_CHILD_HASH
    assert rows[1]["rsk_block_hash"] != bytes.fromhex(RSK_CHILD_HASH)[::-1].hex()
    assert rows[1]["child_block_time"] == "1001"
    assert rows[1]["rsk_merkle_proof"] == "0405"
    assert rows[1]["rsk_coinbase_tail"] == "aabb"


def test_canonical_companion_requires_exact_sidecar_overlay_without_hybrids(
    tmp_path: Path,
) -> None:
    header_hex = _header("22" * 32, 1)
    header = _header_row(header_hex)
    raw = {
        **header,
        "rsk_height": "124",
        "rsk_timestamp": "1700000001",
        "rsk_hash": RSK_CHILD_HASH,
        "rsk_miner": "33" * 20,
        "merge_mining_hash": "44" * 32,
        "merge_mining_merkle_proof": "0405",
        "coinbase_tail_hex": "aabb",
        "coinbase_op_return": "",
        "coinbase_ascii_strings": "",
        "is_uncle": "1",
        "uncle_index": "0",
        "uncle_parent_height": "125",
    }
    output = tmp_path / "rsk_canonical_blocks.csv"
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rsk.OUT_COLS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rsk.build_canonical_output_rows([(700_000, raw)]))
    source = EvidenceSource(
        chain="rsk",
        display_name="RSK / Rootstock",
        path=output,
        source_kind="canonical_blocks",
        artifact_scope="canonical_blocks",
        provenance="archive",
    )

    def normalized_source_rows() -> list[dict[str, str]]:
        with output.open(newline="") as handle:
            reader = csv.DictReader(handle)
            return [
                normalize_evidence_row(source, row, reader.fieldnames, number)[0]
                for number, row in enumerate(reader, start=2)
            ]

    normalized = normalized_source_rows()
    no_sidecar = hydrate_child_identity(normalized, ChildIdentityIndex())
    assert normalized[0]["child_block_hash"] == RSK_CHILD_HASH
    assert normalized[0]["child_block_time"] == "1700000001"
    assert no_sidecar.canonical_unhydrated == 0
    assert no_sidecar.targets == 0

    normalized = normalized_source_rows()
    exact_row = {
        "chain": "rsk",
        "btc_header_hash": header["btc_header_hash"],
        "child_height": "124",
        "child_block_hash": RSK_CHILD_HASH,
        "child_block_time": "1700000001",
        "verification": "merged_mining_header_match",
        "rsk_miner": "33" * 20,
        "merge_mining_hash": "44" * 32,
        "is_uncle": "1",
        "uncle_index": "0",
        "uncle_parent_height": "125",
        "rsk_merkle_proof": "0405",
        "rsk_coinbase_tail": "aabb",
    }

    def index_for(row: dict[str, str]) -> ChildIdentityIndex:
        index = ChildIdentityIndex()
        index.add(("rsk", header["btc_header_hash"]), row)
        return index

    sidecar = index_for(exact_row)
    hydrated = hydrate_child_identity(normalized, sidecar)
    assert hydrated.hydrated == 1
    assert hydrated.canonical_unhydrated == 0
    assert normalized[0]["child_block_hash"] == RSK_CHILD_HASH
    assert normalized[0]["rsk_merkle_proof"] == "0405"
    assert normalized[0]["rsk_coinbase_tail"] == "aabb"

    for field, value in (
        ("child_height", "125"),
        ("child_block_hash", "77" * 32),
    ):
        normalized = normalized_source_rows()
        disagreeing = {**exact_row, field: value}
        unrelated = hydrate_child_identity(
            normalized,
            index_for(disagreeing),
        )
        assert unrelated.targets == 0
        assert normalized[0]["child_block_hash"] == RSK_CHILD_HASH

    for field, value in (("rsk_miner", "88" * 20), ("child_block_time", "1700000002")):
        normalized = normalized_source_rows()
        with pytest.raises(ChildHeaderValidationError, match="disagrees"):
            hydrate_child_identity(normalized, index_for({**exact_row, field: value}))


def test_rsk_repeated_parent_observations_keep_distinct_child_identity(
    tmp_path: Path,
) -> None:
    btc_hash = "11" * 32
    primary = {
        "chain": "rsk",
        "classification": "canonical",
        "btc_height": "700000",
        "btc_header_hash": btc_hash,
        "child_height": "100",
        "child_block_hash": RSK_CHILD_HASH,
    }
    distinct = {
        **primary,
        "child_height": "101",
        "child_block_hash": OTHER_RSK_CHILD_HASH,
    }
    identity_path = tmp_path / "data" / "child-identity" / "rsk_child_identity.csv"
    identity_path.parent.mkdir(parents=True)
    fields = [
        "chain",
        "btc_header_hash",
        "child_height",
        "child_block_hash",
        "child_block_time",
        "verification",
        "rsk_miner",
        "merge_mining_hash",
        "is_uncle",
        "uncle_index",
        "uncle_parent_height",
        "rsk_merkle_proof",
        "rsk_coinbase_tail",
    ]
    with identity_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in (primary, distinct):
            writer.writerow(
                {
                    "chain": row["chain"],
                    "btc_header_hash": row["btc_header_hash"],
                    "child_height": row["child_height"],
                    "child_block_hash": row["child_block_hash"],
                    "child_block_time": "1700000001",
                    "verification": "merged_mining_header_match",
                    "rsk_miner": "33" * 20,
                    "merge_mining_hash": "44" * 32,
                    "is_uncle": "0",
                    "uncle_index": "",
                    "uncle_parent_height": "",
                    "rsk_merkle_proof": "0405",
                    "rsk_coinbase_tail": "aabb",
                }
            )
    identity = load_child_identity(tmp_path / "data")
    assert len(identity.candidates(("rsk", btc_hash))) == 2


def _sealed_empty_extraction(tmp_path: Path) -> tuple[Path, Path]:
    raw = tmp_path / "rsk_auxpow_raw.csv"
    checkpoint = extraction.default_checkpoint_path(raw)
    skips = extraction.default_skip_ledger_path(raw)
    identity = {
        "height": 0,
        "hash": "66" * 32,
        "parent_hash": "55" * 32,
        "timestamp": 1_518_000_000,
    }
    state = extraction.prepare_extraction(
        raw,
        checkpoint,
        skips,
        start=0,
        end=1,
        start_identity=identity,
        end_identity=identity,
        resume=False,
    )
    stats = extraction.empty_stats()
    stats["skipped_pre_auxpow"] = 1
    state = extraction.commit_interval(
        raw,
        checkpoint,
        skips,
        state,
        rows=[],
        skips=[
            {
                "rsk_height": 0,
                "rsk_timestamp": identity["timestamp"],
                "rsk_hash": identity["hash"],
                "is_uncle": 0,
                "uncle_index": "",
                "uncle_parent_height": "",
                "advertised_uncle_hash": "",
                "proof_bytes": 1,
                "reason": "genesis_sentinel",
            }
        ],
        stats_delta=stats,
        next_height=1,
        first_identity=identity,
        last_identity=identity,
        advertised_uncles=0,
    )
    extraction.seal_extraction(
        raw,
        checkpoint,
        skips,
        state,
        rechecked_end_identity=identity,
    )
    return raw, checkpoint


def _classifier_args(tmp_path: Path, raw: Path, checkpoint: Path) -> SimpleNamespace:
    pool_registry = tmp_path / "rsk_pool_registry.csv"
    pool_registry.write_text("rsk_miner,pool_label\n")
    error_blocks = tmp_path / "error_blocks.csv"
    error_blocks.write_text(
        "height,hash,classification\n0," + "11" * 32 + ",error_block\n"
    )
    return SimpleNamespace(
        input=str(raw),
        checkpoint=str(checkpoint),
        stales_out=str(tmp_path / "rsk_stale_blocks.csv"),
        canonical_out=str(tmp_path / "rsk_canonical_blocks.csv"),
        validated_out=str(tmp_path / "rsk_validated_stales.csv"),
        error_blocks_out=str(tmp_path / "rsk_error_blocks.csv"),
        pool_registry=str(pool_registry),
        error_blocks=str(error_blocks),
        summary_out=str(tmp_path / "rsk_classification_summary.txt"),
        manifest_out=str(tmp_path / "rsk_classification_manifest.json"),
    )


def test_classifier_rejects_aliased_output_paths(tmp_path: Path) -> None:
    raw, checkpoint = _sealed_empty_extraction(tmp_path)
    args = _classifier_args(tmp_path, raw, checkpoint)
    args.validated_out = args.stales_out
    with pytest.raises(ValueError, match="aliases"):
        rsk.validate_distinct_paths(
            args,
            args.canonical_out,
            args.error_blocks_out,
            args.manifest_out,
            checkpoint,
        )

    args = _classifier_args(tmp_path, raw, checkpoint)
    args.summary_out = str(rsk.CLASSIFIER_PATH)
    with pytest.raises(ValueError, match="classifier script"):
        rsk.validate_distinct_paths(
            args,
            args.canonical_out,
            args.error_blocks_out,
            args.manifest_out,
            checkpoint,
        )


def test_classifier_rejects_undiscoverable_manifest_path(tmp_path: Path) -> None:
    raw, checkpoint = _sealed_empty_extraction(tmp_path)
    args = _classifier_args(tmp_path, raw, checkpoint)

    for manifest_out in (
        tmp_path / "opaque.json",
        tmp_path / "elsewhere" / "rsk_classification_manifest.json",
    ):
        with pytest.raises(ValueError, match="colocated"):
            artifacts.validate_manifest_output_path(args.stales_out, manifest_out)


def test_classifier_refuses_an_incomplete_checkpoint_before_bitcoin_rpc(
    monkeypatch, tmp_path: Path
) -> None:
    raw = tmp_path / "rsk_auxpow_raw.csv"
    checkpoint = extraction.default_checkpoint_path(raw)
    skips = extraction.default_skip_ledger_path(raw)
    identity = {
        "height": 0,
        "hash": "66" * 32,
        "parent_hash": "55" * 32,
        "timestamp": 1_518_000_000,
    }
    extraction.prepare_extraction(
        raw,
        checkpoint,
        skips,
        start=0,
        end=1,
        start_identity=identity,
        end_identity=identity,
        resume=False,
    )
    args = _classifier_args(tmp_path, raw, checkpoint)
    rpc_called = False

    def forbidden_rpc(_args):
        nonlocal rpc_called
        rpc_called = True
        raise AssertionError("Bitcoin RPC must not be constructed")

    monkeypatch.setattr(rsk, "parse_args", lambda: args)
    monkeypatch.setattr(rsk, "rpc_from_args", forbidden_rpc)
    with pytest.raises(ValueError, match="not complete"):
        rsk.main()
    assert not rpc_called


def test_empty_complete_input_stages_a_hash_bound_output_family(
    monkeypatch, tmp_path: Path
) -> None:
    raw, checkpoint = _sealed_empty_extraction(tmp_path)
    args = _classifier_args(tmp_path, raw, checkpoint)

    tip_hash = "22" * 32

    class ContextOnlyRPC:
        def batch(self, calls):
            responses = []
            for call in calls:
                if call["method"] == "getblockchaininfo":
                    result = {
                        "chain": "main",
                        "blocks": 900_000,
                        "headers": 900_000,
                        "bestblockhash": tip_hash,
                        "initialblockdownload": False,
                    }
                elif call["method"] == "getnetworkinfo":
                    result = {"version": 280000}
                elif call["method"] == "getblockhash":
                    result = tip_hash
                else:
                    raise AssertionError(f"empty input called {call['method']}")
                responses.append({"id": call["id"], "result": result, "error": None})
            return responses

    monkeypatch.setattr(rsk, "parse_args", lambda: args)
    monkeypatch.setattr(rsk, "rpc_from_args", lambda _args: ContextOnlyRPC())
    monkeypatch.setattr(rsk, "load_error_block_keys", lambda _path: set())
    monkeypatch.setattr(rsk, "load_pool_labels", lambda _path: {})
    monkeypatch.setattr(
        rsk,
        "repository_code_context",
        lambda: {"git_commit": "aa" * 20, "dirty": False},
    )

    rsk.main()

    summary = Path(args.summary_out).read_text()
    assert "0.000%" in summary
    manifest = json.loads(Path(args.manifest_out).read_text())
    checkpoint_state = json.loads(checkpoint.read_text())
    assert manifest["input"]["content_sha256"] == checkpoint_state["content_sha256"]
    assert manifest["input"]["checkpoint_sha256"] == extraction.sha256_file(checkpoint)
    assert set(manifest["outputs"]) == {
        "canonical",
        "stale_unknown",
        "error_blocks",
        "validated_stales",
        "summary",
    }
    assert set(manifest["dependencies"]) == {
        "classifier_script",
        "error_blocks",
        "pool_registry",
    }
    assert manifest["classification"]["bitcoin_core"]["start"]["hash"] == tip_hash
    assert manifest["classification"]["bitcoin_core"]["end"]["hash"] == tip_hash
    for artifact in manifest["outputs"].values():
        path = Path(args.manifest_out).parent / artifact["path"]
        assert path.is_file()
        assert extraction.sha256_file(path) == artifact["sha256"]
    canonical_path = Path(args.canonical_out)
    assert validate_classifier_manifest_for_artifact(canonical_path) == manifest
    source = EvidenceSource(
        chain="rsk",
        display_name="RSK / Rootstock",
        path=canonical_path,
        source_kind="canonical_blocks",
        artifact_scope="canonical_blocks",
        provenance="archive",
    )
    assert list(iter_source_rows(source)) == []

    manifest_path = Path(args.manifest_out)
    dirty_manifest = {
        **manifest,
        "classification": {
            **manifest["classification"],
            "code": {**manifest["classification"]["code"], "dirty": True},
        },
    }
    manifest_path.write_text(json.dumps(dirty_manifest))
    with pytest.raises(ValueError, match="classifier code context"):
        validate_classifier_manifest_for_artifact(canonical_path)
    manifest_path.write_text(json.dumps(manifest))

    pool_registry = Path(args.pool_registry)
    original_registry = pool_registry.read_bytes()
    pool_registry.write_bytes(original_registry + b"00,Changed\n")
    with pytest.raises(ValueError, match="dependency pool_registry"):
        list(iter_source_rows(source))
    pool_registry.write_bytes(original_registry)

    checkpoint_bytes = checkpoint.read_bytes()
    checkpoint.write_bytes(checkpoint_bytes + b" ")
    with pytest.raises(ValueError, match="checkpoint digest"):
        list(iter_source_rows(source))
    checkpoint.write_bytes(checkpoint_bytes)

    with canonical_path.open("a") as output:
        output.write("corrupt\n")
    with pytest.raises(ValueError, match="failed content verification"):
        list(iter_source_rows(source))


def test_classifier_rechecks_raw_input_before_publication(
    monkeypatch, tmp_path: Path
) -> None:
    raw, checkpoint = _sealed_empty_extraction(tmp_path)
    args = _classifier_args(tmp_path, raw, checkpoint)
    tip_hash = "22" * 32

    class ContextOnlyRPC:
        def batch(self, calls):
            responses = []
            for call in calls:
                if call["method"] == "getblockchaininfo":
                    result = {
                        "chain": "main",
                        "blocks": 900_000,
                        "headers": 900_000,
                        "bestblockhash": tip_hash,
                        "initialblockdownload": False,
                    }
                elif call["method"] == "getnetworkinfo":
                    result = {"version": 280000}
                elif call["method"] == "getblockhash":
                    result = tip_hash
                else:
                    raise AssertionError(f"empty input called {call['method']}")
                responses.append({"id": call["id"], "result": result, "error": None})
            return responses

    context = {"git_commit": "aa" * 20, "dirty": False}
    context_calls = 0

    def mutate_before_final_input_check():
        nonlocal context_calls
        context_calls += 1
        if context_calls == 2:
            raw.write_bytes(raw.read_bytes() + b"\n")
        return context

    monkeypatch.setattr(rsk, "parse_args", lambda: args)
    monkeypatch.setattr(rsk, "rpc_from_args", lambda _args: ContextOnlyRPC())
    monkeypatch.setattr(rsk, "load_error_block_keys", lambda _path: set())
    monkeypatch.setattr(rsk, "load_pool_labels", lambda _path: {})
    monkeypatch.setattr(rsk, "repository_code_context", mutate_before_final_input_check)

    with pytest.raises(ValueError, match="raw extraction changed"):
        rsk.main()
    assert not Path(args.manifest_out).exists()


def test_classifier_refuses_dirty_worktree_before_bitcoin_rpc(
    monkeypatch, tmp_path: Path
) -> None:
    raw, checkpoint = _sealed_empty_extraction(tmp_path)
    args = _classifier_args(tmp_path, raw, checkpoint)
    rpc_called = False

    def forbidden_rpc(_args):
        nonlocal rpc_called
        rpc_called = True
        raise AssertionError("Bitcoin RPC must not be constructed")

    monkeypatch.setattr(rsk, "parse_args", lambda: args)
    monkeypatch.setattr(rsk, "rpc_from_args", forbidden_rpc)
    monkeypatch.setattr(
        rsk,
        "repository_code_context",
        lambda: {"git_commit": "aa" * 20, "dirty": True},
    )

    with pytest.raises(ValueError, match="clean repository worktree"):
        rsk.main()
    assert not rpc_called


def _sealed_one_row_extraction(
    tmp_path: Path,
) -> tuple[Path, Path, dict[str, str], dict]:
    raw = tmp_path / "inputs" / "rsk_auxpow_raw.csv"
    checkpoint = extraction.default_checkpoint_path(raw)
    skips = extraction.default_skip_ledger_path(raw)
    header = _header_row(_header("22" * 32, 1))
    identity = {
        "height": 0,
        "hash": RSK_CHILD_HASH,
        "parent_hash": "ff" * 32,
        "timestamp": 1_700_000_001,
    }
    row = dict.fromkeys(extraction.RAW_COLUMNS, "")
    row.update(
        {
            **header,
            "rsk_height": "0",
            "rsk_timestamp": str(identity["timestamp"]),
            "rsk_hash": identity["hash"],
            "rsk_miner": "33" * 20,
            "rsk_difficulty": "1",
            "merge_mining_hash": "44" * 32,
            "merge_mining_merkle_proof": "0405",
            "coinbase_tail_hex": "aabb",
            "is_uncle": "0",
        }
    )
    state = extraction.prepare_extraction(
        raw,
        checkpoint,
        skips,
        start=0,
        end=1,
        start_identity=identity,
        end_identity=identity,
        resume=False,
    )
    stats = extraction.empty_stats()
    stats["auxpow_blocks"] = 1
    state = extraction.commit_interval(
        raw,
        checkpoint,
        skips,
        state,
        rows=[row],
        skips=[],
        stats_delta=stats,
        next_height=1,
        first_identity=identity,
        last_identity=identity,
        advertised_uncles=0,
    )
    sealed = extraction.seal_extraction(
        raw,
        checkpoint,
        skips,
        state,
        rechecked_end_identity=identity,
    )
    return raw, checkpoint, row, sealed


def _publication_dependencies(tmp_path: Path) -> dict[str, Path]:
    error_blocks = tmp_path / "dependencies" / "error_blocks.csv"
    pool_registry = tmp_path / "dependencies" / "rsk_pool_registry.csv"
    error_blocks.parent.mkdir(parents=True, exist_ok=True)
    error_blocks.write_text("height,hash,classification\n")
    pool_registry.write_text("rsk_miner,pool_label\n")
    return {
        "classifier_script": SCRIPT,
        "error_blocks": error_blocks,
        "pool_registry": pool_registry,
    }


def _publish_one_canonical_family(
    tmp_path: Path, *, stale_observations: bool = False
) -> tuple[Path, dict[str, Path]]:
    _raw, checkpoint, row, checkpoint_state = _sealed_one_row_extraction(tmp_path)
    relocated = tmp_path / "retained-inputs"
    checkpoint.parent.rename(relocated)
    checkpoint = relocated / checkpoint.name
    assert (
        extraction.load_complete_extraction(relocated / _raw.name, checkpoint)
        == checkpoint_state
    )
    classified = tmp_path / "archive" / "chains" / "rsk" / "classified"
    paths = {
        "canonical": classified / "rsk_canonical_blocks.csv",
        "stale_unknown": classified / "rsk_stale_blocks.csv",
        "error_blocks": classified / "rsk_error_blocks.csv",
        "validated_stales": classified / "rsk_validated_stales.csv",
        "summary": classified / "rsk_classification_summary.txt",
        "manifest": classified / "rsk_classification_manifest.json",
    }
    dependencies = _publication_dependencies(tmp_path)
    publish_output_family(
        csv_artifacts=[
            (
                "canonical",
                paths["canonical"],
                rsk.OUT_COLS,
                rsk.build_canonical_output_rows(
                    [] if stale_observations else [(700_000, row)]
                ),
            ),
            (
                "stale_unknown",
                paths["stale_unknown"],
                rsk.OUT_COLS,
                [
                    rsk.row_to_out(observation, "stale", btc_stale_height=700_000)
                    for observation in (
                        row,
                        {**row, "rsk_hash": "ab" * 32, "rsk_height": "1"},
                    )
                ]
                if stale_observations
                else [],
            ),
            ("error_blocks", paths["error_blocks"], rsk.ERROR_BLOCK_COLS, []),
            (
                "validated_stales",
                paths["validated_stales"],
                rsk.VALIDATED_COLS,
                [],
            ),
        ],
        summary_path=paths["summary"],
        summary_text="one canonical RSK observation\n",
        manifest_path=paths["manifest"],
        checkpoint_path=checkpoint,
        checkpoint_state=checkpoint_state,
        dependency_paths=dependencies,
        expected_dependency_fingerprints=rsk.dependency_fingerprints(dependencies),
        classification_context={
            "bitcoin_core": {
                "start": {
                    "chain": "main",
                    "height": 700_000,
                    "headers": 700_000,
                    "hash": "55" * 32,
                    "initial_block_download": False,
                    "version": 280000,
                },
                "end": {
                    "chain": "main",
                    "height": 700_000,
                    "headers": 700_000,
                    "hash": "55" * 32,
                    "initial_block_download": False,
                    "version": 280000,
                },
            },
            "code": {"git_commit": "aa" * 20, "dirty": False},
        },
    )
    return tmp_path / "archive", paths


def test_nonempty_manifested_classifier_family_reaches_monitor_publication(
    tmp_path: Path,
) -> None:
    from test_monitor_exports import _write_stale_descendant_module

    _write_stale_descendant_module(tmp_path / "data", chain="ixcoin")
    archive, paths = _publish_one_canonical_family(tmp_path)
    output_dir = tmp_path / "monitor"

    build_monitor_evidence_exports(
        data_dir=tmp_path / "data",
        output_dir=output_dir,
        chain_archive_dirs=[archive],
        relevance_inventory=None,
    )

    with (output_dir / "rsk_monitor_evidence.csv").open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["classification"] == "canonical"
    assert rows[0]["child_block_hash"] == RSK_CHILD_HASH
    assert rows[0]["rsk_miner"] == "33" * 20
    assert validate_classifier_manifest_for_artifact(paths["canonical"])


def test_publisher_rejects_cross_alias_and_late_dependency_change(
    monkeypatch, tmp_path: Path
) -> None:
    _raw, checkpoint, _row, checkpoint_state = _sealed_one_row_extraction(tmp_path)
    classified = tmp_path / "classified"
    dependencies = _publication_dependencies(tmp_path)
    fingerprints = rsk.dependency_fingerprints(dependencies)
    csv_artifacts = [
        ("canonical", classified / "rsk_canonical_blocks.csv", rsk.OUT_COLS, []),
        ("stale_unknown", classified / "rsk_stale_blocks.csv", rsk.OUT_COLS, []),
        ("error_blocks", classified / "rsk_error_blocks.csv", rsk.ERROR_BLOCK_COLS, []),
        (
            "validated_stales",
            classified / "rsk_validated_stales.csv",
            rsk.VALIDATED_COLS,
            [],
        ),
    ]
    context = {
        "bitcoin_core": {
            label: {
                "chain": "main",
                "height": 1,
                "headers": 1,
                "hash": "55" * 32,
                "initial_block_download": False,
                "version": 280000,
            }
            for label in ("start", "end")
        },
        "code": {"git_commit": "aa" * 20, "dirty": False},
    }

    with pytest.raises(ValueError, match="aliases output summary"):
        publish_output_family(
            csv_artifacts=csv_artifacts,
            summary_path=SCRIPT,
            summary_text="summary\n",
            manifest_path=classified / "rsk_classification_manifest.json",
            checkpoint_path=checkpoint,
            checkpoint_state=checkpoint_state,
            dependency_paths=dependencies,
            expected_dependency_fingerprints=fingerprints,
            classification_context=context,
        )

    real_stage_text = artifacts._stage_text

    def stage_then_mutate(path: Path, value: str):
        staged = real_stage_text(path, value)
        dependencies["pool_registry"].write_text("rsk_miner,pool_label\n00,changed\n")
        return staged

    monkeypatch.setattr(artifacts, "_stage_text", stage_then_mutate)
    with pytest.raises(ValueError, match="dependency changed during the run"):
        publish_output_family(
            csv_artifacts=csv_artifacts,
            summary_path=classified / "rsk_classification_summary.txt",
            summary_text="summary\n",
            manifest_path=classified / "rsk_classification_manifest.json",
            checkpoint_path=checkpoint,
            checkpoint_state=checkpoint_state,
            dependency_paths=dependencies,
            expected_dependency_fingerprints=fingerprints,
            classification_context=context,
        )
    assert not (classified / "rsk_classification_manifest.json").exists()
    assert not any(path.exists() for _label, path, _columns, _rows in csv_artifacts)


def test_classifier_rejects_core_reorg_through_start_tip() -> None:
    start_hash = "22" * 32
    replacement_hash = "33" * 32

    class ReorgedRPC:
        def batch(self, calls):
            responses = []
            for call in calls:
                if call["method"] == "getblockchaininfo":
                    result = {
                        "chain": "main",
                        "blocks": 900_001,
                        "headers": 900_001,
                        "bestblockhash": "44" * 32,
                        "initialblockdownload": False,
                    }
                elif call["method"] == "getnetworkinfo":
                    result = {"version": 280000}
                elif call["method"] == "getblockhash":
                    result = replacement_hash
                else:
                    raise AssertionError(f"unexpected RPC {call['method']}")
                responses.append({"id": call["id"], "result": result, "error": None})
            return responses

    start = {
        "chain": "main",
        "height": 900_000,
        "headers": 900_000,
        "hash": start_hash,
        "initial_block_download": False,
        "version": 280000,
    }
    with pytest.raises(ValueError, match="changed through the pinned start tip"):
        rsk.verify_bitcoin_core_context(ReorgedRPC(), start)


def test_rsk_sidecar_rejects_unicode_decimal_cells() -> None:
    row = {
        "rsk_miner": "33" * 20,
        "merge_mining_hash": "44" * 32,
        "is_uncle": "1",
        "uncle_index": "\u0661",
        "uncle_parent_height": "100",
        "rsk_merkle_proof": "0405",
        "rsk_coinbase_tail": "aabb",
    }
    with pytest.raises(ValueError, match="non-negative signed 32-bit int"):
        validate_rsk_sidecar_cells(row, row_id="unicode-numeric")


def test_manifest_repository_dependencies_survive_different_archive_layout(
    monkeypatch, tmp_path: Path
) -> None:
    source_repo = tmp_path / "checkout-a"
    dependency_paths = {
        "classifier_script": source_repo
        / "scripts"
        / "classify"
        / "classify_rsk_stales.py",
        "error_blocks": source_repo / "data" / "error-blocks" / "error_blocks.csv",
        "pool_registry": source_repo / "results" / "rsk_pool_registry.csv",
    }
    for label, path in dependency_paths.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(label + "\n")
    monkeypatch.setattr(artifacts, "PROJECT_ROOT", source_repo)
    monkeypatch.setattr(
        sys.modules[__name__],
        "_publication_dependencies",
        lambda _path: dependency_paths,
    )
    source_run = tmp_path / "source-run"
    source_run.mkdir()
    _archive, paths = _publish_one_canonical_family(source_run)
    manifest = json.loads(paths["manifest"].read_text())
    assert all(
        record["path_base"] == "repository"
        for record in manifest["dependencies"].values()
    )
    assert (
        manifest["dependencies"]["pool_registry"]["path"]
        == "results/rsk_pool_registry.csv"
    )

    destination_repo = tmp_path / "vm" / "repos" / "research"
    destination_run = tmp_path / "vm" / "archives" / "rsk-run"
    destination_repo.parent.mkdir(parents=True)
    destination_run.parent.mkdir(parents=True)
    shutil.move(source_repo, destination_repo)
    shutil.move(source_run, destination_run)
    monkeypatch.setattr(artifacts, "PROJECT_ROOT", destination_repo)
    canonical = destination_run / paths["canonical"].relative_to(source_run)
    assert validate_classifier_manifest_for_artifact(canonical) == manifest
    (destination_repo / "results" / "rsk_pool_registry.csv").write_text("changed\n")
    with pytest.raises(
        ValueError, match="dependency pool_registry failed content verification"
    ):
        validate_classifier_manifest_for_artifact(canonical)


def test_fresh_stale_witnesses_survive_compact_verdict_join(tmp_path: Path) -> None:
    from test_monitor_exports import _write_stale_descendant_module

    data = tmp_path / "data"
    _write_stale_descendant_module(data, chain="ixcoin")
    archive, paths = _publish_one_canonical_family(tmp_path, stale_observations=True)
    with paths["stale_unknown"].open(newline="") as handle:
        observations = list(csv.DictReader(handle))
    compact = data / "validated-stales" / "rsk_validated_stales.csv"
    compact.parent.mkdir(parents=True, exist_ok=True)
    # Use the actual compact schema, with no child hash or sidecar ledger.
    verdict = rsk.validated_row(observations[0], 700_000, {})
    with compact.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rsk.VALIDATED_COLS)
        writer.writeheader()
        writer.writerow(verdict)
    output = tmp_path / "monitor"
    build_monitor_evidence_exports(
        data_dir=data,
        output_dir=output,
        chain_archive_dirs=[archive],
        relevance_inventory=None,
        fail_on_missing_child_identity=True,
    )
    with (output / "rsk_monitor_evidence.csv").open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 2
    assert {row["child_block_hash"] for row in rows} == {RSK_CHILD_HASH, "ab" * 32}
    assert all(row["classification"] == "stale" for row in rows)
    assert all(row["validation_status"] == "VALID" for row in rows)
    assert all(row["rsk_coinbase_tail"] == "aabb" for row in rows)
    # An absent or rejecting compact verdict must never promote source stales.
    for replacement in (
        None,
        {**verdict, "validation_status": "REJECTED"},
        {**verdict, "btc_height": "700001", "validation_status": "REJECTED"},
    ):
        with compact.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=rsk.VALIDATED_COLS)
            writer.writeheader()
            if replacement is not None:
                writer.writerow(replacement)
        build_monitor_evidence_exports(
            data_dir=data,
            output_dir=output,
            chain_archive_dirs=[archive],
            relevance_inventory=None,
        )
        with (output / "rsk_monitor_evidence.csv").open(newline="") as handle:
            assert list(csv.DictReader(handle)) == []
