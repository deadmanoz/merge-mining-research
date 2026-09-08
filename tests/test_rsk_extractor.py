from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

from stale_blocks_analysis import rsk_extraction as contract


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "extract"
    / "extract_rsk_auxpow.py"
)
SPEC = importlib.util.spec_from_file_location("extract_rsk_auxpow", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
rsk = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = rsk
SPEC.loader.exec_module(rsk)


def _hash(number: int) -> str:
    return f"{number:064x}"


def _header(nonce: int, *, previous_wire: bytes | None = None) -> str:
    return (
        struct.pack("<i", 4)
        + (previous_wire if previous_wire is not None else bytes(range(32)))
        + bytes(range(32, 64))
        + struct.pack("<I", 1_700_000_000)
        + struct.pack("<I", 0x207FFFFF)
        + struct.pack("<I", nonce)
    ).hex()


def _block(
    height: int,
    nonce: int,
    *,
    block_hash: str | None = None,
    parent_hash: str | None = None,
    uncles: list[str] | None = None,
    proof_hex: str | None = None,
) -> dict:
    return {
        "number": hex(height),
        "timestamp": hex(1_700_000_001 + height),
        "hash": "0x" + (block_hash or _hash(height + 100)),
        "parentHash": "0x" + (parent_hash or _hash(height + 99)),
        "miner": "0x" + "33" * 20,
        "difficulty": "0x1",
        "bitcoinMergedMiningHeader": "0x" + (proof_hex or _header(nonce)),
        "bitcoinMergedMiningCoinbaseTransaction": "0x",
        "bitcoinMergedMiningMerkleProof": "0x44",
        "hashForMergedMining": "0x" + "55" * 32,
        "uncles": ["0x" + value for value in (uncles or [])],
    }


def _identity(height: int, block_hash: str, parent_hash: str) -> dict:
    return {
        "height": height,
        "hash": block_hash,
        "parent_hash": parent_hash,
        "timestamp": 1_700_000_001 + height,
    }


def _raw_row(height: int) -> dict[str, object]:
    header_hex = _header(height)
    header = rsk.parse_header(bytes.fromhex(header_hex))
    row: dict[str, object] = dict.fromkeys(contract.RAW_COLUMNS, "")
    row["rsk_height"] = height
    row["rsk_timestamp"] = 1_700_000_001 + height
    row["rsk_hash"] = _hash(height + 100)
    row["rsk_miner"] = "33" * 20
    row["rsk_difficulty"] = "1"
    row["btc_header_hash"] = header["hash"]
    row["btc_prev_hash"] = header["prev_hash"]
    row["btc_time"] = header["timestamp"]
    row["btc_bits"] = header["bits"]
    row["merge_mining_hash"] = "55" * 32
    row["merge_mining_merkle_proof"] = "44"
    row["btc_header_hex"] = header_hex
    row["is_uncle"] = 0
    return row


def _paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    output = tmp_path / "rsk_auxpow_raw.2026-08-29.csv"
    return (
        output,
        contract.default_checkpoint_path(output),
        contract.default_skip_ledger_path(output),
    )


def test_ordered_rpc_results_require_exact_integer_ids() -> None:
    assert rsk.ordered_rpc_results(
        [{"id": 1, "result": "b"}, {"id": 0, "result": "a"}], 2, "test"
    ) == [{"id": 0, "result": "a"}, {"id": 1, "result": "b"}]
    for bad_id in (True, 0.0, "0"):
        with pytest.raises(requests.RequestException, match="non-integer"):
            rsk.ordered_rpc_results([{"id": bad_id, "result": {}}], 1, "test")


@pytest.mark.parametrize(
    "payload",
    [
        {"error": "malformed top-level error"},
        [{"id": 0, "error": ["malformed per-call error"]}],
    ],
)
def test_malformed_rpc_error_payloads_remain_retryable(monkeypatch, payload) -> None:
    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self):
            return payload

    monkeypatch.setattr(rsk.requests, "post", lambda *_args, **_kwargs: Response())
    with pytest.raises(requests.RequestException, match="error"):
        rsk.rpc_batch([{"id": 0, "method": "test", "params": []}])


def test_parse_header_uses_explicit_asymmetric_wire_order() -> None:
    previous_wire = bytes(range(32))
    raw = bytes.fromhex(_header(7, previous_wire=previous_wire))
    parsed = rsk.parse_header(raw)

    assert parsed["prev_hash"] == previous_wire[::-1].hex()
    assert parsed["prev_hash"] != previous_wire.hex()
    assert (
        parsed["hash"]
        == hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
    )


@pytest.mark.parametrize("length", [69, 70])
def test_only_known_fallback_lengths_are_ledgered(length: int) -> None:
    block = _block(10, 1, proof_hex="ab" * length)
    identity = _identity(10, _hash(110), _hash(109))

    row, skip = rsk.block_to_record(block, identity)

    assert row is None
    assert skip["proof_bytes"] == length
    assert skip["reason"] == "fallback_signature"
    assert skip["rsk_hash"] == identity["hash"]


def test_height_zero_one_byte_genesis_sentinel_is_the_only_extra_skip() -> None:
    genesis = _block(0, 1, proof_hex="00")
    identity = _identity(0, _hash(100), _hash(99))

    row, skip = rsk.block_to_record(genesis, identity)

    assert row is None
    assert skip["proof_bytes"] == 1
    assert skip["reason"] == "genesis_sentinel"

    with pytest.raises(requests.RequestException, match="unsupported"):
        rsk.block_to_record(
            _block(1, 1, proof_hex="00"), _identity(1, _hash(101), _hash(100))
        )


@pytest.mark.parametrize("proof", ["", "ab" * 68, "ab" * 71, "not-hex"])
def test_every_other_missing_or_malformed_proof_shape_fails(proof: str) -> None:
    block = _block(10, 1)
    block["bitcoinMergedMiningHeader"] = "0x" + proof
    with pytest.raises(requests.RequestException):
        rsk.block_to_record(block, _identity(10, _hash(110), _hash(109)))


def test_extract_range_validates_cross_rpc_batch_continuity_and_uncle_hash(
    monkeypatch,
) -> None:
    hashes = {10: _hash(110), 11: _hash(111), 12: _hash(112)}
    advertised_uncle = _hash(900)
    blocks = {
        10: _block(10, 1, block_hash=hashes[10], parent_hash=_hash(109)),
        11: _block(11, 2, block_hash=hashes[11], parent_hash=hashes[10]),
        12: _block(
            12,
            3,
            block_hash=hashes[12],
            parent_hash=hashes[11],
            uncles=[advertised_uncle],
        ),
    }
    uncle = _block(11, 4, block_hash=advertised_uncle, parent_hash=hashes[10])

    def rpc(calls):
        responses = []
        for call in calls:
            if call["method"] == "eth_getBlockByNumber":
                height = int(call["params"][0], 16)
                result = blocks[height]
            else:
                result = uncle
            responses.append({"id": call["id"], "result": result})
        return list(reversed(responses))

    monkeypatch.setattr(rsk, "rpc_batch", rpc)
    result = rsk.extract_range(
        10,
        13,
        rpc_batch_size=2,
        previous_hash=_hash(109),
        expected_start_identity=_identity(10, hashes[10], _hash(109)),
    )
    rows, skips, stats, first, last, uncle_count = result

    assert not skips
    assert [row["rsk_height"] for row in rows] == [10, 11, 12, 11]
    assert stats == {
        "auxpow_blocks": 3,
        "skipped_pre_auxpow": 0,
        "uncle_auxpow_blocks": 1,
        "uncle_skipped_pre_auxpow": 0,
    }
    assert first["hash"] == hashes[10]
    assert last["hash"] == hashes[12]
    assert uncle_count == 1


def test_extract_range_rejects_broken_continuity_across_rpc_batches(
    monkeypatch,
) -> None:
    blocks = {
        10: _block(10, 1, block_hash=_hash(110), parent_hash=_hash(109)),
        11: _block(11, 2, block_hash=_hash(111), parent_hash=_hash(999)),
    }

    def rpc(calls):
        height = int(calls[0]["params"][0], 16)
        return [{"id": 0, "result": blocks[height]}]

    monkeypatch.setattr(rsk, "rpc_batch", rpc)
    with pytest.raises(requests.RequestException, match="continuity break"):
        rsk.extract_range(10, 12, rpc_batch_size=1, previous_hash=_hash(109))


def test_null_canonical_and_null_listed_uncle_are_retry_failures(monkeypatch) -> None:
    monkeypatch.setattr(rsk, "rpc_batch", lambda _calls: [{"id": 0, "result": None}])
    with pytest.raises(requests.RequestException, match="null/non-object block"):
        rsk.extract_range(10, 11)

    canonical = _block(10, 1, uncles=[_hash(900)])
    calls_seen = 0

    def null_uncle(_calls):
        nonlocal calls_seen
        calls_seen += 1
        return [{"id": 0, "result": canonical if calls_seen == 1 else None}]

    monkeypatch.setattr(rsk, "rpc_batch", null_uncle)
    with pytest.raises(requests.RequestException, match="null/non-object uncle"):
        rsk.extract_range(10, 11)


def test_advertised_uncle_hash_must_match_fetched_uncle(monkeypatch) -> None:
    canonical = _block(10, 1, uncles=[_hash(900)])
    wrong_uncle = _block(9, 2, block_hash=_hash(901))
    calls_seen = 0

    def rpc(_calls):
        nonlocal calls_seen
        calls_seen += 1
        return [{"id": 0, "result": canonical if calls_seen == 1 else wrong_uncle}]

    monkeypatch.setattr(rsk, "rpc_batch", rpc)
    with pytest.raises(requests.RequestException, match="advertised"):
        rsk.extract_range(10, 11)


def test_resume_truncates_uncheckpointed_tails_in_both_artifacts(
    monkeypatch, tmp_path: Path
) -> None:
    output, checkpoint, skips = _paths(tmp_path)
    start_identity = _identity(0, _hash(100), _hash(99))
    end_identity = _identity(1, _hash(101), _hash(100))
    state = contract.prepare_extraction(
        output,
        checkpoint,
        skips,
        start=0,
        end=2,
        start_identity=start_identity,
        end_identity=end_identity,
        resume=False,
    )
    raw_header = output.read_bytes()
    skip_header = skips.read_bytes()
    real_writer = contract.write_json_atomic

    def fail_checkpoint(*_args, **_kwargs):
        raise OSError("checkpoint interrupted")

    monkeypatch.setattr(contract, "write_json_atomic", fail_checkpoint)
    stats = contract.empty_stats()
    stats["auxpow_blocks"] = 1
    with pytest.raises(OSError, match="checkpoint interrupted"):
        contract.commit_interval(
            output,
            checkpoint,
            skips,
            state,
            rows=[_raw_row(0)],
            skips=[],
            stats_delta=stats,
            next_height=1,
            first_identity=start_identity,
            last_identity=start_identity,
            advertised_uncles=0,
        )
    assert output.stat().st_size > len(raw_header)

    monkeypatch.setattr(contract, "write_json_atomic", real_writer)
    resumed = contract.prepare_extraction(
        output,
        checkpoint,
        skips,
        start=0,
        end=2,
        start_identity=start_identity,
        end_identity=end_identity,
        resume=True,
    )
    assert resumed["next_height"] == 0
    assert output.read_bytes() == raw_header
    assert skips.read_bytes() == skip_header


def test_retry_to_success_commits_each_height_once(monkeypatch, tmp_path: Path) -> None:
    output, checkpoint, skips = _paths(tmp_path)
    start_identity = _identity(0, _hash(100), _hash(99))
    end_identity = _identity(1, _hash(101), _hash(100))
    attempts = 0

    def retrying_interval(*_args, **_kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise requests.RequestException("transient archive read")
        stats = contract.empty_stats()
        stats["auxpow_blocks"] = 2
        return (
            [_raw_row(0), _raw_row(1)],
            [],
            stats,
            start_identity,
            end_identity,
            0,
        )

    args = SimpleNamespace(
        start=0,
        end=2,
        output=output,
        checkpoint=None,
        skip_ledger=None,
        batch_size=1,
        checkpoint_interval=2,
        resume=False,
    )
    monkeypatch.setattr(rsk, "parse_args", lambda: args)
    monkeypatch.setattr(rsk, "get_chain_tip", lambda: 1)
    monkeypatch.setattr(
        rsk,
        "get_block_identity",
        lambda height: start_identity if height == 0 else end_identity,
    )
    monkeypatch.setattr(rsk, "extract_range", retrying_interval)
    monkeypatch.setattr(rsk.time, "sleep", lambda _seconds: None)

    rsk.main()

    with output.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    state = json.loads(checkpoint.read_text())
    assert attempts == 2
    assert [row["rsk_height"] for row in rows] == ["0", "1"]
    assert len({row["rsk_hash"] for row in rows}) == 2
    assert state["output_rows"] == 2
    assert len(state["commits"]) == 1
    assert state["complete"] is True
    assert skips.is_file()


def test_complete_checkpoint_binds_bytes_and_endpoint_recheck(
    tmp_path: Path,
) -> None:
    output, checkpoint, skips = _paths(tmp_path)
    identity = _identity(0, _hash(100), _hash(99))
    state = contract.prepare_extraction(
        output,
        checkpoint,
        skips,
        start=0,
        end=1,
        start_identity=identity,
        end_identity=identity,
        resume=False,
    )
    stats = contract.empty_stats()
    stats["auxpow_blocks"] = 1
    state = contract.commit_interval(
        output,
        checkpoint,
        skips,
        state,
        rows=[_raw_row(0)],
        skips=[],
        stats_delta=stats,
        next_height=1,
        first_identity=identity,
        last_identity=identity,
        advertised_uncles=0,
    )
    with pytest.raises(ValueError, match="end identity changed"):
        contract.seal_extraction(
            output,
            checkpoint,
            skips,
            state,
            rechecked_end_identity={**identity, "hash": _hash(101)},
        )
    sealed = contract.seal_extraction(
        output,
        checkpoint,
        skips,
        state,
        rechecked_end_identity=identity,
    )
    assert sealed["complete"]
    assert contract.load_complete_extraction(output, checkpoint) == sealed

    content = bytearray(output.read_bytes())
    content[-2] = ord("9") if content[-2] != ord("9") else ord("8")
    output.write_bytes(content)
    with pytest.raises(ValueError, match="digest mismatch"):
        contract.load_complete_extraction(output, checkpoint)


def test_checkpoint_rejects_malformed_raw_rows_and_endpoint_drift(
    tmp_path: Path,
) -> None:
    output, checkpoint, skips = _paths(tmp_path)
    identity = _identity(0, _hash(100), _hash(99))
    state = contract.prepare_extraction(
        output,
        checkpoint,
        skips,
        start=0,
        end=1,
        start_identity=identity,
        end_identity=identity,
        resume=False,
    )
    stats = contract.empty_stats()
    stats["auxpow_blocks"] = 1
    malformed = {**_raw_row(0), "btc_header_hex": "00" * 79}
    with pytest.raises(ValueError, match="btc_header_hex"):
        contract.commit_interval(
            output,
            checkpoint,
            skips,
            state,
            rows=[malformed],
            skips=[],
            stats_delta=stats,
            next_height=1,
            first_identity=identity,
            last_identity=identity,
            advertised_uncles=0,
        )

    wrong_identity = {**_raw_row(0), "rsk_hash": _hash(101)}
    with pytest.raises(ValueError, match="endpoint outcome identity"):
        contract.commit_interval(
            output,
            checkpoint,
            skips,
            state,
            rows=[wrong_identity],
            skips=[],
            stats_delta=stats,
            next_height=1,
            first_identity=identity,
            last_identity=identity,
            advertised_uncles=0,
        )


def test_checkpoint_rejects_broken_count_partition(tmp_path: Path) -> None:
    output, checkpoint, skips = _paths(tmp_path)
    identity = _identity(0, _hash(100), _hash(99))
    state = contract.prepare_extraction(
        output,
        checkpoint,
        skips,
        start=0,
        end=1,
        start_identity=identity,
        end_identity=identity,
        resume=False,
    )
    stats = contract.empty_stats()
    stats["auxpow_blocks"] = 1
    with pytest.raises(ValueError, match="partition invariant"):
        contract.commit_interval(
            output,
            checkpoint,
            skips,
            state,
            rows=[],
            skips=[],
            stats_delta=stats,
            next_height=1,
            first_identity=identity,
            last_identity=identity,
            advertised_uncles=0,
        )


def test_checkpoint_rejects_duplicate_uncle_outcome_identity(tmp_path: Path) -> None:
    output, checkpoint, skips = _paths(tmp_path)
    identity = _identity(0, _hash(100), _hash(99))
    state = contract.prepare_extraction(
        output,
        checkpoint,
        skips,
        start=0,
        end=1,
        start_identity=identity,
        end_identity=identity,
        resume=False,
    )
    uncle = {
        **_raw_row(0),
        "rsk_hash": _hash(900),
        "is_uncle": 1,
        "uncle_index": 0,
        "uncle_parent_height": 0,
    }
    stats = contract.empty_stats()
    stats["auxpow_blocks"] = 1
    stats["uncle_auxpow_blocks"] = 2
    with pytest.raises(ValueError, match="duplicate outcome identities"):
        contract.commit_interval(
            output,
            checkpoint,
            skips,
            state,
            rows=[_raw_row(0), uncle, dict(uncle)],
            skips=[],
            stats_delta=stats,
            next_height=1,
            first_identity=identity,
            last_identity=identity,
            advertised_uncles=2,
        )


def test_cli_splits_rpc_batch_from_durable_checkpoint_interval(tmp_path: Path) -> None:
    args = rsk.parse_args(
        [
            "--start",
            "0",
            "--end",
            "140000",
            "--output",
            str(tmp_path / "rsk.csv"),
            "--batch-size",
            "17",
            "--checkpoint-interval",
            "2500",
        ]
    )
    assert args.batch_size == 17
    assert args.checkpoint_interval == 2500


def test_completed_checkpoint_json_contains_content_digests(tmp_path: Path) -> None:
    output, checkpoint, skips = _paths(tmp_path)
    identity = _identity(0, _hash(100), _hash(99))
    state = contract.prepare_extraction(
        output,
        checkpoint,
        skips,
        start=0,
        end=1,
        start_identity=identity,
        end_identity=identity,
        resume=False,
    )
    stats = contract.empty_stats()
    stats["skipped_pre_auxpow"] = 1
    skip = {
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
    state = contract.commit_interval(
        output,
        checkpoint,
        skips,
        state,
        rows=[],
        skips=[skip],
        stats_delta=stats,
        next_height=1,
        first_identity=identity,
        last_identity=identity,
        advertised_uncles=0,
    )
    contract.seal_extraction(
        output,
        checkpoint,
        skips,
        state,
        rechecked_end_identity=identity,
    )
    persisted = json.loads(checkpoint.read_text())
    assert len(persisted["content_sha256"]) == 64
    assert len(persisted["skip_ledger_sha256"]) == 64
    assert persisted["output_rows"] == 0
    assert persisted["skip_rows"] == 1
    assert persisted["last_canonical_identity"] == identity
    assert persisted["commits"][0]["first_canonical_identity"] == identity
    assert persisted["commits"][0]["last_canonical_identity"] == identity

    tampered = bytearray(skips.read_bytes())
    tampered[-2] = ord("8") if tampered[-2] != ord("8") else ord("9")
    skips.write_bytes(tampered)
    with pytest.raises(ValueError, match="committed segment 0 digest mismatch"):
        contract.load_complete_extraction(output, checkpoint)
