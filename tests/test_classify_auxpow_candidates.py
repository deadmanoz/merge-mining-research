"""Focused tests for the generic batched AuxPoW candidate classifier."""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import struct
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "classify" / "classify_auxpow_candidates.py"


def _load_classifier():
    spec = importlib.util.spec_from_file_location("_classify_auxpow_candidates", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _DispatchRpc:
    """Small fake for the shared BtcRpc.batch surface."""

    def __init__(self, dispatch):
        self.dispatch = dispatch
        self.batches = []

    def batch(self, calls):
        self.batches.append(calls)
        responses = [self.dispatch(call) for call in calls]
        return list(reversed(responses))


def _success(call, result):
    return {"id": call["id"], "result": result, "error": None}


def _error(call, code, message):
    return {
        "id": call["id"],
        "result": None,
        "error": {"code": code, "message": message},
    }


def _header(
    block_hash,
    *,
    height,
    confirmations,
    bits="18013ce9",
    mediantime=1_600_000_000,
):
    return {
        "hash": block_hash,
        "height": height,
        "confirmations": confirmations,
        "bits": bits,
        "mediantime": mediantime,
    }


def _compact_target(bits: int) -> int:
    size = bits >> 24
    word = bits & 0x007FFFFF
    if size <= 3:
        return word >> (8 * (3 - size))
    return word << (8 * (size - 3))


def _bip34_scriptsig(height):
    encoded = bytearray()
    value = height
    while value:
        encoded.append(value & 0xFF)
        value >>= 8
    if encoded[-1] & 0x80:
        encoded.append(0)
    return (bytes([len(encoded)]) + bytes(encoded) + b"pool-data").hex()


def _candidate(prev_hash, bits, child_height, *, nonce_seed=0, bip34_height=478_559):
    bits_value = int(bits, 16)
    timestamp = 1_700_000_000 + child_height
    prefix = (
        struct.pack("<i", 4)
        + bytes.fromhex(prev_hash)[::-1]
        + bytes([child_height & 0xFF]) * 32
        + struct.pack("<II", timestamp, bits_value)
    )
    target = _compact_target(bits_value)
    nonce = nonce_seed
    while True:
        header = prefix + struct.pack("<I", nonce)
        internal_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
        if int.from_bytes(internal_hash, "little") <= target:
            break
        nonce += 1
    child_timestamp = 1_600_000_000 + child_height
    child_nbits = 0x1D00FFFF
    child_header = (
        struct.pack("<i", 1)
        + b"\x33" * 32
        + bytes([child_height & 0xFF]) * 32
        + struct.pack("<III", child_timestamp, child_nbits, child_height)
    )
    child_hash = hashlib.sha256(hashlib.sha256(child_header).digest()).digest()
    return {
        "btc_hash": internal_hash[::-1].hex(),
        "btc_prev_hash": prev_hash,
        "btc_time": str(timestamp),
        "btc_bits_hex": bits,
        "btc_bip34_height": str(bip34_height),
        "btc_nonce": str(nonce),
        "coinbase_scriptsig_hex": _bip34_scriptsig(bip34_height),
        "coinbase_outputs": "[]",
        "btc_header_hex": header.hex(),
        "child_height": str(child_height),
        "child_block_hash": child_hash.hex(),
        "child_header_hex": child_header.hex(),
        "child_block_time": str(child_timestamp),
        "child_nbits": f"{child_nbits:08x}",
    }


def test_classifier_batches_mixed_canonical_stale_orphan_and_validates_nbits(
    tmp_path,
):
    mod = _load_classifier()

    canonical_parent = "11" * 32
    rejected_parent = "12" * 32
    missing_parent = "13" * 32
    expected_valid = "21" * 32
    expected_rejected = "22" * 32

    rows = [
        _candidate("10" * 32, "207fffff", 10, nonce_seed=1),
        _candidate(canonical_parent, "207fffff", 11, nonce_seed=2),
        _candidate(missing_parent, "207fffff", 12, nonce_seed=3),
        _candidate(
            rejected_parent,
            "207fffff",
            13,
            nonce_seed=4,
            bip34_height=500_001,
        ),
    ]
    canonical, stale_valid, unknown, stale_rejected = (row["btc_hash"] for row in rows)

    header_results = {
        canonical: _header(
            canonical, height=400_000, confirmations=80, bits="207fffff"
        ),
        canonical_parent: _header(canonical_parent, height=478_558, confirmations=300),
        rejected_parent: _header(rejected_parent, height=500_000, confirmations=200),
        expected_valid: _header(
            expected_valid,
            height=478_559,
            confirmations=299,
            bits="207fffff",
        ),
        expected_rejected: _header(
            expected_rejected,
            height=500_001,
            confirmations=199,
            bits="1d00ffff",
        ),
    }
    missing_headers = {stale_valid, unknown, stale_rejected, missing_parent}
    height_hashes = {478_559: expected_valid, 500_001: expected_rejected}

    def dispatch(call):
        method = call["method"]
        value = call["params"][0]
        if method == "getblockheader":
            if value in missing_headers:
                return _error(call, -5, "Block not found")
            return _success(call, header_results[value])
        if method == "getblockhash":
            return _success(call, height_hashes[value])
        raise AssertionError(f"unexpected RPC method {method}")

    fake_rpc = _DispatchRpc(dispatch)
    client = mod.RpcClient(rpc=fake_rpc, batch_size=2)
    input_path = tmp_path / "candidates.csv"
    output_path = tmp_path / "validated.csv"
    rejected_path = tmp_path / "rejected.csv"
    evidence_path = tmp_path / "evidence.csv"
    classified_path = tmp_path / "classified.csv"
    publication_path = tmp_path / "i0coin_stale_blocks.csv"
    rows[0]["extraction_note"] = "preserved"
    with input_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    mod.classify_and_validate(
        input_path,
        output_path,
        rejected_path,
        client,
        evidence_csv=evidence_path,
        classified_csv=classified_path,
        publication_csv=publication_path,
    )

    with output_path.open(newline="") as f:
        output_reader = csv.DictReader(f)
        assert output_reader.fieldnames == mod.OUTPUT_FIELDS
        validated = list(output_reader)
    with rejected_path.open(newline="") as f:
        rejected_reader = csv.DictReader(f)
        assert rejected_reader.fieldnames == mod.OUTPUT_FIELDS
        rejected = list(rejected_reader)
    with evidence_path.open(newline="") as f:
        evidence_reader = csv.DictReader(f)
        assert evidence_reader.fieldnames == mod.EVIDENCE_FIELDS
        evidence = list(evidence_reader)
    with classified_path.open(newline="") as f:
        classified_reader = csv.DictReader(f)
        assert classified_reader.fieldnames == [
            *rows[0].keys(),
            *[
                field
                for field in mod.CLASSIFIED_ANNOTATION_FIELDS
                if field not in rows[0]
            ],
        ]
        classified = list(classified_reader)

    assert [row["btc_header_hash"] for row in validated] == [stale_valid]
    assert validated[0]["btc_prev_hash"] == canonical_parent
    assert validated[0]["btc_height"] == "478559"
    assert validated[0]["btc_bits"] == "207fffff"
    assert validated[0]["expected_nbits"] == "207fffff"
    assert validated[0]["validation_status"] == (
        "VALID (post-BCH, difficulty matches BTC)"
    )
    assert validated[0]["child_height"] == "11"
    assert validated[0]["child_block_hash"] == rows[1]["child_block_hash"]
    assert validated[0]["child_block_time"] == str(1_600_000_011)

    assert [row["btc_header_hash"] for row in rejected] == [stale_rejected]
    assert rejected[0]["btc_prev_hash"] == rejected_parent
    assert rejected[0]["expected_nbits"] == "1d00ffff"
    assert "likely BCH/BSV block" in rejected[0]["validation_status"]

    assert [row["btc_hash"] for row in evidence] == [canonical, stale_valid]
    canonical_evidence, stale_evidence = evidence
    assert canonical_evidence["classification"] == "canonical"
    assert canonical_evidence["btc_stale_height"] == "400000"
    assert canonical_evidence["btc_bits_hex"] == "207fffff"
    assert canonical_evidence["expected_nbits"] == "207fffff"
    assert canonical_evidence["nbits_match"] == "true"
    assert canonical_evidence["post_bch_fork"] == "false"
    assert canonical_evidence["validation_status"] == (
        "VALID (canonical Bitcoin block)"
    )
    assert canonical_evidence["child_height"] == "10"
    assert canonical_evidence["child_block_hash"] == rows[0]["child_block_hash"]
    assert canonical_evidence["child_block_time"] == str(1_600_000_010)
    assert stale_evidence["btc_hash"] == validated[0]["btc_header_hash"]
    assert stale_evidence["btc_stale_height"] == validated[0]["btc_height"]
    assert stale_evidence["nbits_match"] == "true"
    assert stale_evidence["post_bch_fork"] == "true"

    assert [row["btc_hash"] for row in classified] == [
        canonical,
        stale_valid,
        unknown,
        stale_rejected,
    ]
    assert [row["classification"] for row in classified] == [
        "canonical",
        "stale",
        "unknown",
        "stale",
    ]
    assert classified[0]["extraction_note"] == "preserved"
    assert classified[1]["validation_status"].startswith("VALID")
    assert classified[2]["validation_status"] == (
        "UNKNOWN: parent is not on the active Bitcoin chain"
    )
    assert "nBits mismatch" in classified[3]["validation_status"]

    with publication_path.open(newline="") as f:
        publication_stales = list(csv.DictReader(f))
    with (tmp_path / "i0coin_canonical_blocks.csv").open(newline="") as f:
        publication_canonical = list(csv.DictReader(f))
    with (tmp_path / "i0coin_unknown_blocks.csv").open(newline="") as f:
        publication_unknown = list(csv.DictReader(f))
    assert [row["btc_header_hash"] for row in publication_canonical] == [canonical]
    assert [row["btc_header_hash"] for row in publication_stales] == [
        stale_valid,
        stale_rejected,
    ]
    assert [row["btc_header_hash"] for row in publication_unknown] == [unknown]
    assert all(
        list(row) == mod.OUTPUT_FIELDS
        for row in [
            *publication_canonical,
            *publication_stales,
            *publication_unknown,
        ]
    )
    assert publication_stales[0]["child_header_hex"] == rows[1]["child_header_hex"]
    assert publication_stales[0]["expected_nbits"] == "207fffff"
    assert publication_stales[0]["validation_status"].startswith("VALID")
    assert publication_canonical[0]["expected_nbits"] == ""
    assert publication_canonical[0]["validation_status"] == ""
    assert publication_unknown[0]["expected_nbits"] == ""
    assert publication_unknown[0]["validation_status"] == ""

    assert max(len(batch) for batch in fake_rpc.batches) <= 2
    # No spurious cache hits on distinct hashes; the exact call/batch totals
    # are incidental to this fixture's shape and deliberately not pinned.
    assert client._stats["cache_hits"] == 0

    # Publication-only mode allocates the full classified inventory internally.
    # This second run covers every outcome the generic classifier can produce:
    # canonical, accepted stale, rejected stale, and unknown.
    publication_only_path = tmp_path / "publication_only_stale_blocks.csv"
    mod.classify_and_validate(
        input_path,
        tmp_path / "publication_only_validated.csv",
        tmp_path / "publication_only_rejected.csv",
        client,
        publication_csv=publication_only_path,
    )
    with publication_only_path.open(newline="") as f:
        assert len(list(csv.DictReader(f))) == 2
    with (tmp_path / "publication_only_canonical_blocks.csv").open(newline="") as f:
        assert len(list(csv.DictReader(f))) == 1
    with (tmp_path / "publication_only_unknown_blocks.csv").open(newline="") as f:
        assert len(list(csv.DictReader(f))) == 1


def test_classifier_rejects_bip34_height_mismatch_even_when_nbits_match(tmp_path):
    mod = _load_classifier()
    parent = "31" * 32
    canonical_at_height = "32" * 32
    row = _candidate(
        parent,
        "207fffff",
        20,
        nonce_seed=5,
        bip34_height=478_560,
    )

    def dispatch(call):
        method = call["method"]
        value = call["params"][0]
        if method == "getblockheader" and value == row["btc_hash"]:
            return _error(call, -5, "Block not found")
        if method == "getblockheader" and value == parent:
            return _success(call, _header(parent, height=478_558, confirmations=2))
        if method == "getblockhash":
            assert value == 478_559
            return _success(call, canonical_at_height)
        if method == "getblockheader" and value == canonical_at_height:
            return _success(
                call,
                _header(
                    canonical_at_height,
                    height=478_559,
                    confirmations=1,
                    bits="207fffff",
                ),
            )
        raise AssertionError(f"unexpected RPC call {call}")

    input_path = tmp_path / "candidates.csv"
    output_path = tmp_path / "validated.csv"
    rejected_path = tmp_path / "rejected.csv"
    evidence_path = tmp_path / "evidence.csv"
    with input_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)

    mod.classify_and_validate(
        input_path,
        output_path,
        rejected_path,
        mod.RpcClient(rpc=_DispatchRpc(dispatch)),
        evidence_csv=evidence_path,
    )

    with output_path.open(newline="") as f:
        assert list(csv.DictReader(f)) == []
    with rejected_path.open(newline="") as f:
        rejected = list(csv.DictReader(f))
    assert len(rejected) == 1
    assert rejected[0]["expected_nbits"] == "207fffff"
    assert rejected[0]["validation_status"] == (
        "REJECTED: BIP34 coinbase height mismatch (got 478560, expected 478559)"
    )
    with evidence_path.open(newline="") as f:
        assert list(csv.DictReader(f)) == []


def test_classifier_does_not_create_evidence_file_by_default(tmp_path):
    mod = _load_classifier()
    fake_rpc = _DispatchRpc(lambda call: pytest.fail(f"unexpected RPC call: {call}"))
    client = mod.RpcClient(rpc=fake_rpc)
    input_path = tmp_path / "empty.csv"
    output_path = tmp_path / "validated.csv"
    rejected_path = tmp_path / "rejected.csv"
    implicit_evidence_path = tmp_path / "validated_evidence.csv"
    with input_path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "btc_hash",
                "btc_prev_hash",
                "btc_time",
                "btc_bits_hex",
                "coinbase_scriptsig_hex",
                "coinbase_outputs",
                "child_height",
                "child_block_hash",
                "child_header_hex",
                "child_block_time",
                "child_nbits",
            ],
        )
        writer.writeheader()

    mod.classify_and_validate(input_path, output_path, rejected_path, client)

    assert output_path.exists()
    assert rejected_path.exists()
    assert not implicit_evidence_path.exists()


@pytest.mark.parametrize(
    "missing_field",
    [
        "child_height",
        "child_block_hash",
        "child_header_hex",
        "child_block_time",
        "child_nbits",
    ],
)
def test_evidence_output_rejects_blank_child_identity(tmp_path, missing_field):
    mod = _load_classifier()
    candidate = _candidate("10" * 32, "207fffff", 10)
    candidate[missing_field] = ""
    input_path = tmp_path / "candidate.csv"
    output_path = tmp_path / "validated.csv"
    rejected_path = tmp_path / "rejected.csv"
    evidence_path = tmp_path / "evidence.csv"
    with input_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(candidate))
        writer.writeheader()
        writer.writerow(candidate)

    class NoRpcExpected:
        def call_many(self, *_args, **_kwargs):
            raise AssertionError("evidence preflight must run before RPC")

    with pytest.raises(
        ValueError,
        match=rf"evidence row 2 \(btc_header_hash={candidate['btc_hash']}\).*{missing_field}",
    ):
        mod.classify_and_validate(
            input_path,
            output_path,
            rejected_path,
            NoRpcExpected(),
            evidence_csv=evidence_path,
        )

    assert not output_path.exists()
    assert not rejected_path.exists()
    assert not evidence_path.exists()


def test_publication_inventory_identifies_parent_on_child_identity_failure(tmp_path):
    mod = _load_classifier()
    row = _candidate("10" * 32, "207fffff", 10)
    row["classification"] = "canonical"
    row["child_block_hash"] = "00" * 32

    with pytest.raises(
        ValueError,
        match=rf"evidence row 2 \(btc_header_hash={row['btc_hash']}\)",
    ):
        mod._write_publication_inventory(tmp_path / "i0coin_stale_blocks.csv", [row])


def test_publication_inventory_rejects_uppercase_child_hash(tmp_path):
    mod = _load_classifier()
    row = _candidate("10" * 32, "207fffff", 10)
    row["classification"] = "canonical"
    row["child_block_hash"] = row["child_block_hash"].upper()

    with pytest.raises(ValueError, match="exact lowercase.*child_block_hash"):
        mod._write_publication_inventory(tmp_path / "i0coin_stale_blocks.csv", [row])


def test_publication_inventory_rejects_uppercase_child_header(tmp_path):
    mod = _load_classifier()
    row = _candidate("10" * 32, "207fffff", 10)
    row["classification"] = "canonical"
    row["child_header_hex"] = row["child_header_hex"].upper()

    with pytest.raises(ValueError, match="exact lowercase child_header_hex"):
        mod._write_publication_inventory(tmp_path / "i0coin_stale_blocks.csv", [row])


def test_publication_inventory_preflights_child_identity_before_rpc(tmp_path):
    mod = _load_classifier()
    row = _candidate("10" * 32, "207fffff", 10)
    row["child_height"] = ""
    input_path = tmp_path / "candidates.csv"
    output_path = tmp_path / "validated.csv"
    rejected_path = tmp_path / "rejected.csv"
    publication_path = tmp_path / "publication_stale_blocks.csv"
    with input_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)

    class NoRpcExpected:
        def call_many(self, *_args, **_kwargs):
            raise AssertionError("publication preflight must run before RPC")

    with pytest.raises(
        ValueError,
        match=rf"evidence row 2 \(btc_header_hash={row['btc_hash']}\).*child_height",
    ):
        mod.classify_and_validate(
            input_path,
            output_path,
            rejected_path,
            NoRpcExpected(),
            publication_csv=publication_path,
        )

    assert not output_path.exists()
    assert not rejected_path.exists()
    assert not publication_path.exists()


def test_publication_row_maps_internal_parent_fields_to_compact_schema():
    mod = _load_classifier()
    row = {
        "btc_stale_height": "42",
        "btc_hash": "11" * 32,
        "btc_bits_hex": "1d00ffff",
        "classification": "stale",
        "validation_status": "VALID",
        "expected_nbits": "1d00ffff",
    }

    normalized = mod._publication_row(row)

    assert normalized["btc_height"] == "42"
    assert normalized["btc_header_hash"] == "11" * 32
    assert normalized["btc_bits"] == "1d00ffff"
    assert normalized["validation_status"] == "VALID"
    assert normalized["expected_nbits"] == "1d00ffff"


def test_publication_row_omits_stale_diagnostics_for_non_stale_rows():
    mod = _load_classifier()

    normalized = mod._publication_row(
        {
            "btc_stale_height": "42",
            "btc_hash": "11" * 32,
            "btc_bits_hex": "1d00ffff",
            "classification": "canonical",
            "validation_status": "VALID (canonical Bitcoin block)",
            "expected_nbits": "1d00ffff",
        }
    )

    assert normalized["validation_status"] == ""
    assert normalized["expected_nbits"] == ""


def test_publication_inventory_rolls_back_the_whole_family_on_install_failure(
    tmp_path, monkeypatch
):
    mod = _load_classifier()
    row = _candidate("10" * 32, "207fffff", 10)
    row["classification"] = "canonical"
    stale_path = tmp_path / "i0coin_stale_blocks.csv"
    canonical_path = tmp_path / "i0coin_canonical_blocks.csv"
    unknown_path = tmp_path / "i0coin_unknown_blocks.csv"
    old_contents = {
        canonical_path: "old canonical\n",
        stale_path: "old stale\n",
        unknown_path: "old unknown\n",
    }
    for path, contents in old_contents.items():
        path.write_text(contents)

    real_replace = mod.os.replace

    def fail_on_stale_install(source, destination):
        source = Path(source)
        destination = Path(destination)
        if source.name == stale_path.name and destination == stale_path:
            raise OSError("simulated stale-bucket install failure")
        real_replace(source, destination)

    monkeypatch.setattr(mod.os, "replace", fail_on_stale_install)

    with pytest.raises(OSError, match="simulated stale-bucket install failure"):
        mod._write_publication_inventory(stale_path, [row])

    assert {path: path.read_text() for path in old_contents} == old_contents


def test_publication_inventory_fsyncs_output_directory(tmp_path, monkeypatch):
    mod = _load_classifier()
    row = _candidate("10" * 32, "207fffff", 10)
    row["classification"] = "canonical"
    synced = []
    monkeypatch.setattr(mod, "_fsync_directory", synced.append)

    mod._write_publication_inventory(tmp_path / "i0coin_stale_blocks.csv", [row])

    assert tmp_path in synced


def test_rpc_client_bounds_large_batches_and_preserves_response_alignment():
    mod = _load_classifier()

    def dispatch(call):
        return _success(call, call["params"][0])

    fake_rpc = _DispatchRpc(dispatch)
    client = mod.RpcClient(rpc=fake_rpc)
    values = list(range(1_201))

    assert client.call_many("echo", [(value,) for value in values]) == values
    assert [len(batch) for batch in fake_rpc.batches] == [500, 500, 201]


def test_rpc_client_rejects_duplicate_batch_response_ids():
    mod = _load_classifier()

    class DuplicateIdRpc:
        def batch(self, calls):
            first = _success(calls[0], "first")
            return [first, dict(first)]

    client = mod.RpcClient(rpc=DuplicateIdRpc(), batch_size=2)
    with pytest.raises(mod.RpcProtocolError, match="duplicate RPC response id"):
        client.call_many("echo", [(1,), (2,)])


def test_rpc_client_does_not_treat_unexpected_rpc_error_as_not_found():
    mod = _load_classifier()

    fake_rpc = _DispatchRpc(lambda call: _error(call, -28, "Loading block index"))
    client = mod.RpcClient(rpc=fake_rpc)

    with pytest.raises(RuntimeError, match=r"code -28: Loading block index"):
        client.call_many(
            "getblockheader",
            [("01" * 32,)],
            allowed_error_codes=frozenset({mod.NOT_FOUND_ERROR_CODE}),
        )


def test_rpc_client_propagates_transport_failures():
    mod = _load_classifier()

    class BrokenTransportRpc:
        def batch(self, calls):
            raise OSError("connection reset")

    client = mod.RpcClient(rpc=BrokenTransportRpc())
    with pytest.raises(OSError, match="connection reset"):
        client.call_many("getblockheader", [("01" * 32,)])


def test_classifier_rejects_incoherent_parent_header_before_rpc(tmp_path):
    mod = _load_classifier()
    candidate = _candidate("10" * 32, "207fffff", 10)
    corrupted_header = bytearray.fromhex(candidate["btc_header_hex"])
    corrupted_header[-1] ^= 1
    candidate["btc_header_hex"] = corrupted_header.hex()
    input_path = tmp_path / "candidate.csv"
    with input_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(candidate))
        writer.writeheader()
        writer.writerow(candidate)

    client = mod.RpcClient(
        rpc=_DispatchRpc(lambda call: pytest.fail(f"unexpected RPC call: {call}"))
    )
    with pytest.raises(ValueError, match="does not match btc_header_hex"):
        mod.classify_and_validate(
            input_path,
            tmp_path / "validated.csv",
            tmp_path / "rejected.csv",
            client,
            evidence_csv=tmp_path / "evidence.csv",
        )


def test_classifier_rejects_aliased_output_paths(tmp_path):
    mod = _load_classifier()
    input_path = tmp_path / "empty.csv"
    input_path.write_text("btc_hash\n")
    output_path = tmp_path / "output.csv"
    client = mod.RpcClient(
        rpc=_DispatchRpc(lambda call: pytest.fail(f"unexpected RPC call: {call}"))
    )

    with pytest.raises(ValueError, match="aliases"):
        mod.classify_and_validate(
            input_path,
            output_path,
            output_path,
            client,
        )
