import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from stale_blocks_analysis import rod_canonical as rod
from stale_blocks_analysis.bitcoin_binary import sha256d


def _header(*, timestamp: int, bits: bytes = bytes(4)) -> bytes:
    return (
        (1).to_bytes(4, "little")
        + bytes(32)
        + bytes(32)
        + timestamp.to_bytes(4, "little")
        + bits
        + bytes(4)
    )


def _coinbase() -> bytes:
    return (
        (1).to_bytes(4, "little")
        + b"\x01"
        + bytes(32)
        + b"\xff\xff\xff\xff"
        + b"\x03\x01\x02\x03"
        + b"\xff\xff\xff\xff"
        + b"\x01"
        + (50 * 100_000_000).to_bytes(8, "little")
        + b"\x01\x51"
        + bytes(4)
    )


def _candidate() -> dict:
    evidence = {
        "source_scope": "node_extraction",
        "source_locator": "chunks/000000000000-000000000255.jsonl",
        "acquisition_height": 42,
        "child_hash": "11" * 32,
        "envelope_sha256": "22" * 32,
    }
    evidence["evidence_sha256"] = rod._canonical_json_sha256(evidence)
    observation_basis = "\0".join(
        str(evidence.get(key, "")) for key in rod.OBSERVATION_ID_FIELDS
    )
    observation_id = hashlib.sha256(observation_basis.encode()).hexdigest()
    return {
        "observation_id": observation_id,
        "evidence": evidence,
        "result": {
            **evidence,
            "observation_id": observation_id,
            "bitcoin_context_category": "bitcoin_canonical_parent",
        },
    }


def _write_candidate(tmp_path, candidate: dict):
    path = tmp_path / "candidates.json"
    path.write_text(json.dumps([candidate]))
    return path, rod.sha256_file(path)


def test_publication_row_uses_external_target_and_internal_child_hash(monkeypatch):
    child = _header(timestamp=1_700_000_000)
    parent = _header(timestamp=1_700_000_001, bits=bytes.fromhex("ffff001d"))
    child_display = sha256d(child)[::-1].hex()
    parent_display = sha256d(parent)[::-1].hex()
    monkeypatch.setattr(rod, "CANONICAL_CHILD_HASH", child_display)
    monkeypatch.setattr(rod, "CANONICAL_BTC_HASH", parent_display)
    source = {
        "child_header_hex": child.hex(),
        "effective_bits": "1d00ffff",
        "parent_header_hex": parent.hex(),
        "parent_coinbase_hex": _coinbase().hex(),
        "parent_coinbase_scriptsig_hex": "010203",
        "proof_envelope_sha256": "11" * 32,
    }
    result = {
        "source_locator": "chunks/example.jsonl",
        "source_provenance": {"chunk_receipt": "receipts/example.json"},
        "observation_id": "22" * 32,
        "evidence_sha256": "33" * 32,
    }
    bindings = {
        "audit_report.json": "44" * 32,
        "review-receipt.json": "55" * 32,
        "candidate-inventory.json": "66" * 32,
        "chunks/example.jsonl": "77" * 32,
        "receipts/example.json": "88" * 32,
    }

    row = rod._publication_row(source, result, 9, bindings)

    assert row["child_block_hash"] == sha256d(child).hex()
    assert row["child_nbits"] == "1d00ffff"
    assert row["btc_header_hash"] == parent_display
    assert row["classification"] == "canonical"
    assert row["validation_status"] == ""
    assert row["expected_nbits"] == ""


def test_publication_row_rejects_nonzero_pure_header_bits(monkeypatch):
    child = _header(timestamp=1_700_000_000, bits=b"\x01\x00\x00\x00")
    parent = _header(timestamp=1_700_000_001)
    monkeypatch.setattr(rod, "CANONICAL_CHILD_HASH", sha256d(child)[::-1].hex())
    monkeypatch.setattr(rod, "CANONICAL_BTC_HASH", sha256d(parent)[::-1].hex())
    source = {
        "child_header_hex": child.hex(),
        "effective_bits": "1d00ffff",
        "parent_header_hex": parent.hex(),
        "parent_coinbase_hex": _coinbase().hex(),
        "parent_coinbase_scriptsig_hex": "010203",
        "proof_envelope_sha256": "11" * 32,
    }
    result = {
        "source_locator": "chunks/example.jsonl",
        "source_provenance": {"chunk_receipt": "receipts/example.json"},
        "observation_id": "22" * 32,
        "evidence_sha256": "33" * 32,
    }
    bindings = {
        "audit_report.json": "44" * 32,
        "review-receipt.json": "55" * 32,
        "candidate-inventory.json": "66" * 32,
        "chunks/example.jsonl": "77" * 32,
        "receipts/example.json": "88" * 32,
    }

    with pytest.raises(ValueError, match="pure child header nBits"):
        rod._publication_row(source, result, 9, bindings)


def test_relative_file_rejects_escape_and_symlink(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    (root / "linked").symlink_to(tmp_path, target_is_directory=True)

    with pytest.raises(ValueError, match="relative descendant"):
        rod._relative_file(root, "../outside.json", "input")
    with pytest.raises(ValueError, match="symlink"):
        rod._relative_file(root, "linked/outside.json", "input")


def test_final_audit_can_be_relocated_when_bound_inputs_match(tmp_path, monkeypatch):
    extraction = tmp_path / "extraction"
    audit = tmp_path / "audit"
    extraction.mkdir()
    audit.mkdir()
    run_config = extraction / "run-config.json"
    run_config.write_text("{}\n")
    report = {
        "schema": "rod-final-audit-v2",
        "complete": True,
        "errors": [],
        "rows_seen": rod.TERMINAL_HEIGHT + 1,
        "rows_expected": rod.TERMINAL_HEIGHT + 1,
        "terminal_height": rod.TERMINAL_HEIGHT,
        "terminal_hash": rod.TERMINAL_HASH,
        "extraction_root": "/original/archive/location",
        "run_config_sha256": rod.sha256_file(run_config),
        "algorithm_counts": {"129": 1_058_017, "2": 3_069_673},
        "proof_status_counts": {
            "valid_commitment_advertised_target": 1_058_017,
            "standalone_structure_retained_neoscrypt_pow_not_performed": 3_069_673,
        },
    }
    report_path = audit / "audit-report.json"
    report_path.write_text(json.dumps(report))
    digest = rod.sha256_file(report_path)
    monkeypatch.setattr(rod, "AUDIT_REPORT_SHA256", digest)
    (audit / "audit-receipt.json").write_text(
        json.dumps(
            {
                "schema": "rod-final-audit-receipt-v2",
                "complete": True,
                "audit_report_sha256": digest,
            }
        )
    )

    validated, _ = rod._validate_audit(audit, extraction)

    assert validated["extraction_root"] == "/original/archive/location"


def test_candidate_identity_formulas_are_recomputed(tmp_path):
    candidate = _candidate()
    path, digest = _write_candidate(tmp_path, candidate)

    selected, actual_digest = rod._select_candidate(path, digest)

    assert selected == candidate
    assert actual_digest == digest


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        (
            lambda candidate: candidate.update(observation_id="00" * 32),
            "observation ID mismatch",
        ),
        (
            lambda candidate: (
                candidate["evidence"].update(source_locator="chunks/tampered.jsonl"),
                candidate["result"].update(source_locator="chunks/tampered.jsonl"),
            ),
            "evidence SHA256 mismatch",
        ),
        (
            lambda candidate: candidate["result"].update(observation_id="00" * 32),
            "observation ID mismatch",
        ),
    ],
)
def test_candidate_identity_mutation_is_rejected(tmp_path, mutation, error):
    candidate = _candidate()
    mutation(candidate)
    path, digest = _write_candidate(tmp_path, candidate)

    with pytest.raises(ValueError, match=error):
        rod._select_candidate(path, digest)


def test_producer_dependency_hashes_bind_loaded_sources():
    hashes = rod._producer_dependency_sha256()

    assert set(hashes) == {
        "src/stale_blocks_analysis/auxpow_chainid.py",
        "src/stale_blocks_analysis/auxpow_parse.py",
        "src/stale_blocks_analysis/bitcoin_binary.py",
        "src/stale_blocks_analysis/evidence_normalization.py",
    }
    for relative, module in rod.PRODUCER_DEPENDENCY_MODULES.items():
        assert hashes[relative] == rod.sha256_file(Path(module.__file__).resolve())


def test_full_evidence_rejects_envelope_target_metadata_contradiction(monkeypatch):
    child = _header(timestamp=1_700_000_000)
    parent_header = _header(timestamp=1_700_000_001)
    coinbase = _coinbase()
    monkeypatch.setattr(rod, "CANONICAL_BTC_HASH", sha256d(parent_header)[::-1].hex())
    parsed = {
        "child": child,
        "algo": 0x81,
        "bits": 0x1D00FFFF,
        "parent": {
            "header": parent_header,
            "tx": {"raw": coinbase},
        },
    }
    expected_proof = {
        "proof_status": "valid_commitment_advertised_target",
        "proof_errors": [],
        "advertised_target_check": "pass",
        "source_commitment_check": "pass",
        "publication_coinbase_form_check": "pass",
        "parent_hash": rod.CANONICAL_BTC_HASH,
    }

    class Cursor:
        def __init__(self, envelope):
            self.envelope = envelope

        def remaining(self):
            return 0

    framing = SimpleNamespace(
        Cursor=Cursor,
        parse_envelope_structure=lambda cursor, height: (parsed, len(cursor.envelope)),
        validate_proof=lambda value: expected_proof,
    )
    row = {
        **expected_proof,
        "proof_envelope_hex": "00",
        "child_header_hex": child.hex(),
        "algorithm_byte": 0x81,
        "effective_bits": "19077766",
        "parent_header_hex": parent_header.hex(),
        "parent_coinbase_hex": coinbase.hex(),
    }

    with pytest.raises(ValueError, match="envelope contradicts"):
        rod._validate_full_evidence(row, "00", framing, SimpleNamespace())


def test_rod_registered_for_historical_child_header_coverage():
    from stale_blocks_analysis.config import (
        CHAINS_BY_AUXPOW_ACTIVATION,
        CHAIN_SPECS,
        HISTORICAL_CHILD_HEADER_CHAINS,
    )

    assert "rod" in HISTORICAL_CHILD_HEADER_CHAINS
    assert ("rod", "2022-06-09") in CHAINS_BY_AUXPOW_ACTIVATION
    assert CHAIN_SPECS["rod"].chain_id == 1899
    assert CHAIN_SPECS["rod"].child_nbits_from_header is False
