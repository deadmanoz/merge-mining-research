import hashlib
import importlib.util
import json
import os
import py_compile
import sys
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


def _candidate(*, canonical=True) -> dict:
    evidence = {
        "source_scope": "node_extraction",
        "source_locator": "chunks/000000000000-000000000255.jsonl",
        "acquisition_height": rod.CANONICAL_HEIGHT if canonical else 43,
        "child_hash": rod.CANONICAL_CHILD_HASH if canonical else "11" * 32,
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
            "bitcoin_context_category": (
                "bitcoin_canonical_parent"
                if canonical
                else "bitcoin_known_noncanonical_predecessor"
            ),
            "research_classification": "canonical_candidate"
            if canonical
            else "unknown",
            "parent_self_target_pass": canonical,
            "publication_disposition": (
                "requires_publication_profile_review"
                if canonical
                else "requires_ancestry_and_consensus_review"
            ),
        },
    }


def _write_candidate(tmp_path, candidate: dict):
    path = tmp_path / "candidates.json"
    path.write_text(json.dumps([candidate, _candidate(canonical=False)]))
    return path, rod.sha256_file(path)


_CANDIDATE_SUMMARY = {
    "counts": {
        "bitcoin_context_category": {
            "bitcoin_canonical_parent": 1,
            "bitcoin_known_noncanonical_predecessor": 1,
        }
    }
}


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

    selected, actual_digest = rod._select_candidate(path, digest, _CANDIDATE_SUMMARY)

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
        rod._select_candidate(path, digest, _CANDIDATE_SUMMARY)


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


def _full_evidence_fixture(monkeypatch):
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
        "proof_envelope_sha256": hashlib.sha256(b"\x00").hexdigest(),
        "child_header_hex": child.hex(),
        "algorithm_byte": 0x81,
        "effective_bits": "1d00ffff",
        "parent_header_hex": parent_header.hex(),
        "parent_coinbase_hex": coinbase.hex(),
        "child_coinbase_height": rod.CANONICAL_HEIGHT,
        "child_merkle_root_matches": True,
        "child_height_matches_node_height": True,
    }
    reparsed = dict(row)
    extractor = SimpleNamespace(parse_block=lambda *args: reparsed)
    return row, framing, extractor, reparsed


def test_full_evidence_rejects_envelope_target_metadata_contradiction(monkeypatch):
    row, framing, extractor, _ = _full_evidence_fixture(monkeypatch)
    row["effective_bits"] = "19077766"

    with pytest.raises(ValueError, match="envelope contradicts"):
        rod._validate_full_evidence(row, "00", framing, extractor)


def test_full_evidence_accepts_verified_body_at_pinned_height(monkeypatch):
    row, framing, extractor, reparsed = _full_evidence_fixture(monkeypatch)

    assert rod._validate_full_evidence(row, "00", framing, extractor) == reparsed


@pytest.mark.parametrize("declared_digest", ["00" * 32, None])
def test_full_evidence_rejects_matching_false_envelope_digests(
    monkeypatch, declared_digest
):
    row, framing, extractor, reparsed = _full_evidence_fixture(monkeypatch)
    row["proof_envelope_sha256"] = reparsed["proof_envelope_sha256"] = declared_digest

    with pytest.raises(ValueError, match="envelope SHA256 mismatch"):
        rod._validate_full_evidence(row, "00", framing, extractor)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (field, value)
        for field in (
            "child_merkle_root_matches",
            "child_height_matches_node_height",
        )
        for value in (False, None, 0, 1, "true")
    ]
    + [
        ("child_coinbase_height", rod.CANONICAL_HEIGHT - 1),
        ("child_coinbase_height", None),
    ],
)
def test_full_evidence_rejects_matching_invalid_body_claims(monkeypatch, field, value):
    row, framing, extractor, reparsed = _full_evidence_fixture(monkeypatch)
    # Agreement with the extraction row does not make a failed check acceptable.
    row[field] = reparsed[field] = value

    with pytest.raises(ValueError, match=f"full ROD body {field}"):
        rod._validate_full_evidence(row, "00", framing, extractor)


def _review_fixture(tmp_path):
    artifacts = {}
    for name, payload in {
        "rod-2697753-body.hex": "00\n",
        "canonical-body.response.json": json.dumps({"result": "00", "error": None}),
    }.items():
        path = tmp_path / name
        path.write_text(payload)
        artifacts[name] = {
            "bytes": path.stat().st_size,
            "sha256": rod.sha256_file(path),
        }
    return {
        "canonical": {
            "rod_height": rod.CANONICAL_HEIGHT,
            "rod_hash": rod.CANONICAL_CHILD_HASH,
            "bitcoin_height": rod.CANONICAL_BTC_HEIGHT,
            "bitcoin_hash": rod.CANONICAL_BTC_HASH,
            "coinbase_txid_and_script_match_proof": True,
            "complete_bitcoin_body_merkle_verified": True,
            "complete_rod_body_merkle_height_and_commitment_verified": True,
            "rod_extraction_envelope_unchanged": True,
        },
        "artifacts": artifacts,
    }


def _write_review(tmp_path, receipt):
    path = tmp_path / "review-receipt.json"
    path.write_text(json.dumps(receipt))
    return rod.sha256_file(path)


def test_candidate_review_binds_both_reviewed_bodies(tmp_path):
    receipt = _review_fixture(tmp_path)
    digest = _write_review(tmp_path, receipt)

    validated, bindings = rod._validate_review(tmp_path, digest)

    assert validated == receipt
    assert bindings == {
        "review-receipt.json": digest,
        **{name: item["sha256"] for name, item in receipt["artifacts"].items()},
    }


@pytest.mark.parametrize("body_present", [False, True])
def test_candidate_review_rejects_unbound_bitcoin_body(tmp_path, body_present):
    receipt = _review_fixture(tmp_path)
    del receipt["artifacts"]["canonical-body.response.json"]
    if not body_present:
        (tmp_path / "canonical-body.response.json").unlink()
    digest = _write_review(tmp_path, receipt)

    with pytest.raises(ValueError, match="artifact inventory is incomplete"):
        rod._validate_review(tmp_path, digest)


@pytest.mark.parametrize("mutation", ["missing", "digest", "size"])
def test_candidate_review_rejects_missing_or_changed_bitcoin_body(tmp_path, mutation):
    receipt = _review_fixture(tmp_path)
    path = tmp_path / "canonical-body.response.json"
    if mutation == "missing":
        path.unlink()
    elif mutation == "digest":
        path.write_text(path.read_text().replace("00", "01"))
    else:
        receipt["artifacts"][path.name]["bytes"] += 1
    digest = _write_review(tmp_path, receipt)

    with pytest.raises(ValueError, match="artifact (missing|mismatch).*canonical-body"):
        rod._validate_review(tmp_path, digest)


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


def _write_pinned_source(path, source, poison_cache):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source)
    if poison_cache:
        original_stat = path.stat()
        poisoned = source.replace('"safe"', '"evil"')
        assert len(poisoned) == len(source) and poisoned != source
        path.write_text(poisoned)
        os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
        py_compile.compile(
            str(path),
            doraise=True,
            invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP,
        )
        path.write_text(source)
        os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    return rod.sha256_file(path)


_PINNED_SOURCE = """from __future__ import annotations
from dataclasses import dataclass
VALUE = "safe"
@dataclass
class Payload:
    value: str = VALUE
"""


@pytest.mark.parametrize("poison_cache", [False, True])
def test_pinned_loader_executes_hashed_source_without_touching_cache(
    tmp_path, monkeypatch, poison_cache
):
    path = tmp_path / "pinned.py"
    digest = _write_pinned_source(path, _PINNED_SOURCE, poison_cache)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*.pyc")}
    monkeypatch.setitem(sys.modules, "rod_test_pinned", None)

    module = rod._load_module(path, digest, "rod_test_pinned")

    assert module.VALUE == module.Payload().value == "safe"
    assert module.__file__ == str(path)
    assert sys.modules["rod_test_pinned"] is module
    assert {p: p.read_bytes() for p in tmp_path.rglob("*.pyc")} == before
    if not poison_cache:
        assert not list(tmp_path.rglob("__pycache__"))


@pytest.mark.parametrize("poison_cache", [False, True])
def test_frozen_extractor_nested_load_uses_verified_source_without_cache(
    tmp_path, monkeypatch, poison_cache
):
    framing_path = tmp_path / "deps" / "rod_header_acquire.py"
    framing_digest = _write_pinned_source(framing_path, _PINNED_SOURCE, poison_cache)
    # Match the frozen extractor's unconditional importlib-based dependency load.
    extractor_source = """import importlib.util, sys
from pathlib import Path
DEP = Path(__file__).resolve().parent / "deps" / "rod_header_acquire.py"
VALUE = "safe"
def load_framing():
    spec = importlib.util.spec_from_file_location("rod_framing", DEP)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module
F = load_framing()
"""
    path = tmp_path / "extract_rod_rpc.py"
    digest = _write_pinned_source(path, extractor_source, poison_cache)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*.pyc")}
    monkeypatch.setattr(rod, "FRAMING_SHA256", framing_digest)
    monkeypatch.setitem(sys.modules, "rod_test_extractor", None)
    monkeypatch.setitem(sys.modules, "rod_framing", None)
    original_spec_factory = importlib.util.spec_from_file_location

    module = rod._load_module(
        path, digest, "rod_test_extractor", framing_path=framing_path
    )

    assert module.VALUE == module.F.Payload().value == "safe"
    assert module.F is sys.modules["rod_framing"]
    assert module.F.__file__ == str(framing_path)
    assert importlib.util.spec_from_file_location is original_spec_factory
    assert {p: p.read_bytes() for p in tmp_path.rglob("*.pyc")} == before
    if not poison_cache:
        assert not list(tmp_path.rglob("__pycache__"))


def test_pinned_loader_rejects_source_digest_mismatch(tmp_path, monkeypatch):
    path = tmp_path / "pinned.py"
    path.write_text(_PINNED_SOURCE)
    monkeypatch.setitem(sys.modules, "rod_test_pinned", None)

    with pytest.raises(ValueError, match="SHA256 mismatch"):
        rod._load_module(path, "00" * 32, "rod_test_pinned")

    assert sys.modules["rod_test_pinned"] is None
    assert not list(tmp_path.rglob("__pycache__"))


@pytest.mark.parametrize("mutation", ["name", "path", "digest"])
def test_nested_framing_load_rejects_unexpected_dependency(
    tmp_path, monkeypatch, mutation
):
    framing_path = tmp_path / "rod_header_acquire.py"
    framing_path.write_text(_PINNED_SOURCE)
    digest = rod.sha256_file(framing_path)
    monkeypatch.setattr(
        rod, "FRAMING_SHA256", "00" * 32 if mutation == "digest" else digest
    )
    name = "unexpected_framing" if mutation == "name" else "rod_framing"
    location = tmp_path / "unexpected.py" if mutation == "path" else framing_path
    path = tmp_path / "extractor.py"
    path.write_text(
        "import importlib.util\n"
        f"importlib.util.spec_from_file_location({name!r}, {str(location)!r})\n"
    )
    monkeypatch.setitem(sys.modules, "rod_test_extractor", None)
    original_spec_factory = importlib.util.spec_from_file_location

    with pytest.raises(ValueError, match="unexpected dependency|SHA256 mismatch"):
        rod._load_module(
            path, rod.sha256_file(path), "rod_test_extractor", framing_path=framing_path
        )

    assert importlib.util.spec_from_file_location is original_spec_factory
    assert not list(tmp_path.rglob("__pycache__"))


def test_pinned_loader_executes_the_single_hashed_read(tmp_path, monkeypatch):
    path = tmp_path / "pinned.py"
    path.write_text(_PINNED_SOURCE)
    digest = rod.sha256_file(path)
    original_read = Path.read_bytes
    reads = []

    def replace_after_read(self):
        source = original_read(self)
        if self == path:
            reads.append(self)
            self.write_bytes(source.replace(b'"safe"', b'"evil"'))
        return source

    monkeypatch.setattr(Path, "read_bytes", replace_after_read)
    monkeypatch.setitem(sys.modules, "rod_test_pinned", None)

    module = rod._load_module(path, digest, "rod_test_pinned")

    assert module.VALUE == "safe"
    assert reads == [path]
    assert '"evil"' in path.read_text()
    assert not list(tmp_path.rglob("__pycache__"))
