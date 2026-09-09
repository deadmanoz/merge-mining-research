"""Build the reviewed canonical SpaceXpanse ROD publication companion."""

from __future__ import annotations

import builtins
import csv
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, Mapping

from . import auxpow_chainid as _auxpow_chainid
from . import auxpow_parse as _auxpow_parse
from . import bitcoin_binary as _bitcoin_binary
from . import evidence_normalization as _evidence_normalization
from .auxpow_parse import parse_child_header
from .bitcoin_binary import format_outputs_canonical, parse_coinbase_tx
from .evidence_normalization import EVIDENCE_FIELDS, parse_header_fields

CHAIN = "rod"
SOURCE_REVISION = "248f1af050579a369af527288f5773a021ae8492"
GENESIS_HASH = "5d4b20be4fc87d2333aea5235d9de1c685696fc935f806a9ffd71c9f9abf3c57"
TERMINAL_HEIGHT = 4_127_689
TERMINAL_HASH = "4a16afd2df5efd2ae7db5e07ba83820bf3174914efe2754da618a150c3df6b0a"
FRAMING_SHA256 = "b4f2b6af6876026c3b7f3a7c4c1df45b827e64a6c084b4e0afb9a061ba2133bc"
EXTRACTOR_SHA256 = "5c41031f03b8214e1fea7fa5a82b304219da8578d69054172c26191956527bb1"
AUDIT_REPORT_SHA256 = "a0a6957e53b5d1dee6a0e54cc444467b13278b4f63b14a988b89101c6d605030"
CANONICAL_HEIGHT = 2_697_753
CANONICAL_CHILD_HASH = (
    "4707fda9b70993a867cf9026a4c977a5fc8ebf8c4bb3b3512596357520bae21b"
)
CANONICAL_BTC_HEIGHT = 886_688
CANONICAL_BTC_HASH = "00000000000000000001822dc3db70b75d281687f8baa10d1818d0703f49fec0"

EXTRA_FIELDS = [
    "observation_id",
    "proof_envelope_sha256",
    "evidence_sha256",
    "extraction_chunk_sha256",
    "extraction_receipt_sha256",
    "audit_report_sha256",
    "candidate_inventory_sha256",
    "candidate_review_receipt_sha256",
]
OUTPUT_FIELDS = EVIDENCE_FIELDS + EXTRA_FIELDS
OBSERVATION_ID_FIELDS = (
    "source_scope",
    "source_locator",
    "acquisition_height",
    "child_hash",
    "envelope_sha256",
)
PRODUCER_DEPENDENCY_MODULES = {
    "src/stale_blocks_analysis/auxpow_chainid.py": _auxpow_chainid,
    "src/stale_blocks_analysis/auxpow_parse.py": _auxpow_parse,
    "src/stale_blocks_analysis/bitcoin_binary.py": _bitcoin_binary,
    "src/stale_blocks_analysis/evidence_normalization.py": _evidence_normalization,
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json(path: Path) -> Any:
    return json.loads(path.read_bytes())


def _require_digest(path: Path, expected: str) -> str:
    actual = sha256_file(path)
    if actual != expected:
        raise ValueError(f"{path}: SHA256 mismatch: expected {expected}, got {actual}")
    return actual


def _canonical_json_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _producer_dependency_sha256() -> dict[str, str]:
    """Bind the local modules whose behavior directly shapes the companion."""
    package_dir = Path(__file__).resolve().parent
    hashes: dict[str, str] = {}
    for relative, module in PRODUCER_DEPENDENCY_MODULES.items():
        loaded_path = Path(str(module.__file__)).resolve()
        expected_path = package_dir / PurePosixPath(relative).name
        if loaded_path != expected_path:
            raise ValueError(
                f"producer dependency loaded from unexpected path: {relative}"
            )
        hashes[relative] = sha256_file(loaded_path)
    return hashes


class _VerifiedSourceLoader:
    """Execute the exact verified bytes without reading or writing a pyc cache."""

    def __init__(self, path: Path, expected_sha256: str):
        source = path.read_bytes()
        if hashlib.sha256(source).hexdigest() != expected_sha256:
            raise ValueError(f"{path}: SHA256 mismatch")
        self.code = compile(source, str(path), "exec", dont_inherit=True)

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        exec(self.code, module.__dict__)


def _load_module(
    path: Path,
    expected_sha256: str,
    name: str,
    *,
    framing_path: Path | None = None,
) -> ModuleType:
    loader = _VerifiedSourceLoader(path, expected_sha256)
    spec = importlib.util.spec_from_file_location(name, path, loader=loader)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load pinned dependency {path}")
    module = importlib.util.module_from_spec(spec)
    if framing_path is not None:
        # The frozen extractor imports importlib.util and reloads its framing
        # module itself. Confine that load to verified source in this module's
        # builtins rather than changing the process-wide import machinery.
        def framing_spec(dependency_name, location):
            if (
                dependency_name != "rod_framing"
                or Path(location).resolve() != framing_path.resolve()
            ):
                raise ValueError("frozen extractor requested an unexpected dependency")
            return importlib.util.spec_from_file_location(
                dependency_name,
                location,
                loader=_VerifiedSourceLoader(framing_path, FRAMING_SHA256),
            )

        local_util = ModuleType("importlib.util")
        local_util.__dict__.update(vars(importlib.util))
        local_util.spec_from_file_location = framing_spec
        local_importlib = ModuleType("importlib")
        local_importlib.__dict__.update(vars(importlib))
        local_importlib.util = local_util

        def import_verified(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "importlib.util" and not fromlist and level == 0:
                return local_importlib
            return builtins.__import__(name, globals, locals, fromlist, level)

        module.__dict__["__builtins__"] = {
            **vars(builtins),
            "__import__": import_verified,
        }
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _relative_file(root: Path, value: object, label: str) -> Path:
    """Resolve a normalized relative file without following a symlink escape."""
    if (
        not isinstance(value, str)
        or not value
        or PurePosixPath(value).as_posix() != value
    ):
        raise ValueError(f"{label} must be a normalized relative path")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or relative == PurePosixPath(".")
        or ".." in relative.parts
    ):
        raise ValueError(f"{label} must be a relative descendant")
    candidate = root.joinpath(*relative.parts)
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"{label} traverses a symlink")
    if not candidate.is_file():
        raise ValueError(f"{label} is missing")
    return candidate


def _validate_audit(
    audit_root: Path, extraction_root: Path
) -> tuple[dict[str, Any], dict[str, str]]:
    report_path = audit_root / "audit-report.json"
    receipt_path = audit_root / "audit-receipt.json"
    report_sha = _require_digest(report_path, AUDIT_REPORT_SHA256)
    receipt = _json(receipt_path)
    report = _json(report_path)
    if (
        receipt.get("schema") != "rod-final-audit-receipt-v2"
        or receipt.get("complete") is not True
    ):
        raise ValueError("final audit receipt is not complete v2")
    if receipt.get("audit_report_sha256") != report_sha:
        raise ValueError("final audit receipt does not bind the audit report")
    if (
        report.get("schema") != "rod-final-audit-v2"
        or report.get("complete") is not True
    ):
        raise ValueError("final audit report is not complete v2")
    if report.get("errors") != [] or report.get("rows_seen") != report.get(
        "rows_expected"
    ):
        raise ValueError("final audit has errors or incomplete row coverage")
    if report.get("rows_seen") != TERMINAL_HEIGHT + 1:
        raise ValueError("final audit row count does not cover the pinned range")
    if (
        report.get("terminal_height") != TERMINAL_HEIGHT
        or report.get("terminal_hash") != TERMINAL_HASH
    ):
        raise ValueError("final audit terminal identity mismatch")
    run_config = extraction_root / "run-config.json"
    if report.get("run_config_sha256") != sha256_file(run_config):
        raise ValueError("final audit run-config digest mismatch")
    if report.get("algorithm_counts") != {"129": 1_058_017, "2": 3_069_673}:
        raise ValueError("final audit algorithm inventory mismatch")
    if report.get("proof_status_counts") != {
        "valid_commitment_advertised_target": 1_058_017,
        "standalone_structure_retained_neoscrypt_pow_not_performed": 3_069_673,
    }:
        raise ValueError("final audit proof inventory mismatch")
    return report, {
        "audit_report.json": report_sha,
        "audit-receipt.json": sha256_file(receipt_path),
    }


def _validate_classification_summary(
    path: Path, audit: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], str]:
    """Bind the complete v6 classification and relocatable extraction inventory."""
    v6 = audit.get("v6")
    if not isinstance(v6, dict) or v6.get("errors") != []:
        raise ValueError("final audit lacks a clean v6 classification binding")
    summary_sha = _require_digest(path, v6.get("summary_sha256"))
    summary = _json(path)
    if not isinstance(summary, dict):
        raise ValueError("classification summary must be an object")
    for field in (
        "complete_context_and_source_coverage",
        "source_coverage_complete",
        "exact_hash_context_complete",
    ):
        if summary.get(field) is not True:
            raise ValueError(f"classification summary {field} must be true")
    expected_numbers = {
        "classifier_version": 6,
        "acquired_observations_accounted": TERMINAL_HEIGHT + 1,
        "acquired_sha256d_accounted": 1_058_017,
        "sha256d_observations": 1_058_017,
        "pointwise_rows": 1_058_017,
        "rpc_errors": 0,
        "rpc_pending_observations": 0,
        "unresolved_source_rows": 0,
    }
    for field, expected in expected_numbers.items():
        if type(summary.get(field)) is not int or summary[field] != expected:
            raise ValueError(f"classification summary {field} mismatch")
    if (
        summary.get("pointwise_sha256") != v6.get("pointwise_sha256")
        or v6.get("pointwise_rows") != summary["pointwise_rows"]
    ):
        raise ValueError("classification summary pointwise audit binding mismatch")
    expected_counts = {
        "bitcoin_context_category": {
            "bitcoin_active_predecessor": 68_246,
            "bitcoin_canonical_parent": 1,
            "bitcoin_known_noncanonical_predecessor": 1,
            "unresolved_parent_network": 989_769,
        },
        "research_classification": {
            "canonical_candidate": 1,
            "near": 660_695,
            "unknown": 397_321,
        },
        "publication_disposition": {
            "requires_ancestry_and_consensus_review": 1,
            "requires_publication_profile_review": 1,
            "retained_lower_work_not_publishable_as_bitcoin_block": 68_246,
            "retained_unresolved_not_publishable": 989_769,
        },
    }
    counts = summary.get("counts")
    if not isinstance(counts, dict):
        raise ValueError("classification summary lacks category counts")
    for field, expected in expected_counts.items():
        actual = counts.get(field)
        if (
            actual != expected
            or not isinstance(actual, dict)
            or any(type(value) is not int for value in actual.values())
        ):
            raise ValueError(f"classification summary {field} inventory mismatch")

    binding = summary.get("observation_source_binding")
    if (
        not isinstance(binding, dict)
        or binding.get("input_kind") != "node-extraction"
        or binding.get("input_path") != audit.get("extraction_root")
        or binding.get("run_config_sha256") != audit.get("run_config_sha256")
    ):
        raise ValueError("classification summary extraction binding mismatch")
    original_root = binding.get("input_path")
    if (
        not isinstance(original_root, str)
        or not original_root.startswith("/")
        or original_root.startswith("//")
        or "\\" in original_root
        or "\0" in original_root
        or PurePosixPath(original_root).as_posix() != original_root
        or ".." in PurePosixPath(original_root).parts
    ):
        raise ValueError("classification summary extraction root is unsafe")
    inputs = summary.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        raise ValueError("classification summary lacks extraction inputs")
    manifest: dict[str, dict[str, Any]] = {}
    for item in inputs:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "kind",
            "bytes",
            "sha256",
        }:
            raise ValueError("classification summary input entry is malformed")
        historical_path = item["path"]
        digest = item["sha256"]
        if (
            not isinstance(historical_path, str)
            or "\\" in historical_path
            or "\0" in historical_path
            or PurePosixPath(historical_path).as_posix() != historical_path
            or ".." in PurePosixPath(historical_path).parts
        ):
            raise ValueError("classification summary input path is unsafe")
        try:
            relative = PurePosixPath(historical_path).relative_to(original_root)
        except ValueError as error:
            raise ValueError(
                "classification summary input escapes extraction root"
            ) from error
        key = relative.as_posix()
        expected_kind = None
        if len(relative.parts) == 2:
            if relative.parts[0] == "chunks" and relative.suffix == ".jsonl":
                expected_kind = "node-chunk"
            elif relative.parts[0] == "receipts" and relative.suffix == ".json":
                expected_kind = "node-chunk-receipt"
        elif key == "run-config.json":
            expected_kind = "node-extraction-run-config"
        if expected_kind is None or item["kind"] != expected_kind:
            raise ValueError("classification summary input kind/path mismatch")
        if (
            type(item["bytes"]) is not int
            or item["bytes"] <= 0
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            raise ValueError("classification summary input digest/size is malformed")
        if key in manifest:
            raise ValueError("classification summary has duplicate input paths")
        manifest[key] = {"kind": item["kind"], "bytes": item["bytes"], "sha256": digest}
    chunks = {PurePosixPath(key).stem for key in manifest if key.startswith("chunks/")}
    receipts = {
        PurePosixPath(key).stem for key in manifest if key.startswith("receipts/")
    }
    if not chunks or chunks != receipts:
        raise ValueError("classification summary chunk/receipt inventory mismatch")
    if (
        manifest.get("run-config.json", {}).get("sha256")
        != binding["run_config_sha256"]
    ):
        raise ValueError("classification summary run-config input binding mismatch")
    return summary, manifest, summary_sha


def _validate_review(
    review_root: Path, expected_sha256: str
) -> tuple[dict[str, Any], dict[str, str]]:
    receipt_path = review_root / "review-receipt.json"
    receipt_sha = _require_digest(receipt_path, expected_sha256)
    receipt = _json(receipt_path)
    canonical = receipt.get("canonical")
    if not isinstance(canonical, dict):
        raise ValueError("candidate review lacks canonical verdict")
    expected = {
        "rod_height": CANONICAL_HEIGHT,
        "rod_hash": CANONICAL_CHILD_HASH,
        "bitcoin_height": CANONICAL_BTC_HEIGHT,
        "bitcoin_hash": CANONICAL_BTC_HASH,
        "coinbase_txid_and_script_match_proof": True,
        "complete_bitcoin_body_merkle_verified": True,
        "complete_rod_body_merkle_height_and_commitment_verified": True,
        "rod_extraction_envelope_unchanged": True,
    }
    for key, value in expected.items():
        if canonical.get(key) != value:
            raise ValueError(f"candidate review canonical {key} mismatch")
    artifacts = receipt.get("artifacts")
    required_bodies = {"rod-2697753-body.hex", "canonical-body.response.json"}
    if not isinstance(artifacts, dict) or not required_bodies.issubset(artifacts):
        raise ValueError("candidate review artifact inventory is incomplete")
    bindings = {"review-receipt.json": receipt_sha}
    for relative, declared in artifacts.items():
        if not isinstance(relative, str) or Path(relative).name != relative:
            raise ValueError("candidate review contains an unsafe artifact path")
        path = review_root / relative
        if not path.is_file() or not isinstance(declared, dict):
            raise ValueError(f"candidate review artifact missing: {relative}")
        actual = sha256_file(path)
        if actual != declared.get("sha256") or path.stat().st_size != declared.get(
            "bytes"
        ):
            raise ValueError(f"candidate review artifact mismatch: {relative}")
        bindings[relative] = actual
    return receipt, bindings


def _select_candidate(
    path: Path, expected_sha256: str, summary: Mapping[str, Any]
) -> tuple[dict[str, Any], str]:
    inventory_sha = _require_digest(path, expected_sha256)
    payload = _json(path)
    categories = summary.get("counts", {}).get("bitcoin_context_category", {})
    expected_categories = {
        "bitcoin_canonical_parent": (
            "canonical_candidate",
            True,
            "requires_publication_profile_review",
        ),
        "bitcoin_known_noncanonical_predecessor": (
            "unknown",
            False,
            "requires_ancestry_and_consensus_review",
        ),
    }
    if (
        not isinstance(payload, list)
        or len(payload) != 2
        or any(categories.get(key) != 1 for key in expected_categories)
    ):
        raise ValueError(
            "special-candidate inventory must contain exactly one canonical and one known noncanonical observation"
        )
    seen_categories: set[str] = set()
    seen_ids: set[str] = set()
    selected = None
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("special-candidate inventory contains a malformed entry")
        result, evidence = item.get("result"), item.get("evidence")
        if not isinstance(result, dict) or not isinstance(evidence, dict):
            raise ValueError("special candidate lacks result or source evidence")
        category = result.get("bitcoin_context_category")
        if not isinstance(category, str) or category not in expected_categories:
            raise ValueError("special candidate has an unrecognized Bitcoin category")
        if category in seen_categories:
            raise ValueError("special-candidate inventory repeats a Bitcoin category")
        classification, self_target, disposition = expected_categories[category]
        if (
            result.get("research_classification") != classification
            or result.get("parent_self_target_pass") is not self_target
            or result.get("publication_disposition") != disposition
        ):
            raise ValueError("special candidate classification/disposition mismatch")
        for key in evidence:
            if key in result and result[key] != evidence[key]:
                raise ValueError(f"special candidate result/evidence mismatch: {key}")
        for key in OBSERVATION_ID_FIELDS:
            value = evidence.get(key)
            if key == "acquisition_height":
                valid = type(value) is int and 0 <= value <= TERMINAL_HEIGHT
            else:
                valid = isinstance(value, str) and bool(value) and "\0" not in value
            if not valid:
                raise ValueError(f"special candidate identity field is invalid: {key}")
            if result.get(key) != value:
                raise ValueError(f"special candidate result/evidence mismatch: {key}")
        if category == "bitcoin_canonical_parent" and (
            evidence["acquisition_height"] != CANONICAL_HEIGHT
            or evidence["child_hash"] != CANONICAL_CHILD_HASH
        ):
            raise ValueError("canonical candidate does not identify the pinned child")
        identity_evidence = dict(evidence)
        declared_evidence_sha = identity_evidence.pop("evidence_sha256", None)
        computed_evidence_sha = _canonical_json_sha256(identity_evidence)
        if (
            declared_evidence_sha != computed_evidence_sha
            or result.get("evidence_sha256") != computed_evidence_sha
        ):
            raise ValueError("special candidate evidence SHA256 mismatch")
        observation_basis = "\0".join(
            str(evidence[key]) for key in OBSERVATION_ID_FIELDS
        )
        computed_observation_id = hashlib.sha256(observation_basis.encode()).hexdigest()
        if (
            item.get("observation_id") != computed_observation_id
            or result.get("observation_id") != computed_observation_id
            or computed_observation_id in seen_ids
        ):
            raise ValueError("special candidate observation ID mismatch or duplicate")
        seen_ids.add(computed_observation_id)
        seen_categories.add(category)
        if category == "bitcoin_canonical_parent":
            selected = item
    assert selected is not None
    return selected, inventory_sha


def _source_row(
    extraction_root: Path,
    result: Mapping[str, Any],
    classification_inputs: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, Any], int, dict[str, str]]:
    locator = result.get("source_locator")
    provenance = result.get("source_provenance")
    if not isinstance(locator, str) or not isinstance(provenance, dict):
        raise ValueError("canonical candidate lacks extraction provenance")
    chunk = _relative_file(extraction_root, locator, "canonical source locator")
    receipt_relative = provenance.get("chunk_receipt")
    if not isinstance(receipt_relative, str):
        raise ValueError("canonical candidate lacks chunk receipt")
    receipt_path = _relative_file(
        extraction_root, receipt_relative, "canonical chunk receipt"
    )
    receipt = _json(receipt_path)
    chunk_sha = sha256_file(chunk)
    receipt_sha = sha256_file(receipt_path)
    for relative, path, kind, digest in (
        (locator, chunk, "node-chunk", chunk_sha),
        (receipt_relative, receipt_path, "node-chunk-receipt", receipt_sha),
    ):
        declared = classification_inputs.get(relative)
        if (
            not isinstance(declared, Mapping)
            or declared.get("kind") != kind
            or declared.get("sha256") != digest
            or type(declared.get("bytes")) is not int
            or declared["bytes"] != path.stat().st_size
        ):
            raise ValueError(
                f"canonical extraction file does not match classification summary: {relative}"
            )
    if receipt.get("chunk_sha256") != chunk_sha:
        raise ValueError("canonical extraction chunk digest mismatch")
    for key, actual in (
        ("chunk_sha256", chunk_sha),
        ("chunk_receipt_sha256", receipt_sha),
    ):
        declared = provenance.get(key)
        if declared is not None and declared != actual:
            raise ValueError(f"canonical candidate {key} mismatch")
    matches: list[tuple[int, dict[str, Any]]] = []
    with chunk.open() as handle:
        for line_number, line in enumerate(handle, start=1):
            row = json.loads(line)
            if row.get("height") == CANONICAL_HEIGHT:
                matches.append((line_number, row))
    if len(matches) != 1:
        raise ValueError("canonical extraction chunk lacks one exact height row")
    line_number, row = matches[0]
    for key, expected in (
        ("node_block_hash", CANONICAL_CHILD_HASH),
        ("child_hash", CANONICAL_CHILD_HASH),
        ("parent_hash", CANONICAL_BTC_HASH),
        ("proof_envelope_sha256", result.get("envelope_sha256")),
    ):
        if row.get(key) != expected:
            raise ValueError(f"canonical extraction row {key} mismatch")
    return (
        row,
        line_number,
        {
            str(chunk.relative_to(extraction_root)): chunk_sha,
            str(receipt_path.relative_to(extraction_root)): receipt_sha,
        },
    )


def _validate_full_evidence(
    row: Mapping[str, Any], body_hex: str, framing: ModuleType, extractor: ModuleType
) -> dict[str, Any]:
    envelope = bytes.fromhex(str(row["proof_envelope_hex"]))
    if hashlib.sha256(envelope).hexdigest() != row.get("proof_envelope_sha256"):
        raise ValueError("canonical PowData envelope SHA256 mismatch")
    cursor = framing.Cursor(envelope)
    parsed, end = framing.parse_envelope_structure(cursor, CANONICAL_HEIGHT)
    if end != len(envelope) or cursor.remaining():
        raise ValueError("PowData envelope was not consumed exactly")
    proof = framing.validate_proof(parsed)
    parent = parsed.get("parent")
    if (
        parsed.get("child") != bytes.fromhex(str(row["child_header_hex"]))
        or parsed.get("algo") != row.get("algorithm_byte")
        or f"{parsed.get('bits'):08x}" != row.get("effective_bits")
        or not isinstance(parent, dict)
        or parent.get("header", b"").hex() != row.get("parent_header_hex")
        or parent.get("tx", {}).get("raw", b"").hex() != row.get("parent_coinbase_hex")
    ):
        raise ValueError("canonical PowData envelope contradicts extraction fields")
    expected_proof = {
        "proof_status": "valid_commitment_advertised_target",
        "proof_errors": [],
        "advertised_target_check": "pass",
        "source_commitment_check": "pass",
        "publication_coinbase_form_check": "pass",
        "parent_hash": CANONICAL_BTC_HASH,
    }
    for key, value in expected_proof.items():
        if proof.get(key) != value or row.get(key) != value:
            raise ValueError(f"canonical PowData proof {key} mismatch")
    reparsed = extractor.parse_block(
        body_hex.strip(), CANONICAL_HEIGHT, CANONICAL_CHILD_HASH
    )
    for key in ("child_merkle_root_matches", "child_height_matches_node_height"):
        if reparsed.get(key) is not True:
            raise ValueError(f"full ROD body {key} must be true")
    if reparsed.get("child_coinbase_height") != CANONICAL_HEIGHT:
        raise ValueError("full ROD body child_coinbase_height mismatch")
    for key in (
        "child_hash",
        "child_header_hex",
        "child_time",
        "effective_bits",
        "proof_envelope_sha256",
        "parent_hash",
        "parent_header_hex",
        "parent_coinbase_hex",
        "parent_coinbase_scriptsig_hex",
        "child_coinbase_height",
        "child_merkle_root_matches",
        "child_height_matches_node_height",
        "rpc_block_serialization_sha256",
    ):
        if reparsed.get(key) != row.get(key):
            raise ValueError(f"full ROD body disagrees with extraction row: {key}")
    return reparsed


def _publication_row(
    source: Mapping[str, Any],
    result: Mapping[str, Any],
    line_number: int,
    bindings: Mapping[str, str],
) -> dict[str, str]:
    child_header = bytes.fromhex(str(source["child_header_hex"]))
    child = parse_child_header(
        child_header,
        expected_hash_display=CANONICAL_CHILD_HASH,
        nbits=int(str(source["effective_bits"]), 16),
    )
    if child_header[72:76] != bytes(4):
        raise ValueError("ROD pure child header nBits must be zero")
    parent = parse_header_fields(str(source["parent_header_hex"]))
    if parent.get("hash") != CANONICAL_BTC_HASH:
        raise ValueError("Bitcoin parent header identity mismatch")
    coinbase = parse_coinbase_tx(bytes.fromhex(str(source["parent_coinbase_hex"])))
    if (
        coinbase is None
        or coinbase["scriptsig"].hex() != source["parent_coinbase_scriptsig_hex"]
    ):
        raise ValueError("Bitcoin parent coinbase parsing mismatch")
    provenance = (
        f"rod-core-rpc:active-chain@{SOURCE_REVISION};"
        f"terminal:{TERMINAL_HEIGHT}:{TERMINAL_HASH};"
        f"powdata-envelope:{source['proof_envelope_sha256']};"
        f"audit:{bindings['audit_report.json']};"
        f"candidate-review:{bindings['review-receipt.json']}"
    )
    row = {field: "" for field in OUTPUT_FIELDS}
    row.update(
        {
            "chain": CHAIN,
            "source_kind": "canonical_blocks",
            "source_path": f"<chain-archive>/rod/comprehensive-run-v2/extraction/{result['source_locator']}",
            "source_row_number": str(line_number),
            "artifact_scope": "canonical_blocks",
            "provenance": provenance,
            "child_height": str(CANONICAL_HEIGHT),
            **child,
            "btc_height": str(CANONICAL_BTC_HEIGHT),
            "btc_header_hash": CANONICAL_BTC_HASH,
            "btc_prev_hash": parent["prev_hash"],
            "btc_time": parent["time"],
            "btc_bits": parent["bits"],
            "btc_nonce": parent["nonce"],
            "btc_header_hex": str(source["parent_header_hex"]),
            "coinbase_scriptsig_hex": coinbase["scriptsig"].hex(),
            "coinbase_outputs": format_outputs_canonical(coinbase["outputs"]),
            "full_coinbase_hex": str(source["parent_coinbase_hex"]),
            "classification": "canonical",
            "observation_id": str(result["observation_id"]),
            "proof_envelope_sha256": str(source["proof_envelope_sha256"]),
            "evidence_sha256": str(result["evidence_sha256"]),
            "extraction_chunk_sha256": bindings[str(result["source_locator"])],
            "extraction_receipt_sha256": bindings[
                str(result["source_provenance"]["chunk_receipt"])
            ],
            "audit_report_sha256": bindings["audit_report.json"],
            "candidate_inventory_sha256": bindings["candidate-inventory.json"],
            "candidate_review_receipt_sha256": bindings["review-receipt.json"],
        }
    )
    return row


def build_rod_canonical(
    *,
    extraction_root: Path,
    audit_root: Path,
    classification_summary_path: Path,
    candidates_path: Path,
    candidates_sha256: str,
    review_root: Path,
    review_receipt_sha256: str,
    framing_path: Path,
    extractor_path: Path,
    output_dir: Path,
) -> dict[str, Any]:
    """Validate the sealed evidence and atomically publish one canonical companion."""
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise ValueError(f"output already exists: {output_dir}")
    extraction_root = extraction_root.resolve()
    report, bindings = _validate_audit(audit_root.resolve(), extraction_root)
    summary, classification_inputs, summary_sha = _validate_classification_summary(
        classification_summary_path.resolve(), report
    )
    bindings["classification-summary.json"] = summary_sha
    run_config = _json(extraction_root / "run-config.json")
    expected_config = {
        "source_revision": SOURCE_REVISION,
        "genesis_hash": GENESIS_HASH,
        "terminal_height": TERMINAL_HEIGHT,
        "terminal_hash": TERMINAL_HASH,
        "framing_sha256": FRAMING_SHA256,
        "extractor_sha256": EXTRACTOR_SHA256,
    }
    for key, value in expected_config.items():
        if run_config.get(key) != value:
            raise ValueError(f"extraction run-config {key} mismatch")
    bindings["run-config.json"] = sha256_file(extraction_root / "run-config.json")
    _, review_bindings = _validate_review(review_root.resolve(), review_receipt_sha256)
    bindings.update(review_bindings)
    candidate, inventory_sha = _select_candidate(
        candidates_path.resolve(), candidates_sha256, summary
    )
    bindings["candidate-inventory.json"] = inventory_sha
    result = candidate["result"]
    source, line_number, source_bindings = _source_row(
        extraction_root, result, classification_inputs
    )
    bindings.update(source_bindings)
    framing = _load_module(
        framing_path.resolve(), FRAMING_SHA256, "rod_canonical_framing"
    )
    expected_extractor_dependency = (
        extractor_path.resolve().parent / "deps" / "rod_header_acquire.py"
    )
    if (
        expected_extractor_dependency.resolve() != framing_path.resolve()
        or sha256_file(expected_extractor_dependency) != FRAMING_SHA256
    ):
        raise ValueError("frozen extractor has a different framing dependency")
    extractor = _load_module(
        extractor_path.resolve(),
        EXTRACTOR_SHA256,
        "rod_canonical_extractor",
        framing_path=framing_path.resolve(),
    )
    loaded_dependency = Path(extractor.DEP).resolve()
    if (
        loaded_dependency != framing_path.resolve()
        or sha256_file(loaded_dependency) != FRAMING_SHA256
    ):
        raise ValueError("frozen extractor loaded a different framing dependency")
    if extractor.F is not sys.modules.get("rod_framing"):
        raise ValueError("frozen extractor framing module identity mismatch")
    body_path = review_root.resolve() / "rod-2697753-body.hex"
    _validate_full_evidence(source, body_path.read_text(), framing, extractor)
    if result.get("bitcoin_parent_height") != CANONICAL_BTC_HEIGHT:
        raise ValueError("canonical candidate Bitcoin height mismatch")
    row = _publication_row(source, result, line_number, bindings)

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    attempt = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}.", dir=output_dir.parent)
    )
    try:
        csv_path = attempt / "rod_canonical_blocks.csv"
        with csv_path.open("w", newline="") as handle:
            writer = csv.DictWriter(
                handle, fieldnames=OUTPUT_FIELDS, lineterminator="\n"
            )
            writer.writeheader()
            writer.writerow(row)
        receipt = {
            "schema": "rod-canonical-companion-v1",
            "canonical_rows": 1,
            "source_revision": SOURCE_REVISION,
            "terminal_height": TERMINAL_HEIGHT,
            "terminal_hash": TERMINAL_HASH,
            "audit_rows": report["rows_seen"],
            "canonical_child_height": CANONICAL_HEIGHT,
            "canonical_child_hash": CANONICAL_CHILD_HASH,
            "canonical_bitcoin_height": CANONICAL_BTC_HEIGHT,
            "canonical_bitcoin_hash": CANONICAL_BTC_HASH,
            "audit_recorded_extraction_root": report.get("extraction_root"),
            "producer_sha256": sha256_file(Path(__file__)),
            "producer_dependency_sha256": _producer_dependency_sha256(),
            "input_sha256": dict(sorted(bindings.items())),
            "output_sha256": sha256_file(csv_path),
        }
        (attempt / "receipt.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        )
        os.replace(attempt, output_dir)
        return receipt
    except Exception:
        shutil.rmtree(attempt, ignore_errors=True)
        raise
