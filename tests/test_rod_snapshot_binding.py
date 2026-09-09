import copy
import hashlib
import json
from pathlib import Path

import pytest

from stale_blocks_analysis import rod_canonical as rod


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n")


def _snapshot(tmp_path: Path):
    extraction = tmp_path / "relocated-extraction"
    chunk_name = "chunks/0002697728-0002697983.jsonl"
    receipt_name = "receipts/0002697728-0002697983.json"
    row = {
        "height": rod.CANONICAL_HEIGHT,
        "node_block_hash": rod.CANONICAL_CHILD_HASH,
        "child_hash": rod.CANONICAL_CHILD_HASH,
        "parent_hash": rod.CANONICAL_BTC_HASH,
        "proof_envelope_sha256": "22" * 32,
    }
    _write_json(extraction / chunk_name, row)
    _write_json(
        extraction / receipt_name,
        {"chunk_sha256": rod.sha256_file(extraction / chunk_name)},
    )
    _write_json(extraction / "run-config.json", {})
    root = "/historical/immutable/extraction"
    inputs = [
        {
            "path": root + "/" + name,
            "kind": kind,
            "bytes": (extraction / name).stat().st_size,
            "sha256": rod.sha256_file(extraction / name),
        }
        for name, kind in (
            (chunk_name, "node-chunk"),
            (receipt_name, "node-chunk-receipt"),
            ("run-config.json", "node-extraction-run-config"),
        )
    ]
    summary = {
        "classifier_version": 6,
        "complete_context_and_source_coverage": True,
        "source_coverage_complete": True,
        "exact_hash_context_complete": True,
        "acquired_observations_accounted": 4_127_690,
        "acquired_sha256d_accounted": 1_058_017,
        "sha256d_observations": 1_058_017,
        "pointwise_rows": 1_058_017,
        "pointwise_sha256": "33" * 32,
        "rpc_errors": 0,
        "rpc_pending_observations": 0,
        "unresolved_source_rows": 0,
        "counts": {
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
        },
        "observation_source_binding": {
            "input_kind": "node-extraction",
            "input_path": root,
            "run_config_sha256": inputs[-1]["sha256"],
        },
        "inputs": inputs,
    }
    audit = {
        "extraction_root": root,
        "run_config_sha256": inputs[-1]["sha256"],
        "v6": {
            "errors": [],
            "pointwise_rows": 1_058_017,
            "pointwise_sha256": summary["pointwise_sha256"],
        },
    }
    result = {
        "source_locator": chunk_name,
        "source_provenance": {"chunk_receipt": receipt_name},
        "envelope_sha256": row["proof_envelope_sha256"],
    }
    return extraction, summary, audit, result


def _summary_path(tmp_path, summary, audit):
    path = tmp_path / "classification-summary.json"
    _write_json(path, summary)
    audit["v6"]["summary_sha256"] = rod.sha256_file(path)
    return path


def test_classification_manifest_relocates_and_authenticates_selected_files(tmp_path):
    extraction, summary, audit, result = _snapshot(tmp_path)
    path = _summary_path(tmp_path, summary, audit)

    validated, manifest, digest = rod._validate_classification_summary(path, audit)
    row, line, bindings = rod._source_row(extraction, result, manifest)

    assert validated == summary
    assert digest == audit["v6"]["summary_sha256"]
    assert set(manifest) == {
        "run-config.json",
        result["source_locator"],
        result["source_provenance"]["chunk_receipt"],
    }
    assert line == 1
    assert row["child_hash"] == rod.CANONICAL_CHILD_HASH
    assert bindings == {
        key: value["sha256"]
        for key, value in manifest.items()
        if key != "run-config.json"
    }


def test_classification_summary_must_match_immutable_audit_digest(tmp_path):
    _, summary, audit, _ = _snapshot(tmp_path)
    path = _summary_path(tmp_path, summary, audit)
    summary["classifier_version"] = 7
    _write_json(path, summary)

    with pytest.raises(ValueError, match="SHA256 mismatch"):
        rod._validate_classification_summary(path, audit)


@pytest.mark.parametrize(
    "field,value",
    [
        ("classifier_version", 5),
        ("complete_context_and_source_coverage", False),
        ("source_coverage_complete", 1),
        ("exact_hash_context_complete", None),
        ("acquired_observations_accounted", 4_127_689),
        ("acquired_sha256d_accounted", 1_058_016),
        ("sha256d_observations", 1_058_016),
        ("pointwise_rows", 1_058_016),
        ("pointwise_sha256", "44" * 32),
        ("rpc_errors", 1),
        ("rpc_pending_observations", 1),
        ("unresolved_source_rows", 1),
    ],
)
def test_classification_rejects_incomplete_or_contradictory_summary(
    tmp_path, field, value
):
    _, summary, audit, _ = _snapshot(tmp_path)
    summary[field] = value
    path = _summary_path(tmp_path, summary, audit)

    with pytest.raises(ValueError, match="classification summary"):
        rod._validate_classification_summary(path, audit)


@pytest.mark.parametrize(
    "field,category",
    [
        ("bitcoin_context_category", "bitcoin_canonical_parent"),
        ("research_classification", "stale"),
        ("publication_disposition", "accepted_stale"),
    ],
)
def test_classification_rejects_changed_or_additional_category_counts(
    tmp_path, field, category
):
    _, summary, audit, _ = _snapshot(tmp_path)
    summary["counts"][field][category] = 2
    path = _summary_path(tmp_path, summary, audit)

    with pytest.raises(ValueError, match="inventory mismatch"):
        rod._validate_classification_summary(path, audit)


@pytest.mark.parametrize("field", ["input_kind", "input_path", "run_config_sha256"])
def test_classification_rejects_a_different_extraction_binding(tmp_path, field):
    _, summary, audit, _ = _snapshot(tmp_path)
    summary["observation_source_binding"][field] = "different"
    path = _summary_path(tmp_path, summary, audit)

    with pytest.raises(ValueError, match="extraction binding mismatch"):
        rod._validate_classification_summary(path, audit)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda entries: entries.append(copy.deepcopy(entries[0])),
        lambda entries: entries.append(None),
        lambda entries: entries[0].update(path="/elsewhere/chunk.jsonl"),
        lambda entries: entries[0].update(
            path=entries[0]["path"].replace("/chunks/", "/chunks/../chunks/")
        ),
        lambda entries: entries[0].update(
            path=entries[0]["path"].replace("/chunks/", "/chunks//")
        ),
        lambda entries: entries[0].update(path="chunks/relative.jsonl"),
        lambda entries: entries[0].update(kind="node-chunk-receipt"),
        lambda entries: entries[0].update(sha256="not-a-digest"),
        lambda entries: entries[0].update(bytes=True),
        lambda entries: entries[0].update(bytes=-1),
        lambda entries: entries[0].pop("sha256"),
        lambda entries: entries.pop(1),
        lambda entries: entries.pop(),
    ],
)
def test_classification_rejects_unsafe_or_unbound_manifest_entries(tmp_path, mutation):
    _, summary, audit, _ = _snapshot(tmp_path)
    mutation(summary["inputs"])
    path = _summary_path(tmp_path, summary, audit)

    with pytest.raises(ValueError, match="classification summary"):
        rod._validate_classification_summary(path, audit)


@pytest.mark.parametrize("which", ["chunk", "receipt"])
@pytest.mark.parametrize("mutation", ["missing", "kind", "sha256", "bytes"])
def test_selected_files_require_matching_summary_membership(tmp_path, which, mutation):
    extraction, summary, audit, result = _snapshot(tmp_path)
    path = _summary_path(tmp_path, summary, audit)
    _, manifest, _ = rod._validate_classification_summary(path, audit)
    key = (
        result["source_locator"]
        if which == "chunk"
        else result["source_provenance"]["chunk_receipt"]
    )
    if mutation == "missing":
        del manifest[key]
    elif mutation == "bytes":
        manifest[key]["bytes"] += 1
    else:
        manifest[key][mutation] = "different"

    with pytest.raises(ValueError, match="does not match classification summary"):
        rod._source_row(extraction, result, manifest)


def test_consistently_rewritten_chunk_and_receipt_cannot_replace_audited_input(
    tmp_path,
):
    extraction, summary, audit, result = _snapshot(tmp_path)
    path = _summary_path(tmp_path, summary, audit)
    _, manifest, _ = rod._validate_classification_summary(path, audit)
    chunk = extraction / result["source_locator"]
    row = json.loads(chunk.read_text())
    row["added_unreviewed_field"] = "tampering"
    _write_json(chunk, row)
    _write_json(
        extraction / result["source_provenance"]["chunk_receipt"],
        {"chunk_sha256": rod.sha256_file(chunk)},
    )

    with pytest.raises(ValueError, match="does not match classification summary"):
        rod._source_row(extraction, result, manifest)


def _special_candidate(canonical):
    evidence = {
        "source_scope": "rod_active_chain",
        "source_locator": "chunks/canonical.jsonl"
        if canonical
        else "chunks/unknown.jsonl",
        "acquisition_height": rod.CANONICAL_HEIGHT if canonical else 3_695_901,
        "child_hash": rod.CANONICAL_CHILD_HASH if canonical else "44" * 32,
        "envelope_sha256": "55" * 32,
        "parent_self_target_pass": canonical,
    }
    evidence["evidence_sha256"] = rod._canonical_json_sha256(evidence)
    observation_id = hashlib.sha256(
        "\0".join(str(evidence[k]) for k in rod.OBSERVATION_ID_FIELDS).encode()
    ).hexdigest()
    return {
        "observation_id": observation_id,
        "evidence": evidence,
        "result": {
            **evidence,
            "observation_id": observation_id,
            "bitcoin_context_category": "bitcoin_canonical_parent"
            if canonical
            else "bitcoin_known_noncanonical_predecessor",
            "research_classification": "canonical_candidate"
            if canonical
            else "unknown",
            "publication_disposition": "requires_publication_profile_review"
            if canonical
            else "requires_ancestry_and_consensus_review",
        },
    }


def test_complete_special_inventory_retains_unaccepted_noncanonical_evidence(tmp_path):
    _, summary, _, _ = _snapshot(tmp_path)
    payload = [_special_candidate(True), _special_candidate(False)]
    path = tmp_path / "special.json"
    _write_json(path, payload)

    selected, _ = rod._select_candidate(path, rod.sha256_file(path), summary)

    assert selected == payload[0]
    assert json.loads(path.read_text()) == payload


@pytest.mark.parametrize("field", rod.OBSERVATION_ID_FIELDS)
def test_special_inventory_requires_result_identity_fields(tmp_path, field):
    _, summary, _, _ = _snapshot(tmp_path)
    payload = [_special_candidate(True), _special_candidate(False)]
    del payload[0]["result"][field]
    path = tmp_path / "special.json"
    _write_json(path, payload)

    with pytest.raises(ValueError, match="result/evidence mismatch"):
        rod._select_candidate(path, rod.sha256_file(path), summary)


@pytest.mark.parametrize(
    "field,value",
    [("acquisition_height", rod.CANONICAL_HEIGHT - 1), ("child_hash", "66" * 32)],
)
def test_canonical_candidate_cannot_rehash_a_different_child_identity(
    tmp_path, field, value
):
    _, summary, _, _ = _snapshot(tmp_path)
    payload = [_special_candidate(True), _special_candidate(False)]
    candidate = payload[0]
    evidence = candidate["evidence"]
    evidence[field] = value
    del evidence["evidence_sha256"]
    evidence["evidence_sha256"] = rod._canonical_json_sha256(evidence)
    candidate["result"].update(evidence)
    new_id = hashlib.sha256(
        "\0".join(str(evidence[key]) for key in rod.OBSERVATION_ID_FIELDS).encode()
    ).hexdigest()
    candidate["observation_id"] = candidate["result"]["observation_id"] = new_id
    path = tmp_path / "special.json"
    _write_json(path, payload)

    with pytest.raises(ValueError, match="pinned child"):
        rod._select_candidate(path, rod.sha256_file(path), summary)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda items: items.pop(),
        lambda items: items.append(_special_candidate(False)),
        lambda items: items.__setitem__(1, None),
        lambda items: items.__setitem__(1, copy.deepcopy(items[0])),
        lambda items: items[1]["result"].update(
            bitcoin_context_category="unresolved_parent_network"
        ),
        lambda items: items[1]["result"].update(research_classification="stale"),
        lambda items: items[1]["result"].update(publication_disposition="accepted"),
        lambda items: items[1]["result"].update(parent_self_target_pass=True),
        lambda items: items[0]["result"].update(parent_self_target_pass=False),
        lambda items: items[1].update(observation_id="00" * 32),
        lambda items: items[1]["evidence"].update(envelope_sha256="00" * 32),
    ],
)
def test_special_inventory_rejects_extra_malformed_or_accepted_noncanonical_rows(
    tmp_path, mutation
):
    _, summary, _, _ = _snapshot(tmp_path)
    payload = [_special_candidate(True), _special_candidate(False)]
    mutation(payload)
    path = tmp_path / "special.json"
    _write_json(path, payload)

    with pytest.raises(ValueError, match="special.candidate"):
        rod._select_candidate(path, rod.sha256_file(path), summary)
