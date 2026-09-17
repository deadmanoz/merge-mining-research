"""Body identity and external-attestation integration, not rule re-validation."""

import csv
import hashlib

import pytest

from stale_blocks_analysis.body_evidence import (
    BODY_EVIDENCE_COLUMNS,
    load_body_evidence,
)
from stale_blocks_analysis.config import (
    BLOCKS_DIR,
    BODY_ERROR_REJECTIONS,
)
from stale_blocks_analysis.error_block_validation import validate_dataset, validate_row
from stale_blocks_analysis.auxpow_parse import parse_parent_header, read_transaction
from stale_blocks_analysis.bitcoin_binary import _varint


def write_csv(path, columns, rows):
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


@pytest.fixture(
    params=[
        (474294, "missing_unconfirmed_parent", 34),
        (477115, "bad-txns-inputs-missingorspent", 35),
        (783426, "bad-blk-sigops", 42),
        (784121, "bad-blk-sigops", 43),
    ]
)
def body_case(request, tmp_path):
    """Use retained bodies with independent verdicts in an isolated catalogue."""
    height, rule, line = request.param
    block_hash = {
        474294: "00000000000000000182acdf5657c93a0769dc6f9004047496b2e15efc6a4232",
        477115: "0000000000000000013ee4a86822d37a061732e04ee5f41fb77168f193363d1b",
        783426: "00000000000000000002ec935e245f8ae70fc68cc828f05bf4cfa002668599e4",
        784121: "000000000000000000046a2698233ed93bb5e74ba7d2146a68ddb0c2504c980d",
    }[height]
    name = f"{height}-{block_hash}.bin"
    source_path = BLOCKS_DIR / name
    if not source_path.exists():
        pytest.skip("pinned stale-blocks bodies not fetched")
    raw = source_path.read_bytes()
    block_path = tmp_path / name
    block_path.write_bytes(raw)
    header = parse_parent_header(raw[:80])
    _, tx_start = _varint(raw, 80)
    coinbase, _ = read_transaction(raw, tx_start)
    row = {
        "height": str(height),
        "hash": block_hash,
        "btc_prev_hash": header["prev_hash"],
        "btc_header_version": str(int.from_bytes(raw[:4], "little", signed=True)),
        "btc_time": str(header["time"]),
        "btc_bits": header["bits_hex"],
        "expected_nbits": header["bits_hex"],
        "btc_header_hex": header["header_hex"],
        "coinbase_height": str(height),
        "coinbase_scriptsig_hex": coinbase["vin"][0]["scriptsig"].hex(),
        "classification": "error_block",
        "rejection_reason": BODY_ERROR_REJECTIONS[rule],
        "rules_violated": rule,
    }
    record = {
        "height": str(height),
        "hash": block_hash,
        "rule": rule,
        "block_file": f"blocks/{name}",
        "block_sha256": hashlib.sha256(raw).hexdigest(),
        "evidence_url": "https://github.com/bitcoin-data/invalid-blocks/blob/"
        f"4d7063b3c8ddf7ab0dcc7deaa18f61d35952ba25/data/invalid-blocks.jsonl#L{line}",
    }
    sidecar = tmp_path / "body_evidence.csv"
    write_csv(sidecar, BODY_EVIDENCE_COLUMNS, [record])
    catalogue = tmp_path / "error_blocks.csv"
    write_csv(catalogue, list(row), [row])
    return row, record, block_path, sidecar, catalogue


def test_external_body_rule_admission_requires_complete_evidence(body_case, tmp_path):
    row, record, block_path, sidecar, catalogue = body_case
    assert validate_dataset(catalogue, blocks_dir=tmp_path) == []
    assert any("missing body evidence" in f for f in validate_row(row))
    block_path.unlink()
    assert any(
        "required body" in f for f in validate_dataset(catalogue, blocks_dir=tmp_path)
    )
    sidecar.unlink()
    assert any(
        "missing body evidence" in f
        for f in validate_dataset(catalogue, blocks_dir=tmp_path)
    )


@pytest.mark.parametrize("corruption", ["digest", "header", "truncated", "body"])
def test_corrupt_body_cannot_authenticate(body_case, tmp_path, corruption):
    row, record, block_path, sidecar, catalogue = body_case
    raw = block_path.read_bytes()
    if corruption == "digest":
        record["block_sha256"] = "00" * 32
    else:
        if corruption == "header":
            raw = bytes([raw[0] ^ 1]) + raw[1:]
        elif corruption == "truncated":
            raw = raw[:-1]
        else:
            raw = raw[:-1] + bytes([raw[-1] ^ 1])
        # Updating the file digest alone must not bypass header/body checks.
        record["block_sha256"] = hashlib.sha256(raw).hexdigest()
        block_path.write_bytes(raw)
    write_csv(sidecar, BODY_EVIDENCE_COLUMNS, [record])
    assert validate_dataset(catalogue, blocks_dir=tmp_path)


@pytest.mark.parametrize(
    "field,value",
    [
        (
            "evidence_url",
            "https://github.com/bitcoin-data/invalid-blocks/blob/main/data/invalid-blocks.jsonl#L1",
        ),
        ("block_file", "../substituted.bin"),
        ("rule", "unreviewed-rule"),
    ],
)
def test_sidecar_rejects_unpinned_or_malformed_evidence(body_case, field, value):
    _, record, _, sidecar, _ = body_case
    write_csv(sidecar, BODY_EVIDENCE_COLUMNS, [dict(record, **{field: value})])
    with pytest.raises(ValueError):
        load_body_evidence(sidecar)


def test_sidecar_requires_unique_matching_rule_membership(body_case, tmp_path):
    row, record, _, sidecar, catalogue = body_case
    write_csv(sidecar, BODY_EVIDENCE_COLUMNS, [record, record])
    assert any(
        "duplicate body-evidence key" in f
        for f in validate_dataset(catalogue, blocks_dir=tmp_path)
    )
    mismatched_rule = (
        "missing_unconfirmed_parent"
        if record["rule"] == "bad-blk-sigops"
        else "bad-blk-sigops"
    )
    write_csv(sidecar, BODY_EVIDENCE_COLUMNS, [dict(record, rule=mismatched_rule)])
    assert any(
        "does not match" in f for f in validate_dataset(catalogue, blocks_dir=tmp_path)
    )
    write_csv(sidecar, BODY_EVIDENCE_COLUMNS, [record])
    row["rules_violated"] = row["rejection_reason"] = "unregistered-rule"
    write_csv(catalogue, list(row), [row])
    failures = validate_dataset(catalogue, blocks_dir=tmp_path)
    assert any("no gate registered" in f for f in failures)
    assert any("no matching catalogue body rule" in f for f in failures)


def test_catalogue_scriptsig_must_match_authenticated_body(body_case, tmp_path):
    row, _, _, _, catalogue = body_case
    assert validate_dataset(catalogue, blocks_dir=tmp_path) == []
    # Keep the BIP34 prefix and script length valid while corrupting the tag.
    scriptsig = bytearray.fromhex(row["coinbase_scriptsig_hex"])
    scriptsig[-1] ^= 1
    row["coinbase_scriptsig_hex"] = scriptsig.hex()
    write_csv(catalogue, list(row), [row])
    assert any(
        "body coinbase scriptSig does not match catalogue" in failure
        for failure in validate_dataset(catalogue, blocks_dir=tmp_path)
    )
