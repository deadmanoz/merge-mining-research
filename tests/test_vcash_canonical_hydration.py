from __future__ import annotations

import csv
import hashlib
from pathlib import Path
from typing import Any

import pytest

from stale_blocks_analysis.vcash_canonical import build_vcash_canonical_hydration


def _write_tsv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]), delimiter="\t")
        writer.writeheader()
        writer.writerows(rows)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def _header(
    *, prev_hash: str = "11" * 32, timestamp: int = 1_700_000_000, nonce: int = 42
) -> tuple[str, str]:
    raw = (
        (0x20000000).to_bytes(4, "little")
        + bytes.fromhex(prev_hash)[::-1]
        + b"\x22" * 32
        + timestamp.to_bytes(4, "little")
        + bytes.fromhex("1d00ffff")[::-1]
        + nonce.to_bytes(4, "little")
    )
    display_hash = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
    return raw.hex(), display_hash


class FakeRpc:
    def __init__(self, responses: dict[tuple[str, tuple[Any, ...]], Any]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def call(self, method: str, params: list | None = None) -> Any:
        key = (method, tuple(params or []))
        self.calls.append(key)
        return self.responses[key]


def _inputs(tmp_path: Path, btc_hash: str) -> tuple[Path, Path, str, str]:
    results = tmp_path / "results.tsv"
    classifications = tmp_path / "canonical_classification.tsv"
    vcash_hash = "01" + "23" * 31
    unknown_hash = "ff" * 32
    _write_tsv(
        results,
        [
            {
                "vcash_height": "100",
                "vcash_hash": vcash_hash,
                "btc_parent_hash": btc_hash,
                "pow_hash": btc_hash,
                "version": "3",
                "age": "2021-01-02, 03:04:05 UTC",
                "prev_hash": "44" * 32,
            },
            {
                "vcash_height": "101",
                "vcash_hash": "02" + "23" * 31,
                "btc_parent_hash": unknown_hash,
                "pow_hash": unknown_hash,
                "version": "3",
                "age": "2021-01-02, 03:05:05 UTC",
                "prev_hash": vcash_hash,
            },
        ],
    )
    _write_tsv(
        classifications,
        [
            {
                "vcash_height": "100",
                "btc_parent_hash": btc_hash,
                "leading_zeros": "19",
                "class": "canonical",
                "btc_height": "700000",
            },
            {
                "vcash_height": "101",
                "btc_parent_hash": unknown_hash,
                "leading_zeros": "18",
                "class": "unknown",
                "btc_height": "",
            },
        ],
    )
    return results, classifications, vcash_hash, unknown_hash


def _rpc(
    btc_hash: str,
    header_hex: str,
    *,
    height: int = 700000,
    confirmations: int = 10,
) -> FakeRpc:
    verbose = {
        "hash": btc_hash,
        "confirmations": confirmations,
        "height": height,
        "previousblockhash": "11" * 32,
        "time": 1_700_000_000,
        "bits": "1d00ffff",
        "nonce": 42,
    }
    block = {
        "hash": btc_hash,
        "confirmations": confirmations,
        "height": height,
        "tx": [
            {
                "hex": "010000000001",
                "vin": [{"coinbase": "03aabbcc"}],
                "vout": [
                    {"scriptPubKey": {"hex": "76a914" + "33" * 20 + "88ac"}},
                    {"scriptPubKey": {"hex": "6a01ff"}},
                ],
            }
        ],
    }
    return FakeRpc(
        {
            ("getblockheader", (btc_hash, True)): verbose,
            ("getblockheader", (btc_hash, False)): header_hex,
            ("getblock", (btc_hash, 2)): block,
        }
    )


def test_hydrates_only_canonical_rows_with_explicit_provenance(tmp_path: Path) -> None:
    header_hex, btc_hash = _header()
    results, classifications, vcash_hash, unknown_hash = _inputs(tmp_path, btc_hash)
    output = tmp_path / "vcash_canonical.csv"
    rpc = _rpc(btc_hash, header_hex)

    summary = build_vcash_canonical_hydration(
        wayback_results_path=results,
        canonical_classification_path=classifications,
        output_path=output,
        rpc=rpc,
    )

    rows = _read_csv(output)
    assert summary["canonical_rows"] == 1
    assert len(rows) == 1
    row = rows[0]
    assert row["chain"] == "vcash"
    assert row["artifact_scope"] == "partial_canonical_subset"
    assert row["classification"] == "canonical"
    assert row["validation_status"] == "CANONICAL_CONFIRMED"
    assert row["child_height"] == row["vcash_height"] == "100"
    assert row["child_block_time"] == "1609556645"
    assert row["vcash_block_hash_display"] == vcash_hash
    assert row["child_block_hash"] == bytes.fromhex(vcash_hash)[::-1].hex()
    assert row["child_block_hash_byte_order"] == "internal"
    assert row["btc_header_hash"] == btc_hash
    assert row["btc_height"] == "700000"
    assert row["btc_header_hex"] == header_hex
    assert len(row["btc_header_hex"]) == 160
    assert row["coinbase_scriptsig_hex"] == "03aabbcc"
    # The shared canonical rendering: a P2PKH script shows as its Bitcoin
    # address, nulldata stays raw hex, and the fixture's vout carries no
    # amounts so no value suffix is emitted.
    assert row["coinbase_outputs"] == "15fioDrrk36NmHdRCtGTu2TMj6rPXzG3sn;6a01ff"
    assert row["source_path"] == "<chain-archive>/vcash/wayback_scrape/results.tsv"
    assert row["source_row_number"] == "2"
    assert row["classification_source_row_number"] == "2"
    assert all(unknown_hash not in str(call) for call in rpc.calls)
    assert rpc.calls == [
        ("getblockheader", (btc_hash, True)),
        ("getblockheader", (btc_hash, False)),
        ("getblock", (btc_hash, 2)),
    ]


def test_fails_before_rpc_when_canonical_row_has_no_wayback_mapping(
    tmp_path: Path,
) -> None:
    header_hex, btc_hash = _header()
    results, classifications, _vcash_hash, _unknown_hash = _inputs(tmp_path, btc_hash)
    with classifications.open("a") as f:
        f.write(f"102\t{'aa' * 32}\t19\tcanonical\t700001\n")
    rpc = _rpc(btc_hash, header_hex)
    output = tmp_path / "vcash_canonical.csv"

    with pytest.raises(ValueError, match="absent from the Wayback results TSV"):
        build_vcash_canonical_hydration(
            wayback_results_path=results,
            canonical_classification_path=classifications,
            output_path=output,
            rpc=rpc,
        )

    assert not output.exists()
    assert rpc.calls == []


def test_fails_closed_when_core_height_does_not_match_classification(
    tmp_path: Path,
) -> None:
    header_hex, btc_hash = _header()
    results, classifications, _vcash_hash, _unknown_hash = _inputs(tmp_path, btc_hash)
    output = tmp_path / "vcash_canonical.csv"
    rpc = _rpc(btc_hash, header_hex, height=700001)

    with pytest.raises(ValueError, match="height mismatch"):
        build_vcash_canonical_hydration(
            wayback_results_path=results,
            canonical_classification_path=classifications,
            output_path=output,
            rpc=rpc,
        )

    assert not output.exists()


def test_fails_closed_when_core_no_longer_reports_parent_as_canonical(
    tmp_path: Path,
) -> None:
    header_hex, btc_hash = _header()
    results, classifications, _vcash_hash, _unknown_hash = _inputs(tmp_path, btc_hash)
    output = tmp_path / "vcash_canonical.csv"
    rpc = _rpc(btc_hash, header_hex, confirmations=-1)

    with pytest.raises(ValueError, match="does not report .* as canonical"):
        build_vcash_canonical_hydration(
            wayback_results_path=results,
            canonical_classification_path=classifications,
            output_path=output,
            rpc=rpc,
        )

    assert not output.exists()


def test_fails_closed_when_raw_header_does_not_match_parent_hash(
    tmp_path: Path,
) -> None:
    header_hex, btc_hash = _header()
    results, classifications, _vcash_hash, _unknown_hash = _inputs(tmp_path, btc_hash)
    output = tmp_path / "vcash_canonical.csv"
    wrong_header_hex, _wrong_hash = _header(nonce=43)
    rpc = _rpc(btc_hash, wrong_header_hex)

    with pytest.raises(ValueError, match="raw header hash mismatch"):
        build_vcash_canonical_hydration(
            wayback_results_path=results,
            canonical_classification_path=classifications,
            output_path=output,
            rpc=rpc,
        )

    assert not output.exists()
