from __future__ import annotations

import csv
import importlib.util
from pathlib import Path

from stale_blocks_analysis import stale_blocks

REPO = Path(__file__).resolve().parents[1]


def _load_script(relative_path: str, name: str):
    spec = importlib.util.spec_from_file_location(name, REPO / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_doichain_extractor_consensus_config() -> None:
    module = _load_script(
        "scripts/extract/extract_auxpow_from_blkdat.py", "_doichain_extractor"
    )
    config = module.CHAINS["doichain"]
    assert config["magic"] == bytes.fromhex("f8b2b2ff")
    assert config["auxpow_start"] == 1
    assert config["chain_id"] == 2
    assert not config.get("enforce_chain_id", False)


def test_doichain_classifier_normalizes_generic_and_legacy_rows(tmp_path: Path) -> None:
    module = _load_script(
        "scripts/classify/classify_doichain_stales.py", "_doichain_classifier"
    )
    generic = module.standardize_row(
        {
            "btc_hash": "aa" * 32,
            "btc_bits_hex": "1a0d69d7",
            "child_height": "123",
            "btc_bip34_height": "700000",
        }
    )
    assert generic["btc_header_hash"] == "aa" * 32
    assert generic["btc_bits"] == "1a0d69d7"
    assert generic["doi_height"] == "123"
    assert generic["btc_bip34_height"] == "700000"

    legacy = module.standardize_row(
        {
            "btc_header_hash": "bb" * 32,
            "btc_bits": "1b0404cb",
            "doi_height": "456",
        }
    )
    assert legacy["btc_header_hash"] == "bb" * 32
    assert legacy["btc_bits"] == "1b0404cb"
    assert legacy["doi_height"] == "456"


def test_doichain_loader_uses_validated_stale_contract(
    tmp_path: Path, monkeypatch
) -> None:
    path = tmp_path / "doichain_validated_stales.csv"
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "btc_height",
                "btc_header_hash",
                "coinbase_scriptsig_hex",
                "coinbase_outputs",
                "doi_height",
                "classification",
                "validation_status",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "btc_height": "700000",
                "btc_header_hash": "cc" * 32,
                "coinbase_scriptsig_hex": "03abcdef",
                "coinbase_outputs": "51",
                "doi_height": "400000",
                "classification": "stale",
                "validation_status": "VALID",
            }
        )
        writer.writerow(
            {
                "btc_height": "700001",
                "btc_header_hash": "dd" * 32,
                "classification": "unknown",
                "validation_status": "",
            }
        )
    monkeypatch.setattr(stale_blocks, "DOICHAIN_CSV", path)
    assert stale_blocks.load_doichain_stales(min_height=0) == [
        {
            "height": 700000,
            "hash": "cc" * 32,
            "source": "doichain",
            "_scriptsig_hex": "03abcdef",
            "_outputs_str": "51",
        }
    ]
