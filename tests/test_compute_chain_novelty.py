"""Novelty allocation, publication gates and committed-report freshness."""

import csv
import importlib.util
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from stale_blocks_analysis import error_blocks

SPEC = importlib.util.spec_from_file_location(
    "compute_chain_novelty",
    Path(__file__).parents[1] / "scripts/compute_chain_novelty.py",
)
novelty = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(novelty)


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def write_csv(path, fields, rows=()):
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    clone = tmp_path / "upstream"
    clone.mkdir()
    git(clone, "init", "-q")
    git(clone, "config", "user.email", "test@example.invalid")
    git(clone, "config", "user.name", "Test")
    upstream = clone / "stale-blocks.csv"
    write_csv(
        upstream,
        ["height", "hash"],
        [{"height": 10, "hash": "a" * 64}, {"height": 20, "hash": "b" * 64}],
    )
    git(clone, "add", ".")
    git(clone, "commit", "-qm", "fixture")
    pin = git(clone, "rev-parse", "HEAD")
    manifest = tmp_path / "data-sources.tsv"
    manifest.write_text(f"stale-blocks\tunused\t{pin}\tunused\n")
    errors = tmp_path / "errors.csv"
    write_csv(
        errors,
        ["height", "hash", "classification"],
        [{"height": 20, "hash": "b" * 64, "classification": "error_block"}],
    )
    compact = tmp_path / "namecoin.csv"
    fields = ["btc_height", "btc_header_hash", "classification", "validation_status"]
    rows = [
        {
            "btc_height": h,
            "btc_header_hash": c * 64,
            "classification": "stale",
            "validation_status": status,
        }
        for h, c, status in [
            (10, "a", "VALID"),
            (20, "b", "VALID"),
            (30, "c", "INVALID"),
            (40, "d", "VALID (post-BCH, difficulty matches BTC)"),
            (40, "d", "VALID"),
        ]
    ]
    write_csv(compact, fields, rows)
    rod = tmp_path / "rod.csv"
    monkeypatch.setattr(
        novelty,
        "CHAINS_BY_AUXPOW_ACTIVATION",
        [("namecoin", "2011-10-08"), ("rod", "2022-06-09")],
    )
    monkeypatch.setattr(
        novelty,
        "CHAIN_SPECS",
        {
            k: replace(novelty.CHAIN_SPECS[k], validated_csv=p)
            for k, p in [("namecoin", compact), ("rod", rod)]
        },
    )
    monkeypatch.setattr(novelty, "CANONICAL_ONLY_CHAINS", frozenset({"rod"}))
    for name, value in {
        "STALE_DIR": clone,
        "STALE_CSV": upstream,
        "MANIFEST": manifest,
        "ERROR_BLOCKS_CSV": errors,
    }.items():
        monkeypatch.setattr(novelty, name, value)
    monkeypatch.setattr(novelty.stale_blocks, "STALE_CSV", upstream)
    monkeypatch.setattr(novelty.stale_blocks, "AUXPOW_CSV", compact)
    monkeypatch.setattr(
        novelty.stale_blocks,
        "exclude_error_block_rows",
        lambda rows: error_blocks.exclude_error_block_rows(rows, path=errors),
    )
    return compact, upstream, manifest, errors, rod


def test_allocation_preserves_identity_overlap_and_chronology():
    a, b, c, d = (10, "a"), (10, "b"), (20, "c"), (30, "d")
    chains = {"early": {a, b}, "later": {b, c, d}, "last": {c}}
    result = novelty.calculate({a}, chains)
    assert [r["chronological"] for r in result["rows"]] == [1, 2, 0]
    assert result["recovered"] == 4
    assert result["absent"] == sum(r["chronological"] for r in result["rows"]) == 3
    assert sum(r["absent"] for r in result["rows"]) > result["absent"]
    # Upstream absorption changes novelty without dropping recovered parents.
    absorbed = novelty.calculate({a, b}, chains)
    assert [r["chronological"] for r in absorbed["rows"]] == [0, 2, 0]
    # Correcting the earlier evidence reallocates credit to the next witness.
    corrected = novelty.calculate({a}, {**chains, "early": {a}})
    assert [r["chronological"] for r in corrected["rows"]] == [0, 3, 0]


def test_report_uses_gated_loaders_and_is_deterministic(inputs):
    report = novelty.build_report()
    assert "| [Namecoin](../docs/chains/namecoin.md) | 2 | 1 | 1 | 1 |" in report
    assert "canonical-only; no validated-stales CSV" in report
    assert "| Effective upstream | 1 |" in report  # catalogued upstream parent excluded
    assert (
        "| Recovered union across chains | 2 |" in report
    )  # rejected, error and duplicate rows excluded
    assert report == novelty.build_report()
    assert "\r" not in report
    assert str(inputs[0].parent) not in report


def test_same_date_order_uses_roster_order(inputs, monkeypatch):
    compact = inputs[0]
    monkeypatch.setattr(novelty, "CANONICAL_ONLY_CHAINS", frozenset())
    specs = {
        k: replace(novelty.CHAIN_SPECS["namecoin"], key=k)
        for k in ["geistgeld", "namecoin"]
    }
    monkeypatch.setattr(novelty, "CHAIN_SPECS", specs)
    monkeypatch.setattr(
        novelty, "CHAINS_BY_AUXPOW_ACTIVATION", [(k, "2011-10-08") for k in specs]
    )
    monkeypatch.setattr(novelty.stale_blocks, "GEISTGELD_CSV", compact)
    report = novelty.build_report()
    assert "chains/geistgeld.md) | 2 | 1 | 1 | 1 |" in report
    assert "chains/namecoin.md) | 2 | 1 | 1 | 0 |" in report


def test_genuine_zero_row_input(inputs):
    path = inputs[0]
    path.write_text(path.read_text().splitlines()[0] + "\n")
    assert "chains/namecoin.md) | 0 | 0 | 0 | 0 |" in novelty.build_report()


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "empty",
        "header",
        "truncated",
        "rod",
        "pin",
        "dirty",
        "unknown",
        "upstream_missing",
        "catalogue_missing",
        "loader",
        "roster",
    ],
)
def test_invalid_inputs_preserve_existing_report(inputs, tmp_path, monkeypatch, fault):
    compact, upstream, manifest, errors, rod = inputs
    if fault == "missing":
        compact.unlink()
    elif fault == "empty":
        compact.write_text("")
    elif fault == "header":
        compact.write_text("btc_height,btc_header_hash\n")
    elif fault == "truncated":
        compact.write_text(compact.read_text() + "50,hash\n")
    elif fault == "rod":
        rod.write_text("unexpected")
    elif fault == "pin":
        manifest.write_text("stale-blocks\tunused\twrong\tunused\n")
    elif fault == "dirty":
        upstream.write_text(upstream.read_text() + "60,changed\n")
    elif fault == "unknown":
        monkeypatch.setattr(novelty, "clone_state", lambda path: None)
    elif fault == "upstream_missing":
        upstream.unlink()
    elif fault == "catalogue_missing":
        errors.unlink()
    elif fault == "loader":
        monkeypatch.delattr(novelty.stale_blocks, "load_namecoin_stales")
    elif fault == "roster":
        monkeypatch.setattr(novelty, "CHAINS_BY_AUXPOW_ACTIVATION", [])
    output = tmp_path / "report.md"
    output.write_bytes(b"previous report\n")
    assert novelty.main(["--output", str(output)]) == 1
    assert output.read_bytes() == b"previous report\n"


def test_upstream_byte_comparison_catches_hidden_change(inputs):
    upstream = inputs[1]
    git(upstream.parent, "update-index", "--assume-unchanged", "stale-blocks.csv")
    upstream.write_text(upstream.read_text() + "60,changed\n")
    assert novelty.clone_state(upstream.parent)["dirty"] is False
    with pytest.raises(ValueError, match="differs from the pinned"):
        novelty.build_report()


def test_check_mode_never_writes_and_detects_stale_report(inputs, tmp_path):
    output = tmp_path / "nested" / "report.md"
    args = ["--output", str(output)]
    assert novelty.main([*args, "--check"]) == 1
    assert not output.parent.exists()
    assert novelty.main(args) == 0
    previous = output.read_bytes()
    stamp = output.stat().st_mtime_ns
    assert novelty.main([*args, "--check"]) == 0
    assert output.stat().st_mtime_ns == stamp
    assert novelty.main(args) == 0
    assert output.read_bytes() == previous
    output.write_bytes(previous + b"stale\n")
    assert novelty.main([*args, "--check"]) == 1
    assert output.read_bytes() == previous + b"stale\n"


def test_fingerprint_covers_catalogue_bytes_and_order(inputs, monkeypatch):
    before = novelty.input_fingerprint()
    errors = inputs[3]
    errors.write_bytes(errors.read_bytes() + b"\n")
    assert novelty.input_fingerprint() != before
    before = novelty.input_fingerprint()
    monkeypatch.setattr(
        novelty,
        "CHAINS_BY_AUXPOW_ACTIVATION",
        list(reversed(novelty.CHAINS_BY_AUXPOW_ACTIVATION)),
    )
    assert novelty.input_fingerprint() != before


def test_committed_report_is_fresh():
    if not novelty.STALE_DIR.exists():
        pytest.skip(
            "Pinned upstream clone has not been fetched; run scripts/fetch-data.sh"
        )
    assert novelty.main(["--check"]) == 0
