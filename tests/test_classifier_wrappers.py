"""Wrapper-preservation tests for the run_classifier adopter scripts.

Adopting ``run_classifier`` reduced each Bucket A classifier to a thin ``main()``.
Parse/import smoke tests prove the modules load, but not that each wrapper still
forwards the right ChainSpec, paths, decimal flag, and RPC/transport. These
tests load a classifier as a module, replace its ``run_classifier`` reference
with a recorder, invoke ``main()`` with explicit CLI args, and assert the
forwarded call -- so a wrapper that silently dropped a default, an env var, or
the decimal flag would fail here.
"""

from __future__ import annotations

import csv
import importlib.util
import struct
import sys
from pathlib import Path

import pytest

from stale_blocks_analysis.auxpow_parse import parse_child_header, parse_parent_header
from stale_blocks_analysis.btc_classify import output_columns, run_classifier
from stale_blocks_analysis.config import CHAIN_SPECS

REPO = Path(__file__).resolve().parents[1]
CLASSIFY = REPO / "scripts" / "classify"


def _load(name: str):
    """Load scripts/classify/<name>.py as a fresh, uniquely-named module."""
    path = CLASSIFY / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"_wrap_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Recorder:
    """Stand-in for run_classifier that records its call and returns a summary
    dict carrying every key the wrappers print."""

    def __init__(self):
        self.calls = []

    def __call__(self, spec, **kwargs):
        self.calls.append({"spec": spec, **kwargs})
        return {
            k: 0
            for k in (
                "total",
                "btc_valid",
                "stale",
                "unknown",
                "valid",
                "rejected",
                "validation_unknown",
                "near",
            )
        } | {
            "output_path": kwargs.get("output_path", ""),
            "validated_output_path": kwargs.get("validated_output_path", ""),
            "near_output_path": None,
        }


def _run_main(monkeypatch, module, argv):
    rec = _Recorder()
    monkeypatch.setattr(module, "run_classifier", rec)
    monkeypatch.setattr(sys, "argv", argv)
    module.main()
    assert len(rec.calls) == 1, "main() must call run_classifier exactly once"
    return rec.calls[0]


def test_ixcoin_wrapper_forwards_standard(monkeypatch, tmp_path):
    mod = _load("classify_ixcoin_stales")
    call = _run_main(
        monkeypatch,
        mod,
        ["x", "--input", "in.csv", "--output", "out.csv", "--all-valid", "v.csv"],
    )
    assert call["spec"].key == "ixcoin"
    assert call["input_path"] == "in.csv"
    assert call["output_path"] == "out.csv"
    assert call["all_valid_path"] == "v.csv"
    # Every wrapper now builds and forwards a real BtcRpc via the shared
    # classifier_cli helpers (see the classifier_cli tests below for that
    # coverage); hex bits (decimal flag absent or False) is chain-specific.
    assert call.get("bits_source_is_decimal", False) is False


def test_xaya_wrapper_forwards_standard(monkeypatch, tmp_path):
    mod = _load("classify_xaya_stales")
    call = _run_main(
        monkeypatch,
        mod,
        [
            "x",
            "--input",
            "in.csv",
            "--output",
            "out.csv",
            "--all-valid",
            "v.csv",
            "--validated-output",
            "validated.csv",
        ],
    )
    assert call["spec"].key == "xaya"
    assert call["input_path"] == "in.csv"
    assert call["output_path"] == "out.csv"
    assert call["all_valid_path"] == "v.csv"
    # Every thin wrapper now exposes --validated-output so Phase B can
    # redirect the committed VALID-only CSV into the archive dir.
    assert call["validated_output_path"] == "validated.csv"
    assert call.get("bits_source_is_decimal", False) is False


def test_syscoin_wrapper_forwards_standard(monkeypatch):
    mod = _load("classify_syscoin_stales")
    call = _run_main(
        monkeypatch,
        mod,
        [
            "x",
            "--input",
            "in.csv",
            "--output",
            "out.csv",
            "--all-valid",
            "v.csv",
            "--validated-output",
            "validated.csv",
        ],
    )
    assert call["spec"].key == "syscoin"
    assert call["input_path"] == "in.csv"
    assert call["output_path"] == "out.csv"
    assert call["all_valid_path"] == "v.csv"
    # Syscoin exposes --validated-output (standard on every thin wrapper) so
    # the committed VALID-only CSV can be redirected explicitly.
    assert call["validated_output_path"] == "validated.csv"
    assert call.get("bits_source_is_decimal", False) is False

    # The historical input default (data/auxpow_raw.csv, not the per-chain
    # data/syscoin_auxpow_raw.csv name) is preserved.
    defaults = _run_main(monkeypatch, mod, ["x"])
    assert defaults["input_path"] == "data/auxpow_raw.csv"
    assert (
        defaults["validated_output_path"]
        == "data/validated-stales/syscoin_validated_stales.csv"
    )


def test_elastos_bespoke_classifier_reproduces_committed_schema():
    mod = _load("classify_elastos_stales")
    committed_header = (
        (REPO / "data" / "validated-stales" / "elastos_validated_stales.csv")
        .read_text()
        .splitlines()[0]
        .split(",")
    )
    assert mod.OUTPUT_COLUMNS == committed_header


def test_elcash_wrapper_forwards_standard_and_reproduces_committed_schema(monkeypatch):
    mod = _load("classify_elcash_stales")
    call = _run_main(monkeypatch, mod, ["x"])  # all defaults
    assert call["spec"].key == "elcash"
    assert call["input_path"] == "data/elcash_auxpow_raw.csv"
    assert call["output_path"] == "data/elcash_stale_blocks.csv"
    assert (
        call["validated_output_path"]
        == "data/validated-stales/elcash_validated_stales.csv"
    )
    assert call["all_valid_path"] == "data/elcash_btc_valid.csv"
    assert call.get("bits_source_is_decimal", False) is False
    # The wrapper's output schema is exactly the committed loader CSV's header,
    # so the normal source rerun reproduces its column set and order.
    committed_header = (
        (REPO / "data" / "validated-stales" / "elcash_validated_stales.csv")
        .read_text()
        .splitlines()[0]
        .split(",")
    )
    assert output_columns(call["spec"].height_column) == committed_header


def test_emercoin_normalizer_maps_legacy_schema_without_chain_id_filter(tmp_path):
    mod = _load("classify_emercoin_stales")
    src = tmp_path / "raw.csv"
    dst = tmp_path / "norm.csv"
    # A legacy-schema row (btc_parent_hash / btc_timestamp) plus a row carrying a
    # non-6 chain_id. Emercoin's raw extract has no chain_id column and the old
    # copy-pasted `chain_id != "6"` guard was inert dead code; the migration
    # removed it, so BOTH rows must survive (no branch filtering).
    with src.open("w", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "btc_parent_hash",
                "btc_prev_hash",
                "btc_timestamp",
                "btc_bits",
                "emc_height",
                "classification",
                "chain_id",
            ],
        )
        w.writeheader()
        w.writerow(
            {
                "btc_parent_hash": "aa" * 32,
                "btc_prev_hash": "bb" * 32,
                "btc_timestamp": "1700000000",
                "btc_bits": "1a0d69d7",
                "emc_height": "220000",
                "classification": "stale",
                "chain_id": "6",
            }
        )
        w.writerow(
            {"btc_parent_hash": "cc" * 32, "chain_id": "2", "emc_height": "220001"}
        )

    total = mod._write_normalized_input(src, dst)
    # Single return value (row count): there is no skipped-chain counter because
    # no chain-id filtering happens, unlike the Huntercoin normalizer.
    assert total == 2

    with dst.open(newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 2  # both rows kept; the chain_id "2" row is NOT dropped
    first = rows[0]
    assert first["btc_header_hash"] == "aa" * 32  # from btc_parent_hash
    assert first["btc_time"] == "1700000000"  # from btc_timestamp
    assert first["emc_height"] == "220000"
    # chain_id never enters the normalized schema.
    assert "chain_id" not in first


def test_coiledcoin_remap_does_not_promote_bip34_commitment_to_btc_height():
    mod = _load("classify_coiledcoin_stales")
    child_header = (
        struct.pack("<I", 1)
        + b"\x11" * 32
        + b"\x22" * 32
        + struct.pack("<III", 1_700_000_001, 0x1D00FFFF, 8)
    )
    candidate = mod.remap_candidate(
        {
            "btc_hash": "aa" * 32,
            "btc_prev_hash": "bb" * 32,
            "btc_time": "1700000000",
            "btc_bits_hex": "1d00ffff",
            "btc_bip34_height": "700000",
            "coinbase_scriptsig_hex": "03abcdef",
            "coinbase_outputs": "",
            "btc_header_hex": "00" * 80,
            "child_height": "",
            **parse_child_header(child_header),
        }
    )

    assert candidate["btc_height"] == ""
    assert candidate["btc_bip34_height"] == "700000"
    assert candidate["clc_height"] == ""


def test_coiledcoin_remap_rejects_partial_child_header_bundle():
    mod = _load("classify_coiledcoin_stales")

    with pytest.raises(
        mod.ChildHeaderValidationError,
        match="incomplete child header evidence",
    ):
        mod.remap_candidate(
            {
                "btc_hash": "aa" * 32,
                "btc_prev_hash": "bb" * 32,
                "btc_time": "1700000000",
                "btc_bits_hex": "1d00ffff",
                "coinbase_scriptsig_hex": "03abcdef",
                "coinbase_outputs": "",
                "btc_header_hex": "00" * 80,
                "child_height": "",
                "child_block_hash": "11" * 32,
            }
        )


class _PreflightRpc:
    """Fake BtcRpc: answers the getblockcount preflight; anything else -> None."""

    def __init__(self):
        self.calls = []

    def batch(self, calls):
        self.calls.append(calls)
        out = []
        for call in calls:
            if call["method"] == "getblockcount":
                out.append({"id": call["id"], "result": 800_000, "error": None})
            else:
                out.append({"id": call["id"], "result": None, "error": None})
        return out


def _near_input_row(dvc_height: str) -> dict:
    """A parseable 80-byte header that fails its encoded target (target 1, bits
    0x03000001), so run_classifier drops it unless keep_near is set."""
    header = (
        struct.pack("<I", 1)
        + b"\x11" * 32
        + b"\x22" * 32
        + struct.pack("<I", 1_700_000_000)
        + struct.pack("<I", 0x03000001)
        + struct.pack("<I", 0)
    )
    parsed = parse_parent_header(header)
    child_header = (
        struct.pack("<I", 1)
        + b"\x33" * 32
        + b"\x44" * 32
        + struct.pack("<III", 1_600_000_555, 0x1D00FFFF, 555)
    )
    return {
        "btc_height": "",
        "btc_header_hash": parsed["hash"],
        "btc_prev_hash": parsed["prev_hash"],
        "btc_time": str(parsed["time"]),
        "btc_bits": parsed["bits_hex"],
        "coinbase_scriptsig_hex": "03abcdef",
        "coinbase_outputs": "",
        "btc_header_hex": header.hex(),
        "dvc_height": dvc_height,
        **parse_child_header(child_header),
    }


def _write_near_input(path: Path) -> None:
    row = _near_input_row("555")
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)


def test_keep_near_writes_fifth_file(tmp_path):
    inp = tmp_path / "in.csv"
    _write_near_input(inp)
    out = tmp_path / "devcoin_stale_blocks.csv"
    summary = run_classifier(
        CHAIN_SPECS["devcoin"],
        input_path=str(inp),
        output_path=str(out),
        validated_output_path=str(tmp_path / "validated.csv"),
        keep_near=True,
        rpc=_PreflightRpc(),
    )
    near_path = tmp_path / "devcoin_near_blocks.csv"
    assert summary["near"] == 1
    assert summary["near_output_path"] == str(near_path)
    assert near_path.exists()
    with near_path.open(newline="") as f:
        near_rows = list(csv.DictReader(f))
    assert len(near_rows) == 1
    assert near_rows[0]["classification"] == "near"
    assert near_rows[0]["dvc_height"] == "555"


def test_keep_near_off_by_default_writes_no_fifth_file(tmp_path):
    inp = tmp_path / "in.csv"
    _write_near_input(inp)
    out = tmp_path / "devcoin_stale_blocks.csv"
    summary = run_classifier(
        CHAIN_SPECS["devcoin"],
        input_path=str(inp),
        output_path=str(out),
        validated_output_path=str(tmp_path / "validated.csv"),
        rpc=_PreflightRpc(),
    )
    assert summary["near"] == 0
    assert summary["near_output_path"] is None
    assert not (tmp_path / "devcoin_near_blocks.csv").exists()


def test_bitcoin_vault_wrapper_preserves_decimal_and_forwards_rpc(monkeypatch):
    # The historical hardcoded bitcoin/bitcoin RPC-auth default is retired as
    # part of the fleet-wide CLI cutover: with no --rpc-user/--rpc-pass this
    # wrapper now falls back to get_btc_auth's cookie/conf/env discovery like
    # every other classifier, rather than injecting a fixed default client.
    mod = _load("classify_bitcoin_vault_stales")
    call = _run_main(
        monkeypatch,
        mod,
        [
            "x",
            "--input",
            "in.csv",
            "--output",
            "out.csv",
            "--all-valid",
            "v.csv",
            "--rpc-user",
            "u",
            "--rpc-pass",
            "p",
        ],
    )
    assert call["spec"].key == "bitcoin-vault"
    # Decimal flag is the whole point for BTCV's legacy decimal btc_bits.
    assert call["bits_source_is_decimal"] is True
    rpc = call.get("rpc")
    assert rpc is not None
    assert rpc.auth == ("u", "p")


def test_bitmark_wrapper_honors_btc_rpc_url_env(monkeypatch):
    # BTC_RPC_URL is read when add_rpc_args builds the --rpc-url default
    # inside main(), so setting it any time before main() runs is enough.
    monkeypatch.setenv("BTC_RPC_URL", "http://10.1.2.3:9999")
    monkeypatch.setenv("BITCOIN_RPC_USER", "u")
    monkeypatch.setenv("BITCOIN_RPC_PASSWORD", "p")
    mod = _load("classify_bitmark_stales")
    call = _run_main(
        monkeypatch,
        mod,
        ["x", "--input", "in.csv", "--output", "out.csv", "--all-valid", "v.csv"],
    )
    assert call["spec"].key == "bitmark"
    rpc = call.get("rpc")
    assert rpc is not None
    assert rpc.url == "http://10.1.2.3:9999"  # env endpoint preserved
    assert call.get("bits_source_is_decimal", False) is False


def test_huntercoin_normalizer_and_chain_id_filter(tmp_path):
    mod = _load("classify_huntercoin_stales")
    src = tmp_path / "raw.csv"
    dst = tmp_path / "norm.csv"
    # Two refreshed extractor rows: a SHA-256d (chain_id 6) row and a Scrypt
    # (chain_id 2) row that must be dropped.
    with src.open("w", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "btc_header_hash",
                "btc_prev_hash",
                "btc_time",
                "btc_bits",
                "huc_height",
                "classification",
                "chain_id",
            ],
        )
        w.writeheader()
        w.writerow(
            {
                "btc_header_hash": "aa" * 32,
                "btc_prev_hash": "bb" * 32,
                "btc_time": "1700000000",
                "btc_bits": "1a0d69d7",
                "huc_height": "100",
                "classification": "stale",
                "chain_id": "6",
            }
        )
        w.writerow({"btc_header_hash": "cc" * 32, "chain_id": "2"})

    total, skipped = mod._write_normalized_input(src, dst)
    assert total == 2
    assert skipped == 1  # the chain_id 2 (Scrypt/LTC) row dropped

    with dst.open(newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1
    row = rows[0]
    assert row["btc_header_hash"] == "aa" * 32
    assert row["btc_time"] == "1700000000"


def test_huntercoin_classifier_requires_refreshed_input(monkeypatch, tmp_path):
    mod = _load("classify_huntercoin_stales")
    missing = tmp_path / "huntercoin_auxpow_raw.csv"
    monkeypatch.setattr(mod, "DEFAULT_INPUT", missing)
    monkeypatch.setattr(sys, "argv", ["x"])

    with pytest.raises(
        SystemExit, match="missing refreshed Huntercoin extractor input"
    ):
        mod.main()


def test_classifier_cli_rpc_args_env_default_and_auth_fallback(monkeypatch, tmp_path):
    """``add_rpc_args``/``rpc_from_args``: the --rpc-url env default, and
    get_btc_auth's cookie/conf/env fallback cascade when --rpc-user/
    --rpc-pass are omitted. Every classify_*.py wrapper relies on this
    wiring, so it is tested once here rather than per wrapper."""
    import argparse

    from stale_blocks_analysis import classifier_cli

    monkeypatch.delenv("BTC_RPC_URL", raising=False)
    monkeypatch.delenv("BITCOIN_RPC_USER", raising=False)
    monkeypatch.delenv("BITCOIN_RPC_PASSWORD", raising=False)
    # Isolate from a real ~/.bitcoin/.cookie or bitcoin.conf on the host
    # running the tests.
    monkeypatch.setattr(
        "stale_blocks_analysis.btc_rpc._COOKIE_PATHS",
        [str(tmp_path / "no-such-cookie")],
    )
    monkeypatch.setattr(
        "stale_blocks_analysis.btc_rpc._CONF_PATHS",
        [str(tmp_path / "no-such-bitcoin.conf")],
    )

    # No BTC_RPC_URL and no discoverable credentials: the hardcoded default
    # URL, and an unauthenticated client rather than a raise -- the caller's
    # own connectivity check (run_classifier's preflight, or a script's own
    # probe) is where a missing-credentials failure should surface.
    parser = argparse.ArgumentParser()
    classifier_cli.add_rpc_args(parser)
    args = parser.parse_args([])
    assert args.rpc_url == classifier_cli.DEFAULT_RPC_URL
    rpc = classifier_cli.rpc_from_args(args)
    assert rpc.url == classifier_cli.DEFAULT_RPC_URL
    assert rpc.auth is None

    # BTC_RPC_URL env default, plus explicit --rpc-user/--rpc-pass.
    monkeypatch.setenv("BTC_RPC_URL", "http://10.1.2.5:8332")
    parser2 = argparse.ArgumentParser()
    classifier_cli.add_rpc_args(parser2)
    args2 = parser2.parse_args(["--rpc-user", "alice", "--rpc-pass", "s3cret"])
    assert args2.rpc_url == "http://10.1.2.5:8332"
    rpc2 = classifier_cli.rpc_from_args(args2)
    assert rpc2.url == "http://10.1.2.5:8332"
    assert rpc2.auth == ("alice", "s3cret")

    # BITCOIN_RPC_USER/BITCOIN_RPC_PASSWORD env fallback when --rpc-user/
    # --rpc-pass are omitted (still ahead of the isolated cookie/conf paths).
    monkeypatch.setenv("BITCOIN_RPC_USER", "envuser")
    monkeypatch.setenv("BITCOIN_RPC_PASSWORD", "envpass")
    parser3 = argparse.ArgumentParser()
    classifier_cli.add_rpc_args(parser3)
    args3 = parser3.parse_args([])
    rpc3 = classifier_cli.rpc_from_args(args3)
    assert rpc3.auth == ("envuser", "envpass")


def test_devcoin_wrapper_forwards_rpc_and_keep_near(monkeypatch):
    """A representative thin wrapper forwards --keep-near and the built
    --rpc-* client through to run_classifier, proving classifier_cli's
    helpers are wired into main() and not just present in --help."""
    mod = _load("classify_devcoin_stales")
    call = _run_main(
        monkeypatch,
        mod,
        [
            "x",
            "--input",
            "in.csv",
            "--output",
            "out.csv",
            "--keep-near",
            "--rpc-url",
            "http://10.1.2.9:8332",
            "--rpc-user",
            "bob",
            "--rpc-pass",
            "hunter2",
        ],
    )
    assert call["spec"].key == "devcoin"
    assert call["keep_near"] is True
    rpc = call.get("rpc")
    assert rpc is not None
    assert rpc.url == "http://10.1.2.9:8332"
    assert rpc.auth == ("bob", "hunter2")
