"""Unit tests for the shared batched-RPC extraction driver.

No network: ``_FakeRpc`` below implements only ``RpcClient.batch()`` and
serves a tiny synthetic chain from an in-memory dict of raw block hex. The
scenario exercises the gate hook, the parse-row hook, multi-height batching,
a batch-level RPC failure recovered by the per-height retry, and the
append/resume path, then asserts the written CSV bytes.
"""

from __future__ import annotations

import csv
import importlib.util
import struct
from pathlib import Path

from stale_blocks_analysis import extract_driver
from stale_blocks_analysis.auxpow_parse import parse_parent_header

CSV_COLUMNS = ["height", "btc_header_hash", "coinbase_scriptsig_hex"]

# Sentinel nVersion the synthetic chain's gate treats as "AuxPoW present".
GATE_VERSION = 0x00000101
NON_GATE_VERSION = 0x00000001
REPO = Path(__file__).resolve().parents[1]


def _parent_header(nonce: int) -> bytes:
    """An 80-byte synthetic Bitcoin parent header, varied only by nonce."""
    return (
        struct.pack("<i", 0x20000000)
        + b"\x11" * 32  # prev hash (internal order)
        + b"\x22" * 32  # merkle root (internal order)
        + struct.pack("<I", 1_700_000_000)
        + struct.pack("<I", 0x1D00FFFF)
        + struct.pack("<I", nonce)
    )


def _coinbase_tx_bytes(scriptsig: bytes) -> bytes:
    """A minimal one-input/one-output coinbase transaction, wire-encoded."""
    pkscript = b"\x51"  # OP_TRUE, one byte
    vin = (
        b"\x00" * 32  # prev hash: null (coinbase)
        + struct.pack("<I", 0xFFFFFFFF)  # prev index
        + bytes([len(scriptsig)])
        + scriptsig
        + struct.pack("<I", 0xFFFFFFFF)  # sequence
    )
    vout = struct.pack("<Q", 5_000_000_000) + bytes([len(pkscript)]) + pkscript
    return (
        struct.pack("<i", 1)  # tx version
        + b"\x01"
        + vin  # vin_count=1
        + b"\x01"
        + vout  # vout_count=1
        + struct.pack("<I", 0)  # locktime
    )


def _auxpow_block_hex(version: int, scriptsig: bytes, nonce: int) -> str:
    """A full synthetic child block: 80-byte header + CAuxPow tail.

    The CAuxPow tail matches ``auxpow_parse.read_auxpow``'s expected layout
    exactly: coinbase tx, hashBlock, empty merkle branch, nIndex, empty
    chain merkle branch, nChainIndex, then the 80-byte parent header.
    """
    child_header = struct.pack("<i", version) + b"\x00" * 76
    tail = (
        _coinbase_tx_bytes(scriptsig)
        + b"\x00" * 32  # hashBlock
        + b"\x00"  # empty vMerkleBranch
        + struct.pack("<i", 0)  # nIndex
        + b"\x00"  # empty vChainMerkleBranch
        + struct.pack("<i", 0)  # nChainIndex
        + _parent_header(nonce)
    )
    return (child_header + tail).hex()


def _gate(version: int, stats: dict) -> bool:
    if version != GATE_VERSION:
        stats["skipped_gate"] += 1
        return False
    return True


def _parse_row(height: int, auxpow: dict) -> dict:
    parent = parse_parent_header(auxpow["parent_header_raw"])
    scriptsig = auxpow["coinbase_tx"]["vin"][0]["scriptsig"]
    return {
        "height": height,
        "btc_header_hash": parent["hash"],
        "coinbase_scriptsig_hex": scriptsig.hex(),
    }


class _FakeRpc:
    """Fake ``child_rpc.RpcClient``: only ``batch()`` is used by the driver.

    ``blocks`` maps height -> raw block hex (``""`` simulates a missing
    block). ``fail_hash_batch_heights`` makes the *first* ``getblockhash``
    attempt raise whenever the batch spans more than one height and
    includes one of those heights, so the driver's retry-individually path
    gets exercised; a size-1 retry batch always succeeds.
    """

    def __init__(self, blocks: dict, fail_hash_batch_heights: set | None = None):
        self.blocks = blocks
        self.fail_hash_batch_heights = fail_hash_batch_heights or set()

    def batch(self, calls: list) -> list:
        method = calls[0]["method"]
        if method == "getblockhash":
            heights = [c["params"][0] for c in calls]
            if len(calls) > 1 and self.fail_hash_batch_heights & set(heights):
                raise RuntimeError("simulated getblockhash batch failure")
            return [{"id": c["id"], "result": f"h{c['params'][0]}"} for c in calls]
        if method == "getblock":
            results = []
            for c in calls:
                height = int(c["params"][0][1:])  # strip the "h" prefix
                results.append({"id": c["id"], "result": self.blocks.get(height, "")})
            return results
        raise AssertionError(f"unexpected RPC method in test: {method}")


def test_run_extraction_gate_parse_batching_retry_and_resume(tmp_path: Path) -> None:
    # Heights 100..105: a normal batch (100-102) and a batch (103-105) whose
    # first getblockhash attempt fails and is retried one height at a time.
    blocks = {
        100: _auxpow_block_hex(GATE_VERSION, b"\x01", nonce=100),
        101: _auxpow_block_hex(NON_GATE_VERSION, b"\x02", nonce=101),  # gate fails
        102: "",  # missing block
        103: "00" * 10,  # short raw (< 80 bytes)
        104: _auxpow_block_hex(GATE_VERSION, b"\x04", nonce=104),
        105: _auxpow_block_hex(GATE_VERSION, b"\x05", nonce=105),
    }
    rpc = _FakeRpc(blocks, fail_hash_batch_heights={103, 104, 105})
    out_path = tmp_path / "out.csv"
    stats = {
        "auxpow_blocks": 0,
        "skipped_empty": 0,
        "skipped_short": 0,
        "skipped_gate": 0,
        "skipped_parse_error": 0,
    }

    result = extract_driver.run_extraction(
        rpc=rpc,
        start=100,
        end=106,
        batch_size=3,
        output_path=out_path,
        csv_columns=CSV_COLUMNS,
        gate=_gate,
        parse_row=_parse_row,
        stats=stats,
        append=False,
    )

    assert result is stats
    assert stats == {
        "auxpow_blocks": 3,
        "skipped_empty": 1,
        "skipped_short": 1,
        "skipped_gate": 1,
        "skipped_parse_error": 0,
    }

    with out_path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    assert [r["height"] for r in rows] == ["100", "104", "105"]
    assert rows[0]["coinbase_scriptsig_hex"] == "01"
    assert rows[1]["coinbase_scriptsig_hex"] == "04"
    assert rows[2]["coinbase_scriptsig_hex"] == "05"
    # The written hash must match what parse_parent_header derives directly
    # from the same synthetic parent header bytes (adversarial cross-check,
    # not a re-assertion of the row-building code under test).
    expected_hash_100 = parse_parent_header(_parent_header(100))["hash"]
    assert rows[0]["btc_header_hash"] == expected_hash_100

    # --- resume / append -----------------------------------------------
    assert extract_driver.resume_start(out_path, "height", default_start=0) == 106

    blocks[106] = _auxpow_block_hex(GATE_VERSION, b"\x06", nonce=106)
    stats2 = {
        "auxpow_blocks": 0,
        "skipped_empty": 0,
        "skipped_short": 0,
        "skipped_gate": 0,
        "skipped_parse_error": 0,
    }
    extract_driver.run_extraction(
        rpc=rpc,
        start=106,
        end=107,
        batch_size=3,
        output_path=out_path,
        csv_columns=CSV_COLUMNS,
        gate=_gate,
        parse_row=_parse_row,
        stats=stats2,
        append=True,
    )

    text = out_path.read_text()
    assert text.count("height,btc_header_hash,coinbase_scriptsig_hex") == 1
    with out_path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    assert [r["height"] for r in rows] == ["100", "104", "105", "106"]


def test_get_chain_tip_uses_a_single_call_batch() -> None:
    calls_seen = []

    class _TipRpc:
        def batch(self, calls):
            calls_seen.extend(calls)
            return [{"id": 0, "result": 4242}]

    assert extract_driver.get_chain_tip(_TipRpc()) == 4242
    assert calls_seen == [
        {"jsonrpc": "1.0", "id": 0, "method": "getblockcount", "params": []}
    ]


def test_resume_start_defaults_when_file_missing_or_header_only(tmp_path: Path) -> None:
    missing = tmp_path / "missing.csv"
    assert extract_driver.resume_start(missing, "height", default_start=7) == 7

    header_only = tmp_path / "header_only.csv"
    header_only.write_text("height,btc_header_hash\n")
    assert extract_driver.resume_start(header_only, "height", default_start=7) == 7


def test_fractal_gate_requires_auxpow_flag_and_chain_id() -> None:
    path = REPO / "scripts" / "extract" / "extract_fractal_auxpow.py"
    spec = importlib.util.spec_from_file_location("_extract_fractal_auxpow", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    stats = {"skipped_no_auxpow_flag": 0}

    assert module._gate(0x20240100, stats)
    assert module._gate(0x20240101, stats)
    assert not module._gate(0x20240000, stats)
    assert not module._gate(0x20260100, stats)
    assert not module._gate(0x00000100, stats)
    assert stats["skipped_no_auxpow_flag"] == 3


def test_elastos_tip_uses_current_height_not_block_count() -> None:
    path = REPO / "scripts" / "extract" / "extract_elastos_auxpow.py"
    spec = importlib.util.spec_from_file_location("_extract_elastos_auxpow", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls_seen = []

    class _TipRpc:
        def call(self, method, params):
            calls_seen.append((method, params))
            return 4242

    assert module.get_chain_tip(_TipRpc()) == 4242
    assert calls_seen == [("getcurrentheight", [])]
