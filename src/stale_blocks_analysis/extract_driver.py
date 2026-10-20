"""Batched-RPC driver for Bitcoin-family AuxPoW extractors.

``run_extraction`` owns the height loop; ``run_standard_extractor_cli`` owns
the thin CLI. The version gate and child-RPC construction stay in the wrapper.
Extractors whose loop is not this shape are left alone. Stdlib plus
intra-package helpers only; the caller supplies the ``RpcClient``.
"""

from __future__ import annotations

import argparse
import csv
import os
import struct
import time
from pathlib import Path
from typing import Callable, Sequence

from .auxpow_parse import (
    ChildHeaderValidationError,
    parse_child_header,
    parse_coinbase_height,
    parse_parent_header,
    read_auxpow,
    standard_auxpow_extraction_columns,
)
from .bitcoin_binary import format_outputs_canonical
from .config import PROJECT_ROOT, ChainSpec

# gate(version, stats) -> True to keep parsing the block, False to skip it.
# A gate that returns False is responsible for tallying its own skip reason
# into ``stats`` (e.g. ``stats["skipped_non_sha256d"] += 1``) so the final
# per-key summary stays chain-specific without the driver knowing the
# per-chain vocabulary.
BlockGate = Callable[[int, dict], bool]

# parse_row(height, auxpow, child_fields) -> the CSV row dict for a block that passed the
# gate and parsed as a CAuxPow. ``auxpow`` is the dict returned by
# ``auxpow_parse.read_auxpow`` (carries ``coinbase_tx`` and
# ``parent_header_raw``). For a row that passes the gate and AuxPoW parse,
# ``child_fields`` is authenticated against the independently fetched child
# block hash before the callback runs.
RowParser = Callable[[int, dict, dict], dict]


def _default_block_fetch_params(block_hash: str) -> list:
    """Default second-batch RPC params: ``getblock <hash> false`` (raw hex)."""
    return [block_hash, False]


def get_chain_tip(rpc) -> int:
    """Tip height from one ``getblockcount`` batch."""
    return rpc.batch(
        [{"jsonrpc": "1.0", "id": 0, "method": "getblockcount", "params": []}]
    )[0]["result"]


def resume_start(output_path: Path, height_column: str, default_start: int) -> int:
    """One past the last recorded height. A missing file, empty file, or header row returns ``default_start``."""
    if not output_path.exists():
        return default_start
    last = None
    with open(output_path) as f:
        for line in f:
            last = line
    if last and not last.startswith(height_column):
        return int(last.split(",", 1)[0]) + 1
    return default_start


def validate_append_schema(output_path: Path, csv_columns: list[str]) -> None:
    """Require an existing extraction CSV to use ``csv_columns`` exactly."""
    if not output_path.is_file():
        raise ValueError(f"cannot resume missing extraction CSV: {output_path}")
    with output_path.open(newline="") as existing:
        existing_header = next(csv.reader(existing), None)
    if existing_header != csv_columns:
        raise ValueError(
            f"cannot resume {output_path}: existing CSV header does not match "
            "the current extraction schema; rerun without --resume"
        )


def run_extraction(
    *,
    rpc,
    start: int,
    end: int,
    batch_size: int,
    output_path: Path,
    csv_columns: list,
    gate: BlockGate,
    parse_row: RowParser,
    stats: dict,
    append: bool,
    block_fetch_method: str = "getblock",
    block_fetch_params: Callable[[str], list] = _default_block_fetch_params,
    progress_extra: tuple | None = None,
    progress_interval: int = 10_000,
) -> dict:
    """Batch ``getblockhash``, then the block fetch. Empty and short results are skipped.

    ``gate`` returning False skips the block after it tallies its own reason.
    A malformed AuxPoW is ``skipped_parse_error``. Only a passing gate reaches
    child-header authentication. A failed batch is retried one height at a
    time. Append mode requires the existing header to match ``csv_columns``.
    A missing key in ``stats`` is recorded as ``skipped_parse_error`` and the
    row is dropped.
    """
    mode = "a" if append else "w"
    if append:
        validate_append_schema(output_path, csv_columns)

    def extract_range(bs: int, be: int) -> None:
        hash_calls = [
            {"jsonrpc": "1.0", "id": i, "method": "getblockhash", "params": [h]}
            for i, h in enumerate(range(bs, be))
        ]
        hash_results = sorted(rpc.batch(hash_calls), key=lambda x: x["id"])
        hashes = [r["result"] for r in hash_results]

        block_calls = [
            {
                "jsonrpc": "1.0",
                "id": i,
                "method": block_fetch_method,
                "params": block_fetch_params(h),
            }
            for i, h in enumerate(hashes)
        ]
        block_results = sorted(rpc.batch(block_calls), key=lambda x: x["id"])
        hex_blocks = [r["result"] for r in block_results]

        for i, hx in enumerate(hex_blocks):
            height = bs + i
            if not hx:
                stats["skipped_empty"] += 1
                continue
            raw = bytes.fromhex(hx)
            if len(raw) < 80:
                stats["skipped_short"] += 1
                continue
            version = struct.unpack_from("<i", raw, 0)[0]
            if not gate(version, stats):
                continue
            try:
                auxpow, _ = read_auxpow(raw, 80)
            except (IndexError, struct.error, ValueError):
                stats["skipped_parse_error"] += 1
                continue

            child_fields = parse_child_header(raw[:80], expected_hash_display=hashes[i])
            row = parse_row(height, auxpow, child_fields)
            stats["auxpow_blocks"] += 1
            writer.writerow(row)

    total = end - start
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, mode, newline="") as f:
        writer = csv.DictWriter(f, fieldnames=csv_columns)
        if mode == "w":
            writer.writeheader()
        t0 = time.time()
        processed = 0
        for bs in range(start, end, batch_size):
            be = min(bs + batch_size, end)
            try:
                extract_range(bs, be)
            except ChildHeaderValidationError:
                raise
            except Exception as e:
                print(f"\n  ! batch {bs}-{be} failed: {e}; retrying individually")
                for h in range(bs, be):
                    try:
                        extract_range(h, h + 1)
                    except ChildHeaderValidationError:
                        raise
                    except Exception as e2:
                        print(f"    skip h={h}: {e2}")
                        stats["skipped_parse_error"] += 1
            processed += be - bs
            if processed % progress_interval < batch_size:
                elapsed = time.time() - t0
                rate = processed / elapsed if elapsed else 0
                eta = (total - processed) / rate if rate else 0
                pct = processed / total * 100
                extra = ""
                if progress_extra is not None:
                    label, key = progress_extra
                    extra = f"{label}={stats[key]:,} | "
                print(
                    f"  {processed:>10,}/{total:,} ({pct:5.1f}%) | "
                    f"{rate:,.0f} blk/s | auxpow={stats['auxpow_blocks']:,} | "
                    f"{extra}eta={eta / 60:.0f}m",
                    flush=True,
                )
                f.flush()

    elapsed = time.time() - t0
    print(f"\nDone in {elapsed / 60:.1f}m")
    for k, v in stats.items():
        print(f"  {k}: {v:,}")
    print(f"  output: {output_path}")
    return stats


def standard_auxpow_parse_row(
    height_column: str, height: int, auxpow: dict, child_fields: dict
) -> dict:
    """Build one standard raw-hex AuxPoW CSV row keyed by ``height_column``."""
    parent = parse_parent_header(auxpow["parent_header_raw"])
    tx = auxpow["coinbase_tx"]
    scriptsig = tx["vin"][0]["scriptsig"] if tx["vin"] else b""
    btc_height = parse_coinbase_height(scriptsig)
    return {
        height_column: height,
        **child_fields,
        "btc_header_hash": parent["hash"],
        "btc_prev_hash": parent["prev_hash"],
        "btc_time": parent["time"],
        "btc_bits": parent["bits_hex"],
        "btc_height": btc_height if btc_height is not None else "",
        "coinbase_scriptsig_hex": scriptsig.hex(),
        "coinbase_outputs": format_outputs_canonical(tx["vout"]),
        "btc_header_hex": parent["header_hex"],
    }


def _rpc_client(rpc):
    """A factory runs after argparse, so ``--help`` does not construct RPC. A client is recognised by ``batch``."""
    if callable(rpc) and not hasattr(rpc, "batch"):
        return rpc()
    return rpc


def run_standard_extractor_cli(
    argv: list[str] | None,
    spec: ChainSpec,
    *,
    rpc,
    gate: BlockGate,
    stats_keys: Sequence[str],
    block_fetch_method: str = "getblock",
    block_fetch_params: Callable[[str], list] = _default_block_fetch_params,
    progress_extra: tuple | None = None,
    progress_interval: int = 10_000,
    batch_size: int = 100,
    description: str | None = None,
    scan_prefix: str = "Extracting AuxPoW",
) -> None:
    """Thin raw-hex CLI. Does not build an ``RpcClient`` or read child-chain env.

    ``stats_keys`` is the insertion-order tuple the wrapper prints. A missing
    key becomes ``skipped_parse_error`` inside ``run_extraction`` and the row
    is dropped.
    """
    if spec.activation_height is None:
        raise ValueError(
            f"{spec.key} has no activation_height; run_standard_extractor_cli "
            "requires a numeric --start default"
        )

    parser = argparse.ArgumentParser(
        description=description or f"Extract BTC AuxPoW from {spec.display_name}"
    )
    parser.add_argument("--start", type=int, default=spec.activation_height)
    parser.add_argument("--end", type=int, default=None, help="Exclusive")
    parser.add_argument(
        "--output", default=os.path.relpath(spec.input_csv, PROJECT_ROOT)
    )
    parser.add_argument("--batch-size", type=int, default=batch_size)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args(argv)
    rpc = _rpc_client(rpc)

    if args.end is None:
        args.end = get_chain_tip(rpc) + 1
        print(f"Chain tip: {args.end - 1}")

    start = args.start
    out_path = Path(args.output)
    if args.resume and out_path.exists():
        resumed = resume_start(out_path, spec.height_column, args.start)
        if resumed > args.start:
            start = resumed
            print(f"Resuming from height {start}")

    total = args.end - start
    print(f"{scan_prefix}: {start:,} → {args.end - 1:,} ({total:,} blocks)")

    stats = {key: 0 for key in stats_keys}
    append = args.resume and out_path.exists() and start > args.start

    def parse_row(height: int, auxpow: dict, child_fields: dict) -> dict:
        return standard_auxpow_parse_row(
            spec.height_column, height, auxpow, child_fields
        )

    run_extraction(
        rpc=rpc,
        start=start,
        end=args.end,
        batch_size=args.batch_size,
        output_path=out_path,
        csv_columns=standard_auxpow_extraction_columns(spec.height_column),
        gate=gate,
        parse_row=parse_row,
        stats=stats,
        append=append,
        block_fetch_method=block_fetch_method,
        block_fetch_params=block_fetch_params,
        progress_extra=progress_extra,
        progress_interval=progress_interval,
    )
