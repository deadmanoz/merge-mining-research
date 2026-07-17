"""Shared extraction driver for the batched-RPC Bitcoin-family AuxPoW extractors.

Roughly a dozen ``scripts/extract/extract_*_auxpow.py`` scripts talk to a
child-chain node via ``child_rpc.RpcClient`` and share the same outer shape:
resolve the height range, batch ``getblockhash`` then a block/header fetch,
apply a per-chain AuxPoW gate, parse the embedded Bitcoin parent header plus
coinbase, and append rows to a CSV. Only the gate and the block-to-row parse
genuinely differ per chain; this module owns the rest.

This driver is adopted only where a script's existing loop is byte-identical
to it modulo chain name, RPC block-fetch method/params, and one optional
progress-line field. Extractors with real quirks (custom resume semantics,
concurrent dispatch, decoded-JSON-instead-of-raw-hex block bodies, missing
retry-on-batch-failure, etc.) are intentionally left untouched; see
``docs/`` / the introducing commit for the per-extractor equivalence
argument.

DEPLOYMENT CONSTRAINT: like ``auxpow_parse``, this module is imported by
extract scripts that run on package-less / NixOS hosts. It MUST remain
importable with the Python standard library plus intra-package pure helpers
only (the caller supplies the already-constructed ``RpcClient``).
"""

from __future__ import annotations

import csv
import struct
import time
from pathlib import Path
from typing import Callable

from .auxpow_parse import read_auxpow

# gate(version, stats) -> True to keep parsing the block, False to skip it.
# A gate that returns False is responsible for tallying its own skip reason
# into ``stats`` (e.g. ``stats["skipped_non_sha256d"] += 1``) so the final
# per-key summary stays chain-specific without the driver knowing the
# per-chain vocabulary.
BlockGate = Callable[[int, dict], bool]

# parse_row(height, auxpow) -> the CSV row dict for a block that passed the
# gate and parsed as a CAuxPow. ``auxpow`` is the dict returned by
# ``auxpow_parse.read_auxpow`` (carries ``coinbase_tx`` and
# ``parent_header_raw``).
RowParser = Callable[[int, dict], dict]


def _default_block_fetch_params(block_hash: str) -> list:
    """Default second-batch RPC params: ``getblock <hash> false`` (raw hex)."""
    return [block_hash, False]


def get_chain_tip(rpc) -> int:
    """Return the chain tip height via a single-call ``getblockcount`` batch.

    Mirrors the one-line ``rpc().batch([{...getblockcount...}])[0]["result"]``
    every adopting extractor's own ``get_chain_tip()`` used to duplicate.
    """
    return rpc.batch(
        [{"jsonrpc": "1.0", "id": 0, "method": "getblockcount", "params": []}]
    )[0]["result"]


def resume_start(output_path: Path, height_column: str, default_start: int) -> int:
    """Return one past the highest height already recorded in ``output_path``.

    Reads the last line of an existing CSV and parses the integer before its
    first comma; a missing file, an empty file, or a last line that is the
    header row (starts with ``height_column``) falls back to
    ``default_start``. Matches the byte-for-byte resume logic every adopting
    extractor used to inline in ``main()``.
    """
    if not output_path.exists():
        return default_start
    last = None
    with open(output_path) as f:
        for line in f:
            last = line
    if last and not last.startswith(height_column):
        return int(last.split(",", 1)[0]) + 1
    return default_start


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
    """Run the common batched-RPC AuxPoW extraction loop and write CSV rows.

    For each ``batch_size``-height window in ``[start, end)``: batch
    ``getblockhash`` then a block/header fetch (``block_fetch_method`` with
    params from ``block_fetch_params(hash)``, default ``getblock <hash>
    false``), then for each returned raw-hex block: skip empty results
    (``stats["skipped_empty"]``) and short results under 80 bytes
    (``stats["skipped_short"]``), decode the little-endian ``nVersion`` and
    call ``gate(version, stats)`` (a False return skips the block, having
    already tallied its own reason), deserialise the CAuxPow tail
    (``stats["skipped_parse_error"]`` on a malformed payload), and hand the
    parsed ``auxpow`` dict to ``parse_row(height, auxpow)`` for the CSV row,
    tallying ``stats["auxpow_blocks"]``.

    A batch that raises is retried one height at a time before giving up on
    it (unparseable individual heights fall into
    ``stats["skipped_parse_error"]``). Opens ``output_path`` in append mode
    when ``append`` is True (the caller has already decided this from its
    own ``--resume``/existing-file logic) and write mode otherwise, writing
    the CSV header only in write mode. Prints periodic progress/ETA every
    ``progress_interval`` processed heights (flushing the output file each
    time) and a final ``Done in Xm`` summary iterating ``stats`` in
    insertion order, plus the output path. ``progress_extra`` is an optional
    ``(label, stats_key)`` pair rendered as ``label=value`` in the progress
    line, for the one or two chains whose interim progress historically
    surfaced a second skip counter alongside ``auxpow_blocks``.

    Returns ``stats`` (mutated in place; returned for convenience).
    """
    mode = "a" if append else "w"

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

            row = parse_row(height, auxpow)
            stats["auxpow_blocks"] += 1
            writer.writerow(row)

    total = end - start
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
            except Exception as e:
                print(f"\n  ! batch {bs}-{be} failed: {e}; retrying individually")
                for h in range(bs, be):
                    try:
                        extract_range(h, h + 1)
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
