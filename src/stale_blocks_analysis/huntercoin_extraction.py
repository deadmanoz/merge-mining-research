"""Authenticated Huntercoin native-dump extraction.

Native heights count stored predecessor links to the known genesis, rather
than asserting active-chain membership or full child-chain consensus validity.
"""

from __future__ import annotations

import csv
import os
import struct
import tempfile
from contextlib import contextmanager, nullcontext
from concurrent.futures import ProcessPoolExecutor
from itertools import repeat
from pathlib import Path

from .auxpow_chainid import (
    hash_from_header_bytes,
    hash_to_display_hex,
)
from .auxpow_parse import (
    CHILD_HEADER_FIELDS,
    VERSION_AUXPOW,
    ChildHeaderValidationError,
    hash_meets_btc_difficulty,
    parse_child_header,
    parse_parent_header,
    read_auxpow,
)
from .bitcoin_binary import format_outputs_canonical
from .auxpow_commitment import transaction_is_coinbase, validate_auxpow_commitment
from .config import (
    CHAIN_SPECS,
    HUNTERCOIN_GENESIS_HASH,
    HUNTERCOIN_NETWORK_MAGIC,
    HUNTERCOIN_SCRYPT_CHAIN_ID,
)
from .native_headers import (
    NativeHeaderIndex,
    decode_block_file,
    framed_blocks,
    native_block_files,
)

HUC_CHAIN_ID_SHA256 = CHAIN_SPECS["huntercoin"].chain_id
HUC_CHAIN_ID_SCRYPT = HUNTERCOIN_SCRYPT_CHAIN_ID

CSV_COLUMNS = [
    "huc_height",
    *CHILD_HEADER_FIELDS,
    "huc_block_hash",
    "chain_id",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_merkle_root",
    "btc_time",
    "btc_bits",
    "btc_nonce",
    "btc_version",
    "pow_valid",
    "coinbase_scriptsig_hex",
    "coinbase_outputs",
    "btc_header_hex",
    "full_coinbase_hex",
    "parent_transaction_hex",
    "parent_tx_is_coinbase",
    "auxpow_hex",
]


def _fsync_directory(path: Path) -> None:
    """Persist a completed same-directory rename."""
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


@contextmanager
def _atomic_csv_output(destination: Path):
    """Yield a staged CSV handle and publish it only after a clean close."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, staged_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    staged = Path(staged_name)
    try:
        with os.fdopen(fd, "w", newline="") as handle:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staged, destination)
        _fsync_directory(destination.parent)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        staged.unlink(missing_ok=True)
        raise


def _scan_native_file(
    path: Path, xor_key: bytes
) -> tuple[list[bytes], list[dict], dict]:
    """Return one bounded file chunk for deterministic parent-side assembly."""
    headers, rows = [], []
    stats = dict.fromkeys(
        [
            "blocks_scanned",
            "sha256_auxpow",
            "scrypt_auxpow",
            "non_auxpow",
            "non_coinbase_parent_proofs",
        ],
        0,
    )
    data = decode_block_file(path, xor_key)
    for offset, block in framed_blocks(data, HUNTERCOIN_NETWORK_MAGIC):
        stats["blocks_scanned"] += 1
        headers.append(block[:80])
        version = struct.unpack_from("<i", block)[0]
        chain_id = (version >> 16) & 0xFFFF
        if not version & VERSION_AUXPOW:
            stats["non_auxpow"] += 1
            continue
        if chain_id == HUC_CHAIN_ID_SCRYPT:
            stats["scrypt_auxpow"] += 1
            continue
        if chain_id != HUC_CHAIN_ID_SHA256:
            raise ChildHeaderValidationError(
                f"{path.name}:{offset}: unknown Huntercoin AuxPoW chain ID {chain_id}"
            )
        child_fields = parse_child_header(block[:80])
        try:
            auxpow, proof_end = read_auxpow(block, 80)
            parent = parse_parent_header(auxpow["parent_header_raw"])
        except (IndexError, struct.error, ValueError) as exc:
            raise ChildHeaderValidationError(
                f"{path.name}:{offset}: malformed Huntercoin AuxPoW"
            ) from exc
        # The native proof must meet the child's target; Bitcoin classification
        # applies the separate parent self-target and context checks later.
        if not hash_meets_btc_difficulty(
            hash_from_header_bytes(auxpow["parent_header_raw"]),
            int(child_fields["child_nbits"], 16),
        ):
            raise ChildHeaderValidationError(
                f"{path.name}:{offset}: malformed or low-work Huntercoin AuxPoW"
            )
        try:
            validate_auxpow_commitment(block[:80], auxpow, HUC_CHAIN_ID_SHA256)
        except ChildHeaderValidationError as exc:
            raise ChildHeaderValidationError(f"{path.name}:{offset}: {exc}") from exc
        tx = auxpow["coinbase_tx"]
        is_coinbase = transaction_is_coinbase(tx)
        if not is_coinbase:
            stats["non_coinbase_parent_proofs"] += 1
        rows.append(
            {
                "huc_height": "",
                **child_fields,
                "huc_block_hash": hash_to_display_hex(
                    bytes.fromhex(child_fields["child_block_hash"])
                ),
                "chain_id": chain_id,
                "btc_header_hash": parent["hash"],
                "btc_prev_hash": parent["prev_hash"],
                "btc_merkle_root": parent["merkle_root"],
                "btc_time": parent["time"],
                "btc_bits": parent["bits_hex"],
                "btc_nonce": parent["nonce"],
                "btc_version": parent["version"],
                "pow_valid": "1",
                "coinbase_scriptsig_hex": tx["vin"][0]["scriptsig"].hex()
                if is_coinbase
                else "",
                "coinbase_outputs": format_outputs_canonical(tx["vout"])
                if is_coinbase
                else "",
                "btc_header_hex": parent["header_hex"],
                "full_coinbase_hex": tx["raw"].hex() if is_coinbase else "",
                "parent_transaction_hex": "" if is_coinbase else tx["raw"].hex(),
                "parent_tx_is_coinbase": "1" if is_coinbase else "0",
                "auxpow_hex": block[80:proof_end].hex(),
                "source_file": path.name,
                "source_offset": offset,
            }
        )
        stats["sha256_auxpow"] += 1
    return headers, rows, stats


def extract_native_blocks(
    blocks_dir: Path,
    output: Path,
    *,
    workers: int = 1,
) -> dict:
    """Scan every stored header and atomically emit genesis-linked BTC proofs."""
    if workers < 1:
        raise ValueError("native workers must be positive")
    files = native_block_files(blocks_dir)
    fingerprints = {p: (p.stat().st_size, p.stat().st_mtime_ns) for p in files}
    xor_path = blocks_dir / "xor.dat"
    xor_key = xor_path.read_bytes() if xor_path.is_file() else b""
    index = NativeHeaderIndex(HUNTERCOIN_GENESIS_HASH)
    columns = CSV_COLUMNS + ["source_file", "source_offset"]
    stats = {
        "blocks_scanned": 0,
        "sha256_auxpow": 0,
        "scrypt_auxpow": 0,
        "non_auxpow": 0,
        "non_coinbase_parent_proofs": 0,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryFile(mode="w+", newline="", dir=output.parent) as spool:
        writer = csv.DictWriter(spool, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        executor_context = (
            ProcessPoolExecutor(max_workers=workers)
            if workers > 1
            else nullcontext(None)
        )
        with executor_context as executor:
            # Bound outstanding chunks to one batch, including pickled row data.
            for batch_start in range(0, len(files), workers):
                batch = files[batch_start : batch_start + workers]
                chunks = (
                    executor.map(_scan_native_file, batch, repeat(xor_key))
                    if executor
                    else map(_scan_native_file, batch, repeat(xor_key))
                )
                for path, (headers, rows, chunk_stats) in zip(
                    batch, chunks, strict=True
                ):
                    for header in headers:
                        index.add(header)
                    writer.writerows(rows)
                    for key, value in chunk_stats.items():
                        stats[key] += value
                    print(f"Native Huntercoin {path.name}: {stats}", flush=True)
        heights = index.resolve()
        if native_block_files(blocks_dir) != files or any(
            (p.stat().st_size, p.stat().st_mtime_ns) != fingerprints[p] for p in files
        ):
            raise ChildHeaderValidationError(
                "native block-file inventory changed during extraction"
            )
        if (xor_path.read_bytes() if xor_path.is_file() else b"") != xor_key:
            raise ChildHeaderValidationError(
                "native block-file XOR key changed during extraction"
            )
        spool.seek(0)
        with _atomic_csv_output(output) as handle:
            final = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
            final.writeheader()
            for row in csv.DictReader(spool):
                row["huc_height"] = heights[bytes.fromhex(row["child_block_hash"])]
                final.writerow(row)
    stats.update(
        unique_child_headers=len(heights),
        maximum_stored_height=max(heights.values()),
        genesis_hash=HUNTERCOIN_GENESIS_HASH,
        height_basis="genesis_linked_headers",
        native_active_chain_verified=False,
    )
    return stats
