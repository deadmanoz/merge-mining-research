"""Build the compact Bitcoin epoch reference used by stale relevance gates.

The source is a public Esplora-compatible API. Only retarget-boundary blocks
and one confirmed horizon block are retained, which is sufficient for strict
height-based and weak timestamp-based nBits matching.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


RETARGET_INTERVAL = 2016
NBITS_FILENAME = "btc_nbits_by_epoch.json"
HEADERS_FILENAME = "btc_epoch_headers.json"
MANIFEST_FILENAME = "manifest.json"
DEFAULT_API_BASE = "https://mempool.space/api"


def load_nbits_by_epoch(directory: Path) -> dict[int, int]:
    """Load the committed epoch table as ``{epoch_start_height: nbits_int}``.

    The consensus gates need integer bits keyed by height; the committed file
    stores hex keyed by a string height.
    """
    with open(Path(directory) / NBITS_FILENAME) as f:
        table = json.load(f)
    return {int(height): int(bits, 16) for height, bits in table.items()}


class ReferenceError(RuntimeError):
    """Raised when public source data cannot form a valid reference."""


class BlockSource(Protocol):
    """Minimal canonical-chain source needed by ``refresh_reference``."""

    api_base: str

    def tip_height(self) -> int: ...

    def hash_at_height(self, height: int) -> str: ...

    def block_at_height(self, height: int) -> dict[str, Any]: ...


def normalize_bits(value: object) -> str:
    """Return compact target bits as exactly eight lowercase hex digits."""
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        raw = value.strip().lower()
        if raw.startswith("0x"):
            number = int(raw, 16)
        elif len(raw) == 8 and any(ch in "abcdef" for ch in raw):
            number = int(raw, 16)
        else:
            number = int(raw, 10)
    else:
        raise ReferenceError(f"unsupported bits value: {value!r}")
    if not 0 <= number <= 0xFFFFFFFF:
        raise ReferenceError(f"bits value outside uint32: {number}")
    return f"{number:08x}"


def normalize_block(payload: object, expected_height: int) -> dict[str, object]:
    """Validate and normalize one Esplora block response."""
    if not isinstance(payload, dict):
        raise ReferenceError(f"block {expected_height} response is not an object")
    try:
        height = int(payload["height"])
        block_hash = str(payload["id"]).lower()
        timestamp = int(payload["timestamp"])
        mediantime = int(payload.get("mediantime", timestamp))
        bits = normalize_bits(payload["bits"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ReferenceError(f"malformed block {expected_height} response") from exc
    if height != expected_height:
        raise ReferenceError(
            f"height mismatch: requested {expected_height}, received {height}"
        )
    if len(block_hash) != 64 or any(ch not in "0123456789abcdef" for ch in block_hash):
        raise ReferenceError(f"invalid hash for block {height}: {block_hash!r}")
    return {
        "height": height,
        "hash": block_hash,
        "time": timestamp,
        "mediantime": mediantime,
        "bits": bits,
    }


@dataclass(slots=True)
class EsploraClient:
    """Small retrying client for the public Esplora block endpoints."""

    api_base: str = DEFAULT_API_BASE
    timeout: float = 30.0
    retries: int = 4
    retry_delay: float = 1.0

    def _request(self, path: str) -> bytes:
        url = f"{self.api_base.rstrip('/')}/{path.lstrip('/')}"
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "merge-mining-research/bitcoin-epoch-reference"},
        )
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    return response.read()
            except (OSError, urllib.error.HTTPError, urllib.error.URLError) as exc:
                last_error = exc
                if attempt == self.retries:
                    break
                time.sleep(self.retry_delay * (2**attempt))
        raise ReferenceError(f"public API request failed: {url}: {last_error}")

    def _text(self, path: str) -> str:
        return self._request(path).decode("utf-8").strip()

    def tip_height(self) -> int:
        try:
            return int(self._text("blocks/tip/height"))
        except ValueError as exc:
            raise ReferenceError("public API returned an invalid tip height") from exc

    def hash_at_height(self, height: int) -> str:
        block_hash = self._text(f"block-height/{height}").lower()
        if len(block_hash) != 64 or any(
            ch not in "0123456789abcdef" for ch in block_hash
        ):
            raise ReferenceError(f"public API returned an invalid hash at {height}")
        return block_hash

    def block_at_height(self, height: int) -> dict[str, Any]:
        try:
            payload = json.loads(self._request(f"blocks/{height}"))
        except json.JSONDecodeError as exc:
            raise ReferenceError(
                f"public API returned invalid JSON for {height}"
            ) from exc
        if not isinstance(payload, list):
            raise ReferenceError(f"public API returned invalid block list for {height}")
        for row in payload:
            if isinstance(row, dict) and int(row.get("height", -1)) == height:
                return normalize_block(row, height)
        raise ReferenceError(f"public API block list omitted requested height {height}")


def _load_existing_headers(output_dir: Path) -> dict[int, dict[str, object]]:
    path = output_dir / HEADERS_FILENAME
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ReferenceError(f"cannot read existing reference: {path}") from exc
    if not isinstance(raw, list):
        raise ReferenceError(f"existing reference is not a list: {path}")
    epochs: dict[int, dict[str, object]] = {}
    for item in raw:
        if not isinstance(item, dict):
            raise ReferenceError(f"malformed row in existing reference: {path}")
        height = int(item.get("height", -1))
        if height % RETARGET_INTERVAL != 0:
            continue
        block = normalize_block(
            {
                "height": height,
                "id": item.get("hash"),
                "timestamp": item.get("time"),
                "mediantime": item.get("mediantime", item.get("time")),
                "bits": f"0x{item.get('bits')}",
            },
            height,
        )
        epochs[height] = block
    return epochs


def _atomic_write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n")
    os.replace(temporary, path)


def refresh_reference(
    source: BlockSource,
    output_dir: Path,
    *,
    confirmations: int = 6,
    workers: int = 1,
) -> dict[str, object]:
    """Incrementally refresh and atomically write the committed reference."""
    if confirmations < 0:
        raise ReferenceError("confirmations must be non-negative")
    if workers < 1:
        raise ReferenceError("workers must be at least one")
    tip_height = source.tip_height()
    finalized_height = tip_height - confirmations
    if finalized_height < 0:
        raise ReferenceError("tip is below the requested confirmation depth")
    final_epoch_height = (finalized_height // RETARGET_INTERVAL) * RETARGET_INTERVAL

    epochs = _load_existing_headers(output_dir)
    epochs = {
        height: row for height, row in epochs.items() if height <= final_epoch_height
    }
    if epochs:
        last_height = max(epochs)
        canonical_hash = source.hash_at_height(last_height)
        if epochs[last_height]["hash"] != canonical_hash:
            raise ReferenceError(
                f"existing epoch hash at {last_height} is not canonical; "
                "refusing incremental refresh"
            )

    missing_heights = [
        height
        for height in range(0, final_epoch_height + 1, RETARGET_INTERVAL)
        if height not in epochs
    ]
    if workers == 1:
        fetched = map(source.block_at_height, missing_heights)
        for height, block in zip(missing_heights, fetched, strict=True):
            epochs[height] = block
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            fetched = executor.map(source.block_at_height, missing_heights)
            for height, block in zip(missing_heights, fetched, strict=True):
                epochs[height] = block

    horizon = source.block_at_height(finalized_height)
    ordered_epochs = [epochs[height] for height in sorted(epochs)]
    headers = list(ordered_epochs)
    if finalized_height != final_epoch_height:
        headers.append(horizon)
    nbits = {str(row["height"]): row["bits"] for row in ordered_epochs}
    manifest = {
        "schema_version": 1,
        "source": {
            "kind": "esplora",
            "api_base": source.api_base,
            "service_documentation": "https://mempool.space/docs/api/rest",
            "api_specification": "https://github.com/Blockstream/esplora/blob/master/API.md",
        },
        "retarget_interval": RETARGET_INTERVAL,
        "confirmation_depth": confirmations,
        "observed_tip_height": tip_height,
        "finalized_horizon": horizon,
        "epoch_rows": len(ordered_epochs),
    }

    _atomic_write_json(output_dir / NBITS_FILENAME, nbits)
    _atomic_write_json(output_dir / HEADERS_FILENAME, headers)
    _atomic_write_json(output_dir / MANIFEST_FILENAME, manifest)
    return manifest
