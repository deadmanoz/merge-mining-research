"""Complete, fail-closed Qbit active-chain acquisition into a private directory."""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import shutil
import time
from pathlib import Path

import requests

from .auxpow_parse import standard_auxpow_extraction_columns
from .btc_classify import _ordered_batch_responses
from .qbit import GENESIS, SOURCE_REVISION, parse_block


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


class RecordedRPC:
    """Retain exact JSON response bytes and request parameters, never credentials."""

    def __init__(self, url: str, cookie: Path, directory: Path):
        self.url = url
        self.session = requests.Session()
        self.session.auth = tuple(cookie.read_text().strip().split(":", 1))
        self.directory = directory
        directory.mkdir()
        self.inventory = []

    def batch(self, method: str, params: list[list]) -> list:
        calls = [
            {"jsonrpc": "2.0", "id": i, "method": method, "params": p}
            for i, p in enumerate(params)
        ]
        index = len(self.inventory)
        request_path = self.directory / f"{index:06d}-request.json"
        request_path.write_text(json.dumps(calls, separators=(",", ":")) + "\n")
        for attempt in range(4):
            try:
                response = self.session.post(self.url, json=calls, timeout=180)
                response_path = (
                    self.directory
                    / f"{index:06d}-attempt-{attempt + 1}-response.json.gz"
                )
                response_path.write_bytes(gzip.compress(response.content, mtime=0))
                response.raise_for_status()
                payload = response.content
                rows = json.loads(payload)
                if not isinstance(rows, list) or len(rows) != len(calls):
                    raise ValueError("incomplete Qbit RPC batch")
                rows = _ordered_batch_responses(
                    rows, expected_count=len(calls), method=method
                )
                if any(r.get("error") or r.get("result") is None for r in rows):
                    raise ValueError(
                        "Qbit RPC batch contains an error or missing result"
                    )
                break
            except (requests.RequestException, ValueError):
                with (self.directory / "retries.jsonl").open("a") as log:
                    log.write(
                        json.dumps(
                            {
                                "batch": index,
                                "method": method,
                                "attempt": attempt + 1,
                                "failed": True,
                            }
                        )
                        + "\n"
                    )
                if attempt == 3:
                    raise RuntimeError(
                        f"Qbit RPC batch {index} ({method}) exhausted retries"
                    ) from None
                time.sleep(attempt + 1)
        self.inventory.append(
            {
                "request": request_path.name,
                "request_sha256": digest(request_path),
                "response": response_path.name,
                "response_sha256": digest(response_path),
                "decoded_response_sha256": hashlib.sha256(payload).hexdigest(),
                "encoding": "gzip of exact HTTP JSON response bytes; getblock result is witness-inclusive network hex",
            }
        )
        return [r["result"] for r in rows]


class CapturedRPC:
    """Replay a sealed acquisition, authenticating its exact ordered calls.

    Retained bytes are copied into a fresh generation. Normal acquisition then
    reruns every coverage and proof gate with the current parser, without
    mutating the original archive or depending on a live historical node.
    """

    def __init__(self, source: Path, directory: Path):
        self.source_receipt_sha256 = digest(source / "acquisition.json")
        self.receipt = json.loads((source / "acquisition.json").read_text())
        if (
            self.receipt.get("status") != "COMPLETE"
            or self.receipt.get("source_revision") != SOURCE_REVISION
            or self.receipt.get("genesis") != GENESIS
        ):
            raise ValueError("replay requires a complete pinned Qbit acquisition")
        for base, field in ((source, "files"), (source / "rpc", "capture_files")):
            if not self.receipt.get(field):
                raise ValueError("missing acquisition digest inventory")
            for name, expected in self.receipt[field].items():
                path = base / name
                if not path.resolve().is_relative_to(base.resolve()):
                    raise ValueError("capture path escapes acquisition")
                if digest(path) != expected:
                    raise ValueError(f"acquisition digest mismatch: {name}")
        shutil.copytree(source / "rpc", directory)
        self.directory = directory
        self.inventory = []

    def batch(self, method: str, params: list[list]) -> list:
        entry = self.receipt["rpc_inventory"][len(self.inventory)]
        request = self.directory / entry["request"]
        response = self.directory / entry["response"]
        if (
            digest(request) != entry["request_sha256"]
            or digest(response) != entry["response_sha256"]
        ):
            raise ValueError("replay call digest mismatch")
        expected = [
            {"jsonrpc": "2.0", "id": i, "method": method, "params": p}
            for i, p in enumerate(params)
        ]
        if json.loads(request.read_text()) != expected:
            raise ValueError("replay call order or range mismatch")
        payload = gzip.decompress(response.read_bytes())
        if hashlib.sha256(payload).hexdigest() != entry["decoded_response_sha256"]:
            raise ValueError("replay decoded response digest mismatch")
        rows = _ordered_batch_responses(
            json.loads(payload), expected_count=len(params), method=method
        )
        if any(row.get("error") or row.get("result") is None for row in rows):
            raise ValueError("replay contains failed RPC result")
        self.inventory.append(entry)
        return [row["result"] for row in rows]


def acquire(
    rpc, output: Path, *, height: int, block_hash: str, batch_size: int = 100
) -> dict:
    """Seal only a complete genesis-through-endpoint scan with every edge checked.

    ``output`` must be fresh. Failed runs retain their captures and INCOMPLETE
    metadata but cannot issue a completion receipt. Retry with a fresh directory.
    """
    if height < 0 or batch_size < 1:
        raise ValueError("invalid acquisition range or batch size")
    if len(block_hash) != 64 or block_hash != block_hash.lower():
        raise ValueError("endpoint hash must be lowercase display hex")
    bytes.fromhex(block_hash)
    if any(
        (output / name).exists()
        for name in ("acquisition.json", "coverage.csv", "qbit_auxpow.csv")
    ):
        raise ValueError("acquisition requires a fresh output directory")
    output.mkdir(parents=True, exist_ok=True)
    receipt_path = output / "acquisition.json"
    implementation = {
        path.name: digest(path) for path in sorted(Path(__file__).parent.glob("*.py"))
    }
    metadata = {
        "status": "INCOMPLETE",
        "source_revision": SOURCE_REVISION,
        "genesis": GENESIS,
        "endpoint": {"height": height, "hash": block_hash},
        "scope": "native active chain, not every historical fork",
        "proof_profile": "Qbit mainnet display commitment, child nBits target; native node owns body and contextual consensus",
        "implementation": implementation,
    }
    receipt_path.write_text(json.dumps(metadata, indent=2) + "\n")
    before = rpc.batch("getblockchaininfo", [[]])[0]
    if before["chain"] != "main" or before["pruned"] or before["blocks"] < height:
        raise ValueError("Qbit node is not an unpruned mainnet archive at endpoint")
    if rpc.batch("getblockhash", [[0], [height]]) != [GENESIS, block_hash]:
        raise ValueError("Qbit pinned chain endpoints mismatch")
    coverage_fields = [
        "height",
        "hash",
        "previous_hash",
        "mining_class",
        "parent_hash",
        "parent_self_pow",
        "raw_block_sha256",
    ]
    counts = {"blocks": 0, "direct": 0, "auxpow": 0, "parent_self_pow": 0}
    earliest = None
    parent_hashes = set()
    previous = "0" * 64
    with (
        (output / "coverage.csv").open("w", newline="") as coverage,
        (output / "qbit_auxpow.csv").open("w", newline="") as evidence,
    ):
        cw = csv.DictWriter(coverage, fieldnames=coverage_fields, lineterminator="\n")
        ew = csv.DictWriter(
            evidence,
            fieldnames=standard_auxpow_extraction_columns("qbit_height"),
            lineterminator="\n",
        )
        cw.writeheader()
        ew.writeheader()
        for start in range(0, height + 1, batch_size):
            heights = list(range(start, min(height + 1, start + batch_size)))
            hashes = rpc.batch("getblockhash", [[h] for h in heights])
            blocks = rpc.batch("getblock", [[h, 0] for h in hashes])
            # Native Qbit refuses verbose views for witness-pruned blocks.
            native = rpc.batch("getblock", [[h, 1] for h in hashes])
            if (
                len(hashes) != len(heights)
                or len(blocks) != len(heights)
                or len(native) != len(heights)
            ):
                raise ValueError("missing Qbit heights")
            for h, expected, raw_hex, placed in zip(
                heights, hashes, blocks, native, strict=True
            ):
                if (
                    placed["height"] != h
                    or placed["hash"] != expected
                    or placed["confirmations"] <= 0
                ):
                    raise ValueError(f"Qbit native block placement mismatch at {h}")
                raw = bytes.fromhex(raw_hex)
                parsed = parse_block(raw, height=h, expected_hash=expected)
                if parsed["header"]["prev_hash"] != previous:
                    raise ValueError(f"Qbit predecessor edge mismatch at {h}")
                previous = expected
                merged = parsed["mining_class"] == "auxpow"
                parent_hash = parsed["parent"]["hash"] if merged else ""
                cw.writerow(
                    {
                        "height": h,
                        "hash": expected,
                        "previous_hash": parsed["header"]["prev_hash"],
                        "mining_class": parsed["mining_class"],
                        "parent_hash": parent_hash,
                        "parent_self_pow": str(parsed["parent_self_pow"]).lower()
                        if merged
                        else "",
                        "raw_block_sha256": hashlib.sha256(raw).hexdigest(),
                    }
                )
                counts["blocks"] += 1
                counts[parsed["mining_class"]] += 1
                if merged:
                    ew.writerow(parsed["row"])
                    counts["parent_self_pow"] += parsed["parent_self_pow"]
                    parent_hashes.add(parent_hash)
                    if earliest is None:
                        earliest = {"height": h, "hash": expected}
            coverage.flush()
            evidence.flush()
            print(
                f"Qbit acquired through {heights[-1]} of {height}; AuxPoW={counts['auxpow']}",
                flush=True,
            )
    if previous != block_hash or counts["blocks"] != height + 1:
        raise ValueError("Qbit scan endpoint or count mismatch")
    if rpc.batch("getblockhash", [[0], [height]]) != [GENESIS, block_hash]:
        raise ValueError("Qbit endpoint reorganised during acquisition")
    after = rpc.batch("getblockchaininfo", [[]])[0]
    if isinstance(rpc, CapturedRPC):
        if len(rpc.inventory) != len(rpc.receipt["rpc_inventory"]):
            raise ValueError("replay did not consume the complete acquisition")
        if (
            rpc.receipt["endpoint"] != metadata["endpoint"]
            or counts != rpc.receipt["counts"]
        ):
            raise ValueError("replay endpoint or native population mismatch")
        metadata["replayed_acquisition_sha256"] = rpc.source_receipt_sha256
    if implementation != {
        path.name: digest(path) for path in sorted(Path(__file__).parent.glob("*.py"))
    }:
        raise ValueError("Qbit acquisition implementation changed during scan")
    metadata.update(
        status="COMPLETE",
        counts=counts,
        unique_parent_headers=len(parent_hashes),
        earliest_auxpow=earliest,
        native_before=before,
        native_after=after,
        rpc_inventory=getattr(rpc, "inventory", []),
        files={
            name: digest(output / name) for name in ("coverage.csv", "qbit_auxpow.csv")
        },
        capture_files={
            path.name: digest(path)
            for path in sorted((output / "rpc").glob("*"))
            if path.is_file()
        },
    )
    temporary = receipt_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(metadata, indent=2) + "\n")
    temporary.replace(receipt_path)
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc-url")
    parser.add_argument("--cookie-file", type=Path)
    parser.add_argument("--from-acquisition", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--end-height", type=int, required=True)
    parser.add_argument("--end-hash", required=True)
    parser.add_argument("--batch-size", type=int, default=100)
    args = parser.parse_args()
    if bool(args.from_acquisition) == bool(args.rpc_url or args.cookie_file):
        parser.error("select --from-acquisition or both --rpc-url and --cookie-file")
    if not args.from_acquisition and not (args.rpc_url and args.cookie_file):
        parser.error("live acquisition requires URL and cookie")
    args.output_dir.mkdir(parents=True, exist_ok=False)
    rpc = (
        CapturedRPC(args.from_acquisition, args.output_dir / "rpc")
        if args.from_acquisition
        else RecordedRPC(args.rpc_url, args.cookie_file, args.output_dir / "rpc")
    )
    acquire(
        rpc,
        args.output_dir,
        height=args.end_height,
        block_hash=args.end_hash,
        batch_size=args.batch_size,
    )


if __name__ == "__main__":
    main()
