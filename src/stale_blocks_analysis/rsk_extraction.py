"""Durable acquisition contract for the private RSK merge-mining corpus.

The RSK extractor writes two append-only CSVs as one checkpointed unit: the
raw 80-byte parent-header rows and an exact ledger of the 69/70-byte fallback
proofs plus the exact height-zero genesis sentinel that were intentionally
skipped. A checkpoint integrity-protects every committed byte interval, the
canonical-chain continuity at that boundary, and the pinned source-chain
endpoints. The classifier consumes only a completed, content-addressed
checkpoint through :func:`load_complete_extraction`.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import tempfile
from pathlib import Path
from typing import Iterable

from .rsk_sidecar import validate_rsk_sidecar_cells

CHECKPOINT_VERSION = 3

RAW_COLUMNS = [
    "rsk_height",
    "rsk_timestamp",
    "rsk_hash",
    "rsk_miner",
    "rsk_difficulty",
    "btc_header_hash",
    "btc_prev_hash",
    "btc_time",
    "btc_bits",
    "merge_mining_hash",
    "merge_mining_merkle_proof",
    "coinbase_outputs",
    "coinbase_op_return",
    "coinbase_ascii_strings",
    "coinbase_tail_hex",
    "btc_header_hex",
    "is_uncle",
    "uncle_index",
    "uncle_parent_height",
]

SKIP_COLUMNS = [
    "rsk_height",
    "rsk_timestamp",
    "rsk_hash",
    "is_uncle",
    "uncle_index",
    "uncle_parent_height",
    "advertised_uncle_hash",
    "proof_bytes",
    "reason",
]

STATS_KEYS = (
    "auxpow_blocks",
    "skipped_pre_auxpow",
    "uncle_auxpow_blocks",
    "uncle_skipped_pre_auxpow",
)


def default_checkpoint_path(output_path: Path) -> Path:
    """Return the checkpoint sidecar for one raw extraction CSV."""
    return output_path.with_name(f"{output_path.name}.checkpoint.json")


def default_skip_ledger_path(output_path: Path) -> Path:
    """Return the private fallback ledger for one raw extraction CSV."""
    return output_path.with_name(f"{output_path.name}.skips.csv")


def checkpoint_artifact_path(checkpoint_path: Path, value: object) -> Path:
    """Resolve a portable artifact reference from its actual checkpoint."""
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise ValueError("RSK checkpoint artifact path must be relative")
    return (checkpoint_path.resolve().parent / value).resolve()


def empty_stats() -> dict[str, int]:
    """Return a fresh extraction counter set."""
    return dict.fromkeys(STATS_KEYS, 0)


def fsync_directory_best_effort(path: Path) -> None:
    """Try to persist directory metadata without obscuring a completed rename.

    Some filesystems reject directory fsync.  Both opening and fsyncing are
    therefore best effort.  In particular, an error after ``os.replace`` must
    not report that the replacement failed when it already happened.
    """
    directory_fd: int | None = None
    try:
        directory_fd = os.open(path, os.O_RDONLY)
        os.fsync(directory_fd)
    except OSError:
        return
    finally:
        if directory_fd is not None:
            try:
                os.close(directory_fd)
            except OSError:
                pass


def write_json_atomic(path: Path, value: dict) -> None:
    """Fsync and atomically replace a JSON file, then best-effort fsync its dir."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
        fsync_directory_best_effort(path.parent)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def sha256_file(path: Path, *, length: int | None = None) -> str:
    """Hash exactly ``length`` leading bytes, or the complete file when None."""
    digest = hashlib.sha256()
    remaining = length
    with path.open("rb") as source:
        while remaining is None or remaining:
            wanted = 1024 * 1024 if remaining is None else min(1024 * 1024, remaining)
            chunk = source.read(wanted)
            if not chunk:
                break
            digest.update(chunk)
            if remaining is not None:
                remaining -= len(chunk)
    if remaining not in (None, 0):
        raise ValueError(f"{path} is shorter than the requested digest length")
    return digest.hexdigest()


def _csv_bytes(
    rows: Iterable[dict], columns: list[str], *, header: bool = False
) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=columns, lineterminator="\n")
    if header:
        writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().encode("utf-8")


def _append_durable(
    path: Path, payload: bytes, expected_offset: int
) -> tuple[int, str]:
    """Append one byte segment at the exact expected offset and fsync it."""
    with path.open("r+b") as output:
        output.seek(0, os.SEEK_END)
        actual_offset = output.tell()
        if actual_offset != expected_offset:
            raise ValueError(
                f"refusing to append to {path}: byte length changed "
                f"({actual_offset} != {expected_offset})"
            )
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())
        end_offset = output.tell()
    return end_offset, hashlib.sha256(payload).hexdigest()


def is_lower_hex(value: object, *, lengths: tuple[int, ...] = (64,)) -> bool:
    """Accept an exact unprefixed lowercase hex identity or digest."""
    if not isinstance(value, str) or len(value) not in lengths:
        return False
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        return False
    return decoded.hex() == value


def _valid_endpoint(value: object, expected_height: int) -> bool:
    return (
        isinstance(value, dict)
        and type(value.get("height")) is int
        and value["height"] == expected_height
        and is_lower_hex(value.get("hash"))
        and is_lower_hex(value.get("parent_hash"))
        and type(value.get("timestamp")) is int
        and value["timestamp"] >= 0
    )


def _validate_csv_header(path: Path, expected: list[str]) -> None:
    try:
        with path.open(newline="") as source:
            actual = csv.DictReader(source).fieldnames
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    if actual != expected:
        raise ValueError(f"{path}: CSV header does not match its checkpoint schema")


def _load_checkpoint(path: Path) -> dict:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read RSK checkpoint {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"invalid RSK checkpoint object: {path}")
    return value


def _validate_stats(stats: object) -> bool:
    return (
        isinstance(stats, dict)
        and set(stats) == set(STATS_KEYS)
        and all(type(stats[key]) is int and stats[key] >= 0 for key in STATS_KEYS)
    )


def _validate_commit_ledger(state: dict) -> None:
    commits = state.get("commits")
    if not isinstance(commits, list):
        raise ValueError("malformed RSK checkpoint commit ledger")
    expected_height = state["start_height"]
    expected_output_offset = state["output_header_bytes"]
    expected_skip_offset = state["skip_header_bytes"]
    output_rows = 0
    skip_rows = 0
    advertised_uncles = 0
    previous_identity: dict | None = None
    for index, commit in enumerate(commits):
        if not isinstance(commit, dict):
            raise ValueError(f"malformed RSK checkpoint commit {index}")
        required_ints = (
            "start_height",
            "end_height",
            "output_start",
            "output_end",
            "skip_start",
            "skip_end",
            "output_rows",
            "skip_rows",
            "advertised_uncles",
        )
        if any(type(commit.get(field)) is not int for field in required_ints):
            raise ValueError(f"malformed RSK checkpoint commit {index}")
        if (
            commit["start_height"] != expected_height
            or commit["end_height"] <= commit["start_height"]
            or commit["output_start"] != expected_output_offset
            or commit["output_end"] < commit["output_start"]
            or commit["skip_start"] != expected_skip_offset
            or commit["skip_end"] < commit["skip_start"]
            or commit["output_rows"] < 0
            or commit["skip_rows"] < 0
            or commit["advertised_uncles"] < 0
            or not is_lower_hex(commit.get("output_segment_sha256"))
            or not is_lower_hex(commit.get("skip_segment_sha256"))
            or not _valid_endpoint(
                commit.get("first_canonical_identity"), commit["start_height"]
            )
            or not _valid_endpoint(
                commit.get("last_canonical_identity"), commit["end_height"] - 1
            )
        ):
            raise ValueError(f"malformed RSK checkpoint commit {index}")
        first_identity = commit["first_canonical_identity"]
        last_identity = commit["last_canonical_identity"]
        if previous_identity is None:
            if first_identity != state["start_identity"]:
                raise ValueError("RSK checkpoint commit ledger start identity mismatch")
        elif first_identity["parent_hash"] != previous_identity["hash"]:
            raise ValueError("RSK checkpoint commit ledger continuity mismatch")
        previous_identity = last_identity
        expected_height = commit["end_height"]
        expected_output_offset = commit["output_end"]
        expected_skip_offset = commit["skip_end"]
        output_rows += commit["output_rows"]
        skip_rows += commit["skip_rows"]
        advertised_uncles += commit["advertised_uncles"]
    if (
        expected_height != state["next_height"]
        or expected_output_offset != state["committed_bytes"]
        or expected_skip_offset != state["skip_committed_bytes"]
        or output_rows != state["output_rows"]
        or skip_rows != state["skip_rows"]
        or advertised_uncles != state["advertised_uncles"]
    ):
        raise ValueError("RSK checkpoint cumulative commit accounting mismatch")
    if commits:
        if state.get("last_canonical_identity") != previous_identity:
            raise ValueError("RSK checkpoint continuity state mismatch")
        if (
            expected_height == state["end_height"]
            and previous_identity != state["end_identity"]
        ):
            raise ValueError("RSK checkpoint commit ledger end identity mismatch")
    elif state.get("last_canonical_identity") is not None:
        raise ValueError("RSK checkpoint has premature continuity state")


def validate_checkpoint(
    checkpoint_path: Path,
    *,
    output_path: Path,
    skip_path: Path,
    start: int,
    end: int,
    start_identity: dict,
    end_identity: dict,
) -> dict:
    """Load and structurally validate the resumable acquisition contract."""
    state = _load_checkpoint(checkpoint_path)
    expected = {
        "version": CHECKPOINT_VERSION,
        "output_path": os.path.relpath(
            output_path.resolve(), checkpoint_path.resolve().parent
        ),
        "skip_ledger_path": os.path.relpath(
            skip_path.resolve(), checkpoint_path.resolve().parent
        ),
        "start_height": start,
        "end_height": end,
        "start_identity": start_identity,
        "end_identity": end_identity,
        "csv_columns": RAW_COLUMNS,
        "skip_columns": SKIP_COLUMNS,
    }
    for field, value in expected.items():
        if state.get(field) != value:
            raise ValueError(
                f"cannot resume {output_path}: checkpoint {field} mismatch "
                f"({state.get(field)!r} != {value!r})"
            )
    if not _valid_endpoint(start_identity, start) or not _valid_endpoint(
        end_identity, end - 1
    ):
        raise ValueError("malformed pinned RSK endpoint identity")
    next_height = state.get("next_height")
    integer_fields = (
        "committed_bytes",
        "skip_committed_bytes",
        "output_header_bytes",
        "skip_header_bytes",
        "output_rows",
        "skip_rows",
        "advertised_uncles",
    )
    if (
        type(next_height) is not int
        or not start <= next_height <= end
        or any(
            type(state.get(field)) is not int or state[field] < 0
            for field in integer_fields
        )
        or state["committed_bytes"] < state["output_header_bytes"]
        or state["skip_committed_bytes"] < state["skip_header_bytes"]
        or not _validate_stats(state.get("stats"))
        or type(state.get("complete")) is not bool
    ):
        raise ValueError(f"cannot resume {output_path}: malformed checkpoint progress")
    if state["complete"] and next_height != end:
        raise ValueError(f"cannot resume {output_path}: premature completion marker")
    if not state["complete"] and (
        state.get("content_sha256") or state.get("skip_ledger_sha256")
    ):
        raise ValueError(f"cannot resume {output_path}: unsealed content digest")
    if state["complete"] and (
        not is_lower_hex(state.get("content_sha256"))
        or not is_lower_hex(state.get("skip_ledger_sha256"))
    ):
        raise ValueError(f"cannot resume {output_path}: missing completed digest")
    _validate_commit_ledger(state)
    stats = state["stats"]
    committed_canonical = next_height - start
    if (
        stats["auxpow_blocks"] + stats["skipped_pre_auxpow"] != committed_canonical
        or stats["uncle_auxpow_blocks"] + stats["uncle_skipped_pre_auxpow"]
        != state["advertised_uncles"]
        or stats["auxpow_blocks"] + stats["uncle_auxpow_blocks"] != state["output_rows"]
        or stats["skipped_pre_auxpow"] + stats["uncle_skipped_pre_auxpow"]
        != state["skip_rows"]
    ):
        raise ValueError(f"cannot resume {output_path}: checkpoint partition mismatch")
    return state


def _validate_committed_segments(path: Path, state: dict, *, skip: bool) -> None:
    header_bytes = state["skip_header_bytes" if skip else "output_header_bytes"]
    header_digest = state["skip_header_sha256" if skip else "output_header_sha256"]
    if sha256_file(path, length=header_bytes) != header_digest:
        raise ValueError(f"{path}: CSV header bytes disagree with checkpoint")
    start_field = "skip_start" if skip else "output_start"
    end_field = "skip_end" if skip else "output_end"
    digest_field = "skip_segment_sha256" if skip else "output_segment_sha256"
    with path.open("rb") as source:
        for index, commit in enumerate(state["commits"]):
            start = commit[start_field]
            end = commit[end_field]
            source.seek(start)
            payload = source.read(end - start)
            if (
                len(payload) != end - start
                or hashlib.sha256(payload).hexdigest() != commit[digest_field]
            ):
                raise ValueError(f"{path}: committed segment {index} digest mismatch")


def prepare_extraction(
    output_path: Path,
    checkpoint_path: Path,
    skip_path: Path,
    *,
    start: int,
    end: int,
    start_identity: dict,
    end_identity: dict,
    resume: bool,
) -> dict:
    """Create or resume the coupled raw CSV, skip ledger, and checkpoint."""
    resolved = {output_path.resolve(), checkpoint_path.resolve(), skip_path.resolve()}
    if len(resolved) != 3:
        raise ValueError("output CSV, skip ledger, and checkpoint must be distinct")
    if start < 0 or end <= start:
        raise ValueError("require 0 <= start < end")

    if resume:
        if not all(
            path.is_file() for path in (output_path, skip_path, checkpoint_path)
        ):
            raise ValueError(
                "--resume requires the output, skip ledger, and checkpoint"
            )
        state = validate_checkpoint(
            checkpoint_path,
            output_path=output_path,
            skip_path=skip_path,
            start=start,
            end=end,
            start_identity=start_identity,
            end_identity=end_identity,
        )
        _validate_csv_header(output_path, RAW_COLUMNS)
        _validate_csv_header(skip_path, SKIP_COLUMNS)
        for path, committed, is_skip in (
            (output_path, state["committed_bytes"], False),
            (skip_path, state["skip_committed_bytes"], True),
        ):
            actual = path.stat().st_size
            if actual < committed:
                raise ValueError(
                    f"{path}: shorter than its checkpoint ({actual} < {committed})"
                )
            _validate_committed_segments(path, state, skip=is_skip)
            if actual > committed:
                with path.open("r+b") as output:
                    output.truncate(committed)
                    output.flush()
                    os.fsync(output.fileno())
        if state["complete"]:
            if sha256_file(output_path) != state["content_sha256"]:
                raise ValueError(f"{output_path}: completed content digest mismatch")
            if sha256_file(skip_path) != state["skip_ledger_sha256"]:
                raise ValueError(f"{skip_path}: completed content digest mismatch")
        return state

    existing = [
        path for path in (output_path, skip_path, checkpoint_path) if path.exists()
    ]
    if existing:
        raise FileExistsError(
            "refusing to replace an existing RSK extraction artifact: "
            + ", ".join(str(path) for path in existing)
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    skip_path.parent.mkdir(parents=True, exist_ok=True)
    output_header = _csv_bytes([], RAW_COLUMNS, header=True)
    skip_header = _csv_bytes([], SKIP_COLUMNS, header=True)
    created: list[Path] = []
    try:
        for path, payload in ((output_path, output_header), (skip_path, skip_header)):
            with path.open("xb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            created.append(path)
            fsync_directory_best_effort(path.parent)
        state = {
            "version": CHECKPOINT_VERSION,
            "output_path": os.path.relpath(
                output_path.resolve(), checkpoint_path.resolve().parent
            ),
            "skip_ledger_path": os.path.relpath(
                skip_path.resolve(), checkpoint_path.resolve().parent
            ),
            "start_height": start,
            "end_height": end,
            "start_identity": start_identity,
            "end_identity": end_identity,
            "csv_columns": RAW_COLUMNS,
            "skip_columns": SKIP_COLUMNS,
            "next_height": start,
            "committed_bytes": len(output_header),
            "skip_committed_bytes": len(skip_header),
            "output_header_bytes": len(output_header),
            "skip_header_bytes": len(skip_header),
            "output_header_sha256": hashlib.sha256(output_header).hexdigest(),
            "skip_header_sha256": hashlib.sha256(skip_header).hexdigest(),
            "output_rows": 0,
            "skip_rows": 0,
            "advertised_uncles": 0,
            "last_canonical_identity": None,
            "complete": False,
            "content_sha256": "",
            "skip_ledger_sha256": "",
            "stats": empty_stats(),
            "commits": [],
        }
        write_json_atomic(checkpoint_path, state)
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
            fsync_directory_best_effort(path.parent)
        checkpoint_path.unlink(missing_ok=True)
        raise
    return state


def _as_int(value: object, *, field: str) -> int:
    if type(value) is int:
        return value
    if isinstance(value, str) and value.isascii() and value.isdigit():
        return int(value)
    raise ValueError(f"RSK extraction row has malformed {field}")


def _hex_cell(
    value: object,
    *,
    field: str,
    expected_bytes: int | None = None,
    allow_empty: bool = False,
) -> str:
    if allow_empty and value == "":
        return ""
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("0x")
        or value != value.lower()
        or len(value) % 2
        or (expected_bytes is not None and len(value) != expected_bytes * 2)
    ):
        raise ValueError(f"RSK raw row has malformed {field}")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"RSK raw row has malformed {field}") from exc
    return value


def _validate_raw_row(row: dict) -> None:
    """Validate one durable 80-byte proof row before it enters the corpus."""
    missing = set(RAW_COLUMNS) - set(row)
    if missing:
        raise ValueError("RSK raw row is missing fields: " + ", ".join(sorted(missing)))
    rsk_height = _as_int(row.get("rsk_height"), field="rsk_height")
    rsk_timestamp = _as_int(row.get("rsk_timestamp"), field="rsk_timestamp")
    if rsk_height < 0 or rsk_timestamp <= 0 or not is_lower_hex(row.get("rsk_hash")):
        raise ValueError("RSK raw row has malformed child identity")

    difficulty = row.get("rsk_difficulty")
    try:
        parsed_difficulty = int(difficulty, 16) if isinstance(difficulty, str) else -1
    except ValueError as exc:
        raise ValueError("RSK raw row has malformed rsk_difficulty") from exc
    if (
        parsed_difficulty < 0
        or difficulty != difficulty.lower()
        or difficulty.startswith("0x")
        or difficulty != f"{parsed_difficulty:x}"
    ):
        raise ValueError("RSK raw row has malformed rsk_difficulty")

    header_hex = _hex_cell(
        row.get("btc_header_hex"), field="btc_header_hex", expected_bytes=80
    )
    header = bytes.fromhex(header_hex)
    header_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()
    expected = {
        "btc_header_hash": header_hash,
        "btc_prev_hash": header[4:36][::-1].hex(),
        "btc_time": int.from_bytes(header[68:72], "little"),
        "btc_bits": header[72:76][::-1].hex(),
    }
    if (
        row.get("btc_header_hash") != expected["btc_header_hash"]
        or row.get("btc_prev_hash") != expected["btc_prev_hash"]
    ):
        raise ValueError("RSK raw row Bitcoin header identity mismatch")
    if _as_int(row.get("btc_time"), field="btc_time") != expected["btc_time"]:
        raise ValueError("RSK raw row Bitcoin header time mismatch")
    if row.get("btc_bits") != expected["btc_bits"]:
        raise ValueError("RSK raw row Bitcoin header nBits mismatch")

    _hex_cell(
        row.get("merge_mining_merkle_proof"),
        field="merge_mining_merkle_proof",
        allow_empty=True,
    )
    _hex_cell(row.get("coinbase_tail_hex"), field="coinbase_tail_hex", allow_empty=True)
    validate_rsk_sidecar_cells(
        {
            "rsk_miner": str(row.get("rsk_miner", "")),
            "merge_mining_hash": str(row.get("merge_mining_hash", "")),
            "is_uncle": str(row.get("is_uncle", "")),
            "uncle_index": str(row.get("uncle_index", "")),
            "uncle_parent_height": str(row.get("uncle_parent_height", "")),
            "rsk_merkle_proof": str(row.get("merge_mining_merkle_proof", "")),
            "rsk_coinbase_tail": str(row.get("coinbase_tail_hex", "")),
        },
        row_id=f"RSK raw row at child height {rsk_height}",
    )


def _validate_interval_partition(
    state: dict,
    *,
    rows: list[dict],
    skips: list[dict],
    stats_delta: dict[str, int],
    next_height: int,
    advertised_uncles: int,
    first_identity: dict,
    last_identity: dict,
) -> None:
    start = state["next_height"]
    height_count = next_height - start
    if not _validate_stats(stats_delta):
        raise ValueError("RSK interval statistics do not match the checkpoint schema")
    for row in rows:
        _validate_raw_row(row)
    canonical_rows = [
        row for row in rows if _as_int(row.get("is_uncle"), field="is_uncle") == 0
    ]
    uncle_rows = [
        row for row in rows if _as_int(row.get("is_uncle"), field="is_uncle") == 1
    ]
    canonical_skips = [
        row for row in skips if _as_int(row.get("is_uncle"), field="is_uncle") == 0
    ]
    uncle_skips = [
        row for row in skips if _as_int(row.get("is_uncle"), field="is_uncle") == 1
    ]
    if (
        len(canonical_rows) != stats_delta["auxpow_blocks"]
        or len(canonical_skips) != stats_delta["skipped_pre_auxpow"]
        or len(uncle_rows) != stats_delta["uncle_auxpow_blocks"]
        or len(uncle_skips) != stats_delta["uncle_skipped_pre_auxpow"]
        or len(canonical_rows) + len(canonical_skips) != height_count
        or len(uncle_rows) + len(uncle_skips) != advertised_uncles
    ):
        raise ValueError("RSK interval row/stat partition invariant failed")
    canonical_heights = sorted(
        _as_int(row.get("rsk_height"), field="rsk_height")
        for row in [*canonical_rows, *canonical_skips]
    )
    if canonical_heights != list(range(start, next_height)):
        raise ValueError("RSK interval canonical heights are missing or duplicated")

    canonical_outcomes = {
        _as_int(row.get("rsk_height"), field="rsk_height"): row
        for row in [*canonical_rows, *canonical_skips]
    }
    for endpoint, identity in (
        (canonical_outcomes[start], first_identity),
        (canonical_outcomes[next_height - 1], last_identity),
    ):
        if (
            endpoint.get("rsk_hash") != identity["hash"]
            or _as_int(endpoint.get("rsk_timestamp"), field="rsk_timestamp")
            != identity["timestamp"]
        ):
            raise ValueError("RSK interval endpoint outcome identity mismatch")

    def outcome_identity(row: dict, *, is_skip: bool) -> tuple[str, int, int]:
        row_height = _as_int(row.get("rsk_height"), field="rsk_height")
        row_timestamp = _as_int(row.get("rsk_timestamp"), field="rsk_timestamp")
        row_hash = row.get("rsk_hash")
        is_uncle = _as_int(row.get("is_uncle"), field="is_uncle")
        if row_height < 0 or row_timestamp < 0 or not is_lower_hex(row_hash):
            raise ValueError("RSK interval outcome has malformed block identity")
        if is_uncle == 0:
            if row.get("uncle_index") not in (None, "") or row.get(
                "uncle_parent_height"
            ) not in (None, ""):
                raise ValueError("RSK canonical outcome has uncle placement")
            if is_skip and row.get("advertised_uncle_hash") not in (None, ""):
                raise ValueError("RSK canonical skip has an advertised uncle hash")
            return ("canonical", row_height, -1)
        if is_uncle != 1:
            raise ValueError("RSK interval outcome has invalid is_uncle")
        uncle_index = _as_int(row.get("uncle_index"), field="uncle_index")
        parent_height = _as_int(
            row.get("uncle_parent_height"), field="uncle_parent_height"
        )
        if uncle_index < 0 or not start <= parent_height < next_height:
            raise ValueError("RSK uncle outcome has invalid placement")
        if is_skip and row.get("advertised_uncle_hash") != row_hash:
            raise ValueError("RSK uncle skip disagrees with its advertised hash")
        return ("uncle", parent_height, uncle_index)

    outcome_identities = [
        *(outcome_identity(row, is_skip=False) for row in rows),
        *(outcome_identity(row, is_skip=True) for row in skips),
    ]
    if len(set(outcome_identities)) != len(outcome_identities):
        raise ValueError("RSK interval contains duplicate outcome identities")
    if any(
        not (
            (
                _as_int(row.get("proof_bytes"), field="proof_bytes") in (69, 70)
                and row.get("reason") == "fallback_signature"
            )
            or (
                _as_int(row.get("proof_bytes"), field="proof_bytes") == 1
                and row.get("reason") == "genesis_sentinel"
                and _as_int(row.get("rsk_height"), field="rsk_height") == 0
                and _as_int(row.get("is_uncle"), field="is_uncle") == 0
            )
        )
        for row in skips
    ):
        raise ValueError("RSK interval skip ledger contains a non-fallback proof")


def commit_interval(
    output_path: Path,
    checkpoint_path: Path,
    skip_path: Path,
    state: dict,
    *,
    rows: list[dict],
    skips: list[dict],
    stats_delta: dict[str, int],
    next_height: int,
    first_identity: dict,
    last_identity: dict,
    advertised_uncles: int,
) -> dict:
    """Append and integrity-bind one contiguous durable checkpoint interval."""
    if not state["next_height"] < next_height <= state["end_height"]:
        raise ValueError("committed RSK interval does not advance within bounds")
    if state["complete"]:
        raise ValueError("cannot append to a completed RSK extraction")
    start = state["next_height"]
    if not _valid_endpoint(first_identity, start) or not _valid_endpoint(
        last_identity, next_height - 1
    ):
        raise ValueError("RSK interval endpoint identity is malformed")
    if start == state["start_height"]:
        if first_identity != state["start_identity"]:
            raise ValueError("RSK interval does not begin at the pinned start identity")
    else:
        previous_identity = state.get("last_canonical_identity")
        if (
            not _valid_endpoint(previous_identity, start - 1)
            or first_identity["parent_hash"] != previous_identity["hash"]
        ):
            raise ValueError("RSK interval breaks canonical continuity at checkpoint")
    if next_height == state["end_height"] and last_identity != state["end_identity"]:
        raise ValueError("RSK interval does not end at the pinned end identity")
    _validate_interval_partition(
        state,
        rows=rows,
        skips=skips,
        stats_delta=stats_delta,
        next_height=next_height,
        advertised_uncles=advertised_uncles,
        first_identity=first_identity,
        last_identity=last_identity,
    )

    output_payload = _csv_bytes(rows, RAW_COLUMNS)
    skip_payload = _csv_bytes(skips, SKIP_COLUMNS)
    output_start = state["committed_bytes"]
    skip_start = state["skip_committed_bytes"]
    output_end, output_segment_sha256 = _append_durable(
        output_path, output_payload, output_start
    )
    skip_end, skip_segment_sha256 = _append_durable(skip_path, skip_payload, skip_start)
    next_stats = {key: state["stats"][key] + stats_delta[key] for key in STATS_KEYS}
    commit = {
        "start_height": start,
        "end_height": next_height,
        "output_start": output_start,
        "output_end": output_end,
        "skip_start": skip_start,
        "skip_end": skip_end,
        "output_rows": len(rows),
        "skip_rows": len(skips),
        "advertised_uncles": advertised_uncles,
        "output_segment_sha256": output_segment_sha256,
        "skip_segment_sha256": skip_segment_sha256,
        "first_canonical_identity": first_identity,
        "last_canonical_identity": last_identity,
    }
    next_state = {
        **state,
        "next_height": next_height,
        "committed_bytes": output_end,
        "skip_committed_bytes": skip_end,
        "output_rows": state["output_rows"] + len(rows),
        "skip_rows": state["skip_rows"] + len(skips),
        "advertised_uncles": state["advertised_uncles"] + advertised_uncles,
        "last_canonical_identity": last_identity,
        "stats": next_stats,
        "commits": [*state["commits"], commit],
    }
    write_json_atomic(checkpoint_path, next_state)
    return next_state


def seal_extraction(
    output_path: Path,
    checkpoint_path: Path,
    skip_path: Path,
    state: dict,
    *,
    rechecked_end_identity: dict,
) -> dict:
    """Seal a fully committed run after rechecking the pinned end identity."""
    if state["next_height"] != state["end_height"] or state["complete"]:
        raise ValueError("RSK extraction is not in the sealable state")
    if rechecked_end_identity != state["end_identity"]:
        raise ValueError("RSK end identity changed before final seal")
    if (
        output_path.stat().st_size != state["committed_bytes"]
        or skip_path.stat().st_size != state["skip_committed_bytes"]
    ):
        raise ValueError("RSK extraction artifacts changed before final seal")
    sealed = {
        **state,
        "complete": True,
        "content_sha256": sha256_file(output_path),
        "skip_ledger_sha256": sha256_file(skip_path),
    }
    write_json_atomic(checkpoint_path, sealed)
    return sealed


def load_complete_extraction(input_path: Path, checkpoint_path: Path) -> dict:
    """Require a sealed checkpoint that verifies the classifier input bytes."""
    state = _load_checkpoint(checkpoint_path)
    try:
        skip_path = checkpoint_artifact_path(checkpoint_path, state["skip_ledger_path"])
        start_identity = state["start_identity"]
        end_identity = state["end_identity"]
        start = state["start_height"]
        end = state["end_height"]
    except (KeyError, TypeError) as exc:
        raise ValueError(f"malformed RSK checkpoint {checkpoint_path}") from exc
    validated = validate_checkpoint(
        checkpoint_path,
        output_path=input_path,
        skip_path=skip_path,
        start=start,
        end=end,
        start_identity=start_identity,
        end_identity=end_identity,
    )
    if not validated["complete"]:
        raise ValueError(
            f"RSK classifier input checkpoint is not complete: {checkpoint_path}"
        )
    for path, expected_bytes, expected_digest, columns, is_skip in (
        (
            input_path,
            validated["committed_bytes"],
            validated["content_sha256"],
            RAW_COLUMNS,
            False,
        ),
        (
            skip_path,
            validated["skip_committed_bytes"],
            validated["skip_ledger_sha256"],
            SKIP_COLUMNS,
            True,
        ),
    ):
        if not path.is_file() or path.stat().st_size != expected_bytes:
            raise ValueError(f"{path}: completed artifact byte length mismatch")
        _validate_csv_header(path, columns)
        _validate_committed_segments(path, validated, skip=is_skip)
        if sha256_file(path) != expected_digest:
            raise ValueError(f"{path}: completed content digest mismatch")
    return validated
