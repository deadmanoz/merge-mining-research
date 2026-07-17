#!/usr/bin/env python3
"""Recover Lyncoin's pre-Flex AuxPoW evidence via raw P2P ``getheaders``.

The live Lyncoin network can deliver extended headers much faster than full
block bodies.  Lyncoin's header serialization includes the complete
Namecoin-family CAuxPow object, so the height 0..260,499 header stream is a
lossless input to the existing Bitcoin-parent classifier.

The downloader is resumable at atomic batch-file boundaries.  On every start
it verifies all existing batches from the pinned genesis through the last
saved header before opening a socket.  It writes the classifier CSV only after
the full pre-Flex range and the height-260,500 boundary proof validate.

No RPC credentials are needed.  The peer is required explicitly so a changing
public network endpoint never silently alters provenance.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import secrets
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from stale_blocks_analysis.lyncoin_headers import (  # noqa: E402
    AUXPOW_END_HEIGHT,
    BATCH_VERSION,
    CANDIDATE_FIELDS,
    CHECKPOINTS,
    DEFAULT_PORT,
    FLEX_HEIGHT,
    GENESIS_RAW,
    MAX_HEADERS_RESULTS,
    NETWORK_MAGIC,
    NODE_NETWORK,
    PROTOCOL_VERSION,
    SOURCE_COMMIT,
    SOURCE_URL,
    HeaderSummary,
    ParsedHeader,
    RecoveryValidationError,
    candidate_row,
    decode_batch,
    decode_p2p_header,
    encode_batch,
    encode_compact_size,
    encode_p2p_message,
    parse_extended_header,
    parse_headers_payload,
    sha256d,
    validate_flex_boundary,
    validate_genesis,
    validate_pre_flex_header,
)

MANIFEST_SCHEMA = "lyncoin-p2p-header-recovery-v1"
BATCH_SUFFIX = ".lhbatch"
CANDIDATE_FILENAME = "lyncoin_auxpow_candidates.csv"
MANIFEST_FILENAME = "manifest.json"
USER_AGENT = b"/stale-blocks-research:lyn-headers-v1/"


def utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string with a ``Z`` suffix."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_peer(value: str) -> tuple[str, int]:
    """Parse an argparse ``HOST[:PORT]`` or ``[IPv6]:PORT`` peer spec.

    Applies ``DEFAULT_PORT`` when no port is given. Raises
    ``argparse.ArgumentTypeError`` on an empty value, an unterminated
    bracketed IPv6 host, a missing ``:port`` after brackets, or a
    non-integer/out-of-range port.
    """
    value = value.strip()
    if not value:
        raise argparse.ArgumentTypeError("peer cannot be empty")
    if value.startswith("["):
        close = value.find("]")
        if close < 0:
            raise argparse.ArgumentTypeError("unterminated bracketed IPv6 peer")
        host = value[1:close]
        remainder = value[close + 1 :]
        if not remainder:
            return host, DEFAULT_PORT
        if not remainder.startswith(":"):
            raise argparse.ArgumentTypeError("expected :port after bracketed peer")
        port_text = remainder[1:]
    elif value.count(":") == 1:
        host, port_text = value.rsplit(":", 1)
    elif ":" in value:
        host, port_text = value, str(DEFAULT_PORT)
    else:
        host, port_text = value, str(DEFAULT_PORT)
    if not host:
        raise argparse.ArgumentTypeError("peer host cannot be empty")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("peer port must be an integer") from exc
    if port < 1 or port > 65_535:
        raise argparse.ArgumentTypeError("peer port must be in 1..65535")
    return host, port


def format_peer(peer: tuple[str, int]) -> str:
    """Render a ``(host, port)`` tuple back to ``host:port``, bracketing an IPv6 host."""
    host, port = peer
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _fsync_directory(path: Path) -> None:
    """Fsync a directory's inode so a prior rename into it is durable. No-op if it can't be opened."""
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_bytes(
    path: Path, data: bytes, *, refuse_existing: bool = False
) -> None:
    """Write ``data`` to ``path`` atomically via a temp file, fsync, and rename.

    When ``refuse_existing`` is set, raises ``RecoveryValidationError``
    rather than clobbering a file that already exists at ``path`` — checked
    both before and after writing the temp file, closing the
    check-then-act race against a concurrent writer. The temp file is
    removed on every exit path, including after a successful rename.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if refuse_existing and path.exists():
        raise RecoveryValidationError(f"refusing to overwrite batch {path}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if refuse_existing and path.exists():
            raise RecoveryValidationError(f"refusing to overwrite batch {path}")
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    """JSON-encode ``value`` (sorted keys, trailing newline) and write it atomically."""
    payload = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    atomic_write_bytes(path, payload)


def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 digest of a file's contents, streamed in 1 MiB chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def batch_filename(start_height: int, end_height: int) -> str:
    """Return the deterministic zero-padded batch filename for a height range."""
    return f"{start_height:010d}-{end_height:010d}{BATCH_SUFFIX}"


@dataclass(frozen=True)
class PeerVersion:
    protocol: int
    services: int
    timestamp: int
    user_agent: str
    start_height: int
    relay: bool | None

    def to_json(self) -> dict[str, Any]:
        """Render this ``PeerVersion`` as the JSON-serialisable dict stored in batch metadata."""
        return {
            "protocol": self.protocol,
            "services": self.services,
            "timestamp": self.timestamp,
            "user_agent": self.user_agent,
            "start_height": self.start_height,
            "relay": self.relay,
        }


@dataclass(frozen=True)
class BatchInfo:
    file: str
    start_height: int
    end_height: int
    count: int
    size_bytes: int
    sha256: str
    first_hash: str
    last_hash: str
    metadata: dict[str, Any]

    def to_json(self) -> dict[str, Any]:
        """Render this ``BatchInfo`` as the JSON-serialisable dict stored in the manifest."""
        return {
            "file": self.file,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "count": self.count,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "first_hash": self.first_hash,
            "last_hash": self.last_hash,
            "metadata": self.metadata,
        }


@dataclass
class RecoveryState:
    output_dir: Path
    target_height: int
    history: list[HeaderSummary] = field(default_factory=list)
    batches: list[BatchInfo] = field(default_factory=list)
    auxpow_headers: int = 0
    solo_headers: int = 0
    candidate_count: int = 0
    flex_boundary: dict[str, Any] | None = None
    candidate_artifact: dict[str, Any] | None = None

    @property
    def last_height(self) -> int:
        """Height of the most recently validated header, or -1 before genesis."""
        return len(self.history) - 1

    @property
    def next_height(self) -> int:
        """Height that would be assigned to the next appended header."""
        return len(self.history)

    @property
    def complete(self) -> bool:
        """True once every header through ``target_height`` is validated and the Flex boundary proof is recorded."""
        return self.last_height == self.target_height and self.flex_boundary is not None


def _require_metadata_int(metadata: dict[str, Any], name: str) -> int:
    """Return ``metadata[name]`` as an int, raising ``RecoveryValidationError`` if missing or not a (non-bool) int."""
    value = metadata.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise RecoveryValidationError(f"batch metadata {name} must be an integer")
    return value


def _validate_boundary_metadata(
    metadata: dict[str, Any],
    previous: HeaderSummary,
) -> dict[str, Any]:
    """Re-derive and cross-check a batch's persisted Flex-activation boundary proof.

    Parses the stored ``raw_header_hex``, recomputes the boundary proof
    against ``previous``, and raises ``RecoveryValidationError`` if the
    metadata is missing, malformed, or the recomputed proof differs from
    what was stored (tamper/corruption detection).
    """
    boundary = metadata.get("flex_boundary")
    if not isinstance(boundary, dict):
        raise RecoveryValidationError("final batch lacks Flex boundary proof")
    raw_hex = boundary.get("raw_header_hex")
    if not isinstance(raw_hex, str):
        raise RecoveryValidationError("Flex boundary raw_header_hex is missing")
    try:
        parsed = parse_extended_header(bytes.fromhex(raw_hex))
    except ValueError as exc:
        raise RecoveryValidationError(
            "Flex boundary raw header is invalid hex"
        ) from exc
    validated = validate_flex_boundary(parsed, previous)
    if validated != boundary:
        raise RecoveryValidationError("stored Flex boundary metadata is inconsistent")
    return validated


def _validate_and_add_header(
    state: RecoveryState,
    raw_header: bytes,
    height: int,
) -> tuple[ParsedHeader, HeaderSummary]:
    """Parse, validate, and append one raw header to ``state``.

    Applies genesis rules at height 0 (raising ``RecoveryValidationError``
    if genesis is not actually first) and pre-Flex chain rules otherwise,
    appends the resulting summary to ``state.history``, updates the
    AuxPoW/solo and self-target-PoW-candidate counters, and returns
    ``(parsed, summary)``.
    """
    parsed = parse_extended_header(raw_header)
    if height == 0:
        if state.history:
            raise RecoveryValidationError("genesis is not the first header")
        summary = validate_genesis(parsed)
    else:
        summary = validate_pre_flex_header(parsed, height, state.history)
    state.history.append(summary)
    if summary.has_auxpow:
        state.auxpow_headers += 1
    else:
        state.solo_headers += 1
    if candidate_row(parsed, summary) is not None:
        state.candidate_count += 1
    return parsed, summary


def _batch_info(
    path: Path, metadata: dict[str, Any], summaries: list[HeaderSummary]
) -> BatchInfo:
    """Build a ``BatchInfo`` record for a persisted batch file from its metadata and validated header summaries."""
    return BatchInfo(
        file=f"batches/{path.name}",
        start_height=summaries[0].height,
        end_height=summaries[-1].height,
        count=len(summaries),
        size_bytes=path.stat().st_size,
        sha256=sha256_file(path),
        first_hash=summaries[0].hash_display,
        last_hash=summaries[-1].hash_display,
        metadata=metadata,
    )


def create_genesis_batch(output_dir: Path) -> None:
    """Write the pinned Lyncoin genesis header as the height-0 batch, if not already present."""
    batches_dir = output_dir / "batches"
    batches_dir.mkdir(parents=True, exist_ok=True)
    path = batches_dir / batch_filename(0, 0)
    if path.exists():
        return
    metadata = {
        "schema": MANIFEST_SCHEMA,
        "source": "pinned Lyncoin Core v4.0.0 genesis",
        "source_commit": SOURCE_COMMIT,
        "created_at": utc_now(),
        "start_height": 0,
        "end_height": 0,
        "response_header_count": 1,
        "peer": None,
    }
    atomic_write_bytes(
        path,
        encode_batch(metadata, [GENESIS_RAW]),
        refuse_existing=True,
    )


def scan_batches(output_dir: Path, target_height: int) -> RecoveryState:
    """Revalidate every persisted byte and rebuild resumable state."""
    if target_height != AUXPOW_END_HEIGHT:
        raise RecoveryValidationError(
            f"only the canonical pre-Flex target {AUXPOW_END_HEIGHT} is supported"
        )
    batches_dir = output_dir / "batches"
    paths = sorted(batches_dir.glob(f"*{BATCH_SUFFIX}"))
    if not paths:
        raise RecoveryValidationError("recovery has no genesis batch")

    state = RecoveryState(output_dir=output_dir, target_height=target_height)
    expected_start = 0
    for path in paths:
        decoded = decode_batch(path.read_bytes())
        metadata = decoded.metadata
        if metadata.get("schema") != MANIFEST_SCHEMA:
            raise RecoveryValidationError(f"{path}: wrong metadata schema")
        if metadata.get("source_commit") != SOURCE_COMMIT:
            raise RecoveryValidationError(f"{path}: source commit mismatch")
        start_height = _require_metadata_int(metadata, "start_height")
        end_height = _require_metadata_int(metadata, "end_height")
        if start_height != expected_start:
            raise RecoveryValidationError(
                f"{path}: starts at {start_height}, expected {expected_start}"
            )
        if end_height > target_height:
            raise RecoveryValidationError(f"{path}: persists post-target headers")
        if end_height - start_height + 1 != len(decoded.raw_headers):
            raise RecoveryValidationError(f"{path}: height range/count mismatch")
        expected_name = batch_filename(start_height, end_height)
        if path.name != expected_name:
            raise RecoveryValidationError(
                f"{path}: expected deterministic filename {expected_name}"
            )

        summaries: list[HeaderSummary] = []
        for offset, raw_header in enumerate(decoded.raw_headers):
            height = start_height + offset
            _, summary = _validate_and_add_header(state, raw_header, height)
            summaries.append(summary)
        if not summaries:
            raise RecoveryValidationError(f"{path}: empty batch")
        state.batches.append(_batch_info(path, metadata, summaries))
        expected_start = end_height + 1

        if end_height == target_height:
            state.flex_boundary = _validate_boundary_metadata(
                metadata,
                state.history[-1],
            )
        elif "flex_boundary" in metadata:
            raise RecoveryValidationError(f"{path}: early Flex boundary metadata")

    manifest_path = output_dir / MANIFEST_FILENAME
    if manifest_path.exists():
        try:
            old_manifest = json.loads(manifest_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise RecoveryValidationError("existing manifest is invalid JSON") from exc
        artifact = old_manifest.get("candidate_artifact")
        if isinstance(artifact, dict):
            candidate_path = output_dir / CANDIDATE_FILENAME
            if candidate_path.is_file():
                expected_digest = artifact.get("sha256")
                expected_count = artifact.get("rows")
                if (
                    expected_digest == sha256_file(candidate_path)
                    and expected_count == state.candidate_count
                ):
                    state.candidate_artifact = artifact
    return state


def build_manifest(state: RecoveryState) -> dict[str, Any]:
    """Assemble the JSON manifest describing this recovery's scope, validation
    checks, header/candidate counts, Flex boundary proof, and batch list.
    """
    created_at = (
        state.batches[0].metadata.get("created_at") if state.batches else utc_now()
    )
    return {
        "schema": MANIFEST_SCHEMA,
        "batch_format_version": BATCH_VERSION,
        "created_at": created_at,
        "updated_at": utc_now(),
        "complete": state.complete,
        "source": {
            "name": "Lyncoin Core v4.0.0",
            "commit": SOURCE_COMMIT,
            "url": SOURCE_URL,
            "network_magic": NETWORK_MAGIC.hex(),
            "protocol_version": PROTOCOL_VERSION,
        },
        "scope": {
            "start_height": 0,
            "target_height": state.target_height,
            "flex_activation_height": FLEX_HEIGHT,
        },
        "validation": {
            "official_checkpoints": {str(k): v for k, v in CHECKPOINTS.items()},
            "checks": [
                "P2P network magic, payload length, and double-SHA256 checksum",
                "canonical CompactSize encodings and bounded extended-header parse",
                "genesis trust anchor and every available official source checkpoint",
                "continuous child previous-hash linkage",
                "exact Lyncoin v4 pre-Flex difficulty-transition rules",
                "chain ID, Flex activation boundary, and claimed proof of work",
                "full Namecoin-family CAuxPow merkle and coinbase commitment rules",
            ],
            "flex_boundary_limit": (
                "Height 260,500 linkage/version/chain-ID/nBits are validated; "
                "the Flex PoW hash itself is not computed."
            ),
        },
        "counts": {
            "headers": len(state.history),
            "last_height": state.last_height,
            "auxpow_headers": state.auxpow_headers,
            "solo_headers": state.solo_headers,
            "btc_difficulty_candidates": state.candidate_count,
        },
        "flex_boundary": state.flex_boundary,
        "batches": [batch.to_json() for batch in state.batches],
        "candidate_artifact": state.candidate_artifact,
    }


def write_manifest(state: RecoveryState) -> None:
    """Write ``state``'s manifest to ``output_dir/manifest.json`` atomically."""
    atomic_write_json(state.output_dir / MANIFEST_FILENAME, build_manifest(state))


def _serialize_net_address(address: str, port: int, services: int = 0) -> bytes:
    """Encode one P2P NetAddr for the ``version`` message: services, the
    address as an IPv4-mapped-IPv6 16-byte field, and a big-endian port.
    Accepts either an IPv4 or IPv6 literal.
    """
    try:
        packed = socket.inet_pton(socket.AF_INET, address)
    except OSError:
        try:
            packed = socket.inet_pton(socket.AF_INET6, address)
        except OSError as exc:
            raise RecoveryValidationError(
                f"resolved peer address is invalid: {address}"
            ) from exc
    if len(packed) == 4:
        packed = b"\x00" * 10 + b"\xff\xff" + packed
    return struct.pack("<Q", services) + packed + struct.pack(">H", port)


def _version_payload(resolved_address: str, port: int) -> bytes:
    """Build the raw ``version`` message payload sent to the peer.

    Advertises ``PROTOCOL_VERSION``, zero services, the current time, the
    peer's resolved address and a null local address, a random nonce, and
    ``USER_AGENT``, with a zero start height and relay flag unset.
    """
    payload = bytearray()
    payload.extend(struct.pack("<i", PROTOCOL_VERSION))
    payload.extend(struct.pack("<Q", 0))
    payload.extend(struct.pack("<q", int(time.time())))
    payload.extend(_serialize_net_address(resolved_address, port))
    payload.extend(_serialize_net_address("0.0.0.0", 0))
    payload.extend(secrets.token_bytes(8))
    payload.extend(encode_compact_size(len(USER_AGENT)))
    payload.extend(USER_AGENT)
    payload.extend(struct.pack("<i", 0))
    payload.extend(b"\x00")
    return bytes(payload)


def parse_version_payload(payload: bytes) -> PeerVersion:
    """Decode a peer's ``version`` message payload into a ``PeerVersion``.

    Tolerates the optional trailing user-agent/start-height/relay fields
    per the wire spec (returning ``relay=None`` if absent), and raises
    ``RecoveryValidationError`` on truncation, a non-canonical CompactSize
    user-agent length, or non-UTF-8 user-agent bytes.
    """
    if len(payload) < 80:
        raise RecoveryValidationError("peer version payload is truncated")
    protocol = struct.unpack_from("<i", payload, 0)[0]
    services = struct.unpack_from("<Q", payload, 4)[0]
    timestamp = struct.unpack_from("<q", payload, 12)[0]
    position = 80
    if position >= len(payload):
        return PeerVersion(protocol, services, timestamp, "", 0, None)

    prefix = payload[position]
    position += 1
    if prefix < 253:
        size = prefix
    elif prefix == 253:
        if position + 2 > len(payload):
            raise RecoveryValidationError("truncated version user-agent length")
        size = struct.unpack_from("<H", payload, position)[0]
        position += 2
        if size < 253:
            raise RecoveryValidationError("non-canonical version user-agent length")
    else:
        raise RecoveryValidationError("oversized version user-agent length")
    if size > 256 or position + size > len(payload):
        raise RecoveryValidationError("invalid version user-agent")
    try:
        user_agent = payload[position : position + size].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RecoveryValidationError("peer user-agent is not UTF-8") from exc
    position += size
    if position + 4 > len(payload):
        raise RecoveryValidationError("peer version lacks start height")
    start_height = struct.unpack_from("<i", payload, position)[0]
    position += 4
    relay = bool(payload[position]) if position < len(payload) else None
    return PeerVersion(
        protocol=protocol,
        services=services,
        timestamp=timestamp,
        user_agent=user_agent,
        start_height=start_height,
        relay=relay,
    )


class P2PClient:
    def __init__(self, peer: tuple[str, int], timeout: float):
        """Store the target peer and socket timeout; the connection is opened in ``__enter__``."""
        self.peer = peer
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.resolved_address = ""
        self.peer_version: PeerVersion | None = None

    def __enter__(self) -> "P2PClient":
        """Resolve the peer, connect to the first address that accepts a
        TCP connection, and perform the version/verack handshake.

        Raises ``RecoveryValidationError`` if the host cannot be resolved
        or every candidate address refuses the connection.
        """
        host, port = self.peer
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if not addresses:
            raise RecoveryValidationError(f"could not resolve peer {host}")
        last_error: OSError | None = None
        for family, socktype, proto, _, sockaddr in addresses:
            candidate = socket.socket(family, socktype, proto)
            candidate.settimeout(self.timeout)
            try:
                candidate.connect(sockaddr)
            except OSError as exc:
                last_error = exc
                candidate.close()
                continue
            self.sock = candidate
            self.resolved_address = sockaddr[0]
            break
        if self.sock is None:
            raise RecoveryValidationError(
                f"failed to connect to {format_peer(self.peer)}: {last_error}"
            )
        self._handshake()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        """Close the underlying socket if it is open."""
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def _socket(self) -> socket.socket:
        """Return the connected socket, raising ``RecoveryValidationError`` if not yet connected."""
        if self.sock is None:
            raise RecoveryValidationError("P2P socket is not connected")
        return self.sock

    def send(self, command: str, payload: bytes = b"") -> None:
        """Frame ``payload`` as a ``command`` P2P message and send it in full."""
        self._socket().sendall(encode_p2p_message(command, payload))

    def _read_exact(self, size: int) -> bytes:
        """Read exactly ``size`` bytes, raising ``RecoveryValidationError`` if the peer closes the connection early."""
        output = bytearray()
        while len(output) < size:
            chunk = self._socket().recv(size - len(output))
            if not chunk:
                raise RecoveryValidationError("peer closed the P2P connection")
            output.extend(chunk)
        return bytes(output)

    def receive(self) -> tuple[str, bytes]:
        """Read one P2P message and return ``(command, payload)``.

        Verifies the payload against its sha256d-derived checksum, raising
        ``RecoveryValidationError`` on a mismatch.
        """
        header = self._read_exact(24)
        command, payload_size, checksum = decode_p2p_header(header)
        payload = self._read_exact(payload_size)
        if sha256d(payload)[:4] != checksum:
            raise RecoveryValidationError(
                f"peer sent a {command} payload with the wrong checksum"
            )
        return command, payload

    def _receive_until(self, wanted: str) -> bytes:
        """Read messages until one with command ``wanted`` arrives, and return its payload.

        Transparently answers ``ping`` with ``pong`` and discards a fixed
        allowlist of unsolicited relay/inventory/announcement commands
        received while waiting. Raises ``RecoveryValidationError`` on a
        ``reject`` message, a malformed ``ping``, or any other unexpected
        command.
        """
        while True:
            command, payload = self.receive()
            if command == wanted:
                return payload
            if command == "ping":
                if len(payload) != 8:
                    raise RecoveryValidationError("peer sent malformed ping")
                self.send("pong", payload)
            elif command in {
                "sendaddrv2",
                "sendcmpct",
                "sendheaders",
                "wtxidrelay",
                "feefilter",
                "inv",
                "addr",
                "addrv2",
                "getheaders",
                "mempool",
            }:
                continue
            elif command == "reject":
                raise RecoveryValidationError("peer rejected the recovery request")
            elif command == "version" and wanted != "version":
                raise RecoveryValidationError("peer sent a duplicate version message")
            elif command == "verack" and wanted != "verack":
                raise RecoveryValidationError("peer sent an unexpected verack")
            else:
                raise RecoveryValidationError(
                    f"unexpected P2P command {command!r} while waiting for {wanted!r}"
                )

    def _handshake(self) -> None:
        """Perform the P2P version/verack handshake and validate the peer.

        Sends ``version``, waits for the peer's ``version``, and enforces
        protocol >= 70015, the ``NODE_NETWORK`` service bit, a reported
        tip at or past ``FLEX_HEIGHT``, and a "Lyncoin Core" user agent
        before completing the ``verack`` exchange. Raises
        ``RecoveryValidationError`` on any check failure.
        """
        host, port = self.peer
        del host
        self.send("version", _version_payload(self.resolved_address, port))
        version = parse_version_payload(self._receive_until("version"))
        if version.protocol < 70_015:
            raise RecoveryValidationError(
                f"peer protocol {version.protocol} is too old for this recovery"
            )
        if not version.services & NODE_NETWORK:
            raise RecoveryValidationError("peer does not advertise NODE_NETWORK")
        if version.start_height < FLEX_HEIGHT:
            raise RecoveryValidationError(
                f"peer tip {version.start_height} is below required boundary {FLEX_HEIGHT}"
            )
        if "Lyncoin Core" not in version.user_agent:
            raise RecoveryValidationError(
                f"peer user-agent is not Lyncoin Core: {version.user_agent!r}"
            )
        self.peer_version = version
        self.send("verack")
        self._receive_until("verack")

    def request_headers(self, locator_hash_internal: bytes) -> tuple[ParsedHeader, ...]:
        """Send ``getheaders`` with a single-hash locator and null stop hash, and return the parsed ``headers`` response.

        ``locator_hash_internal`` must be the 32-byte internal-order hash of
        the last locally validated header.
        """
        if len(locator_hash_internal) != 32:
            raise RecoveryValidationError("header locator hash must be 32 bytes")
        payload = (
            struct.pack("<i", PROTOCOL_VERSION)
            + encode_compact_size(1)
            + locator_hash_internal
            + b"\x00" * 32
        )
        self.send("getheaders", payload)
        return parse_headers_payload(self._receive_until("headers"))


def append_network_batch(
    state: RecoveryState,
    headers: tuple[ParsedHeader, ...],
    peer: tuple[str, int],
    peer_version: PeerVersion,
) -> None:
    """Validate and persist one P2P ``headers`` response as the next batch.

    Takes at most ``target_height - last_height`` headers (bounded further
    by ``MAX_HEADERS_RESULTS``), raising ``RecoveryValidationError`` if the
    response is empty or shorter than the minimum expected given how many
    heights remain. When the batch reaches ``target_height``, also
    validates and records the Flex-activation boundary proof from the
    header immediately after it. Writes the batch file (refusing to
    overwrite an existing one), appends its ``BatchInfo`` to ``state``, and
    rewrites the manifest.
    """
    if not headers:
        raise RecoveryValidationError(
            f"peer returned no headers before target height {state.target_height}"
        )
    start_height = state.next_height
    remaining = state.target_height - state.last_height
    take_count = min(remaining, len(headers))
    if take_count <= 0:
        raise RecoveryValidationError("attempted to append after target completion")
    minimum_response = min(remaining, MAX_HEADERS_RESULTS)
    if len(headers) < minimum_response:
        raise RecoveryValidationError(
            f"peer returned {len(headers)} headers, expected at least "
            f"{minimum_response} while {remaining} remain"
        )

    raw_headers: list[bytes] = []
    summaries: list[HeaderSummary] = []
    for offset, parsed in enumerate(headers[:take_count]):
        height = start_height + offset
        summary = validate_pre_flex_header(parsed, height, state.history)
        state.history.append(summary)
        if summary.has_auxpow:
            state.auxpow_headers += 1
        else:
            state.solo_headers += 1
        if candidate_row(parsed, summary) is not None:
            state.candidate_count += 1
        raw_headers.append(parsed.raw)
        summaries.append(summary)

    end_height = summaries[-1].height
    metadata: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "source": "Lyncoin P2P headers response",
        "source_commit": SOURCE_COMMIT,
        "created_at": utc_now(),
        "start_height": start_height,
        "end_height": end_height,
        "response_header_count": len(headers),
        "peer": format_peer(peer),
        "peer_version": peer_version.to_json(),
    }

    if end_height == state.target_height:
        boundary_index = take_count
        if len(headers) <= boundary_index:
            raise RecoveryValidationError(
                "final response does not include height-260,500 boundary header"
            )
        boundary = validate_flex_boundary(headers[boundary_index], state.history[-1])
        metadata["flex_boundary"] = boundary
        state.flex_boundary = boundary

    path = state.output_dir / "batches" / batch_filename(start_height, end_height)
    atomic_write_bytes(
        path,
        encode_batch(metadata, raw_headers),
        refuse_existing=True,
    )
    state.batches.append(_batch_info(path, metadata, summaries))
    write_manifest(state)


def write_candidates(state: RecoveryState) -> None:
    """Re-derive and write the self-target-PoW-candidate CSV from the fully persisted batch set.

    This is an independent re-validation pass over every stored batch
    (not a reuse of the counters accumulated during scan/append), so it
    also re-raises ``RecoveryValidationError`` if the recomputed header
    count or candidate count disagrees with ``state``. Writes atomically
    and records the resulting file's row count, size, and sha256 as
    ``state.candidate_artifact`` before rewriting the manifest. Requires
    ``state.complete``.
    """
    if not state.complete:
        raise RecoveryValidationError(
            "cannot emit candidates before recovery completes"
        )
    destination = state.output_dir / CANDIDATE_FILENAME
    temporary = destination.with_name(
        f".{destination.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp"
    )
    history: list[HeaderSummary] = []
    rows = 0
    try:
        with temporary.open("x", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=CANDIDATE_FIELDS)
            writer.writeheader()
            for batch in state.batches:
                decoded = decode_batch((state.output_dir / batch.file).read_bytes())
                start_height = _require_metadata_int(decoded.metadata, "start_height")
                for offset, raw_header in enumerate(decoded.raw_headers):
                    height = start_height + offset
                    parsed = parse_extended_header(raw_header)
                    if height == 0:
                        summary = validate_genesis(parsed)
                    else:
                        summary = validate_pre_flex_header(parsed, height, history)
                    history.append(summary)
                    row = candidate_row(parsed, summary)
                    if row is not None:
                        writer.writerow(row)
                        rows += 1
            handle.flush()
            os.fsync(handle.fileno())
        if len(history) - 1 != state.target_height:
            raise RecoveryValidationError("candidate pass did not cover target height")
        if rows != state.candidate_count:
            raise RecoveryValidationError(
                f"candidate pass produced {rows}, expected {state.candidate_count}"
            )
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass

    state.candidate_artifact = {
        "file": destination.name,
        "rows": rows,
        "size_bytes": destination.stat().st_size,
        "sha256": sha256_file(destination),
        "schema": CANDIDATE_FIELDS,
        "consumer": "scripts/classify/classify_auxpow_candidates.py",
    }
    write_manifest(state)


def recover(
    peer: tuple[str, int],
    output_dir: Path,
    timeout: float,
) -> RecoveryState:
    """Drive one full recovery run and return the final ``RecoveryState``.

    Creates the genesis batch if missing, revalidates every persisted
    batch from disk (resumable — no network needed if already complete),
    then, while short of ``AUXPOW_END_HEIGHT``, connects to ``peer`` and
    pages through ``getheaders`` until the target height and Flex boundary
    proof are reached. Writes the candidate CSV once complete, reusing an
    already-verified artifact if the manifest and CSV on disk still match.
    Raises ``RecoveryValidationError`` if the target is reached without a
    valid Flex boundary proof.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    create_genesis_batch(output_dir)
    state = scan_batches(output_dir, AUXPOW_END_HEIGHT)
    write_manifest(state)

    print(
        f"Validated local recovery through height {state.last_height:,} "
        f"({len(state.batches)} atomic batches)"
    )
    if state.last_height < state.target_height:
        print(f"Connecting to {format_peer(peer)}")
        with P2PClient(peer, timeout) as client:
            if client.peer_version is None:
                raise RecoveryValidationError(
                    "peer handshake did not produce version data"
                )
            print(
                f"Peer {client.peer_version.user_agent} reports height "
                f"{client.peer_version.start_height:,}"
            )
            while state.last_height < state.target_height:
                headers = client.request_headers(state.history[-1].hash_internal)
                append_network_batch(
                    state,
                    headers,
                    peer,
                    client.peer_version,
                )
                print(
                    f"Saved and validated heights through {state.last_height:,} "
                    f"({state.candidate_count:,} self-target-PoW candidates)"
                )

    if not state.complete:
        raise RecoveryValidationError("target reached without Flex boundary proof")
    if state.candidate_artifact is None:
        write_candidates(state)
        print(
            f"Wrote {state.candidate_count:,} candidates to "
            f"{output_dir / CANDIDATE_FILENAME}"
        )
    else:
        print(f"Candidate artifact already verified: {output_dir / CANDIDATE_FILENAME}")
    print(f"Manifest: {output_dir / MANIFEST_FILENAME}")
    return state


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser for ``--peer``/``--output-dir``/``--timeout``."""
    parser = argparse.ArgumentParser(
        description=(
            "Recover and validate Lyncoin heights 0..260499 from raw P2P "
            "extended headers"
        )
    )
    parser.add_argument(
        "--peer",
        required=True,
        type=parse_peer,
        metavar="HOST[:PORT]",
        help="explicit Lyncoin NODE_NETWORK peer (default port when omitted: 5054)",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="recovery directory for atomic batches, manifest, and candidate CSV",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="socket connect/read timeout in seconds (default: 120)",
    )
    return parser


def main() -> None:
    """Parse CLI args and run ``recover``, exiting with status 1 on ``OSError`` or ``RecoveryValidationError``."""
    args = build_parser().parse_args()
    if args.timeout <= 0:
        raise SystemExit("--timeout must be positive")
    try:
        recover(args.peer, args.output_dir.expanduser().resolve(), args.timeout)
    except (OSError, RecoveryValidationError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
