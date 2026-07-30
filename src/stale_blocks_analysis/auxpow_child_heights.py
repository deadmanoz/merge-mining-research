"""Resolve provisional blk-file child records to exact RPC-backed heights.

The generic Namecoin-family blk-file extractor leaves child height blank
because disk order is not consensus order. This module validates each raw child
hash and version against a running child-chain node before atomically filling
the uniform height slot with the exact consensus height.
"""

from __future__ import annotations

import base64
import csv
import itertools
import json
import os
import tempfile
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .auxpow_chainid import hash_from_internal_hex, hash_to_display_hex


VERSION_AUXPOW = 1 << 8


@dataclass(frozen=True, slots=True)
class ChainRpcSpec:
    slug: str
    rpc_method: str
    rpc_params_include_verbose: bool
    default_rpc_url: str
    env_prefix: str
    default_conf: Path
    chain_ids: tuple[int, ...]
    minimum_height: int
    maximum_height: int | None = None
    excluded_version_mask: int = 0
    enforce_chain_id: bool = True


CHAIN_SPECS = {
    "lyncoin": ChainRpcSpec(
        slug="lyncoin",
        rpc_method="getblockheader",
        rpc_params_include_verbose=True,
        default_rpc_url="http://127.0.0.1:5053",
        env_prefix="LYNCOIN",
        default_conf=Path.home() / ".lyncoin" / "lyncoin.conf",
        chain_ids=(0x0B0D,),
        minimum_height=0,
        maximum_height=260_499,
        excluded_version_mask=0x8000,
    ),
    "sixeleven": ChainRpcSpec(
        slug="sixeleven",
        rpc_method="getblock",
        rpc_params_include_verbose=False,
        default_rpc_url="http://127.0.0.1:8663",
        env_prefix="SIXELEVEN",
        default_conf=Path.home() / ".611" / "611.conf",
        chain_ids=(1,),
        minimum_height=19_200,
    ),
    "blast": ChainRpcSpec(
        slug="blast",
        rpc_method="getblockheader",
        rpc_params_include_verbose=True,
        default_rpc_url="http://127.0.0.1:64639",
        env_prefix="BLAST",
        default_conf=Path.home() / ".blast" / "blast.conf",
        chain_ids=(0x1940, 0x00A4),
        minimum_height=1,
    ),
    "doichain": ChainRpcSpec(
        slug="doichain",
        rpc_method="getblockheader",
        rpc_params_include_verbose=True,
        default_rpc_url="http://127.0.0.1:8339",
        env_prefix="DOICHAIN",
        default_conf=Path.home() / ".doichain" / "doichain.conf",
        chain_ids=(2,),
        minimum_height=1,
        enforce_chain_id=False,
    ),
}

REQUIRED_FIELDS = {
    "child_height",
    "child_block_hash",
    "child_block_hash_display",
    "child_version",
    "child_block_time",
}


class RpcClient(Protocol):
    def call(self, method: str, params: list | None = None) -> Any:
        """Make a single JSON-RPC call and return its ``result``."""
        ...


Transport = Callable[[bytes], bytes]


class ChildChainRpc:
    """Single-request stdlib JSON-RPC client compatible with legacy 611d.

    SixEleven rejects batch-array JSON roots, including one-element batches.
    Lyncoin accepts the same standard single-request object, so both chains use
    this transport rather than the Bitcoin-specific batched client.
    """

    def __init__(
        self,
        *,
        url: str,
        auth: tuple[str, str],
        timeout: float = 30.0,
        transport: Transport | None = None,
    ) -> None:
        self.url = url
        self.auth = auth
        self.timeout = timeout
        self._transport = transport or self._urllib_transport

    def _urllib_transport(self, payload: bytes) -> bytes:
        """POST the JSON-encoded request ``payload`` with HTTP basic auth and
        return the raw response body.
        """
        user, password = self.auth
        token = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
        request = urllib.request.Request(
            self.url,
            data=payload,
            headers={
                "Authorization": f"Basic {token}",
                "content-type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return response.read()

    def call(self, method: str, params: list | None = None) -> Any:
        """Make a single JSON-RPC request and return its ``result``.

        Raises ``RuntimeError`` if the response is not a JSON object or
        carries a non-null ``error``.
        """
        request = {
            "jsonrpc": "1.0",
            "id": 0,
            "method": method,
            "params": params or [],
        }
        response = json.loads(self._transport(json.dumps(request).encode("utf-8")))
        if not isinstance(response, Mapping):
            raise RuntimeError(f"RPC returned a non-object response for {method}")
        if response.get("error") is not None:
            raise RuntimeError(f"RPC error for {method}: {response['error']}")
        return response.get("result")


def _require_hash(
    value: str | None, *, field: str, input_path: Path, row_number: int
) -> str:
    """Return ``value`` normalized to 64-char lowercase hex, or raise ``ValueError``."""
    normalized = (value or "").strip().lower()
    if len(normalized) != 64:
        raise ValueError(
            f"{input_path}:{row_number}: {field} must be 64 hex characters"
        )
    try:
        bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError(
            f"{input_path}:{row_number}: {field} must be 64 hex characters"
        ) from exc
    return normalized


def _require_int(
    value: str | int | None, *, field: str, input_path: Path, row_number: int
) -> int:
    """Parse ``value`` as an int, or raise ``ValueError`` naming the offending field/row."""
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"{input_path}:{row_number}: {field} must be an integer"
        ) from exc
    return parsed


def _version_u32(version: int) -> int:
    """Mask a signed 32-bit ``child_version`` into its unsigned uint32 form."""
    if version < -(1 << 31) or version > 0xFFFFFFFF:
        raise ValueError(f"child version is outside the 32-bit range: {version}")
    return version & 0xFFFFFFFF


def _validate_chain_version(
    version: int, spec: ChainRpcSpec, *, input_path: Path, row_number: int
) -> int:
    """Validate ``version`` carries the AuxPoW flag, any required chain ID,
    and none of ``spec.excluded_version_mask``. Returns the unsigned uint32 form.
    """
    normalized = _version_u32(version)
    if not normalized & VERSION_AUXPOW:
        raise ValueError(f"{input_path}:{row_number}: child_version has no AuxPoW flag")
    chain_id = (normalized >> 16) & 0xFFFF
    if spec.enforce_chain_id and chain_id not in spec.chain_ids:
        raise ValueError(
            f"{input_path}:{row_number}: child_version chain ID {chain_id} "
            f"does not match {spec.slug} chain IDs {spec.chain_ids}"
        )
    if spec.excluded_version_mask and normalized & spec.excluded_version_mask:
        raise ValueError(
            f"{input_path}:{row_number}: child_version uses an excluded "
            f"{spec.slug} encoding"
        )
    return normalized


def _rpc_params(spec: ChainRpcSpec, display_hash: str) -> list[Any]:
    """Build the RPC params for ``spec.rpc_method``, adding the verbose flag when required."""
    if spec.rpc_params_include_verbose:
        return [display_hash, True]
    return [display_hash]


def _resolve_row(
    row: dict[str, str],
    *,
    row_number: int,
    input_path: Path,
    spec: ChainRpcSpec,
    rpc: RpcClient,
    tip_height: int,
) -> dict[str, str]:
    """Validate one raw child row and resolve its exact consensus height via RPC.

    Every child hash byte-order pair, ``child_version`` AuxPoW/chain-ID shape,
    and ``child_block_time`` is checked before the RPC call. The RPC result
    (``spec.rpc_method`` on the display hash, then ``getblockhash`` at the
    resolved height) must agree on hash, height range, version, time, and
    canonical linkage. Returns ``row`` with ``child_height`` populated;
    raises ``ValueError`` on any mismatch.
    """
    internal_hash = _require_hash(
        row.get("child_block_hash"),
        field="child_block_hash",
        input_path=input_path,
        row_number=row_number,
    )
    display_hash = _require_hash(
        row.get("child_block_hash_display"),
        field="child_block_hash_display",
        input_path=input_path,
        row_number=row_number,
    )
    expected_display = hash_to_display_hex(hash_from_internal_hex(internal_hash))
    if display_hash != expected_display:
        raise ValueError(
            f"{input_path}:{row_number}: child hash byte-order mismatch: "
            f"internal {internal_hash} does not encode display {display_hash}"
        )

    extracted_version = _require_int(
        row.get("child_version"),
        field="child_version",
        input_path=input_path,
        row_number=row_number,
    )
    extracted_version_u32 = _validate_chain_version(
        extracted_version, spec, input_path=input_path, row_number=row_number
    )
    extracted_time = _require_int(
        row.get("child_block_time"),
        field="child_block_time",
        input_path=input_path,
        row_number=row_number,
    )
    if extracted_time < 0 or extracted_time > 0xFFFFFFFF:
        raise ValueError(
            f"{input_path}:{row_number}: child_block_time is outside the uint32 range"
        )

    result = rpc.call(spec.rpc_method, _rpc_params(spec, display_hash))
    if not isinstance(result, Mapping):
        raise ValueError(
            f"{spec.slug} RPC {spec.rpc_method} returned no object for {display_hash}"
        )
    rpc_hash = result.get("hash")
    if not isinstance(rpc_hash, str) or rpc_hash.lower() != display_hash:
        raise ValueError(
            f"{spec.slug} RPC hash mismatch for {display_hash}: got {rpc_hash!r}"
        )

    height = result.get("height")
    if isinstance(height, bool) or not isinstance(height, int):
        raise ValueError(
            f"{spec.slug} RPC returned no integer height for {display_hash}"
        )
    if height < spec.minimum_height:
        raise ValueError(
            f"{spec.slug} RPC height {height} is below the supported AuxPoW "
            f"activation height {spec.minimum_height}"
        )
    if spec.maximum_height is not None and height > spec.maximum_height:
        raise ValueError(
            f"{spec.slug} RPC height {height} is above the supported pre-Flex "
            f"height {spec.maximum_height}"
        )
    if height > tip_height:
        raise ValueError(
            f"{spec.slug} RPC height {height} is above node tip {tip_height}"
        )

    rpc_version = result.get("version")
    if isinstance(rpc_version, bool) or not isinstance(rpc_version, int):
        raise ValueError(
            f"{spec.slug} RPC returned no integer version for {display_hash}"
        )
    if _version_u32(rpc_version) != extracted_version_u32:
        raise ValueError(
            f"{spec.slug} RPC version mismatch for {display_hash}: expected "
            f"{extracted_version}, got {rpc_version}"
        )

    rpc_time = result.get("time")
    if isinstance(rpc_time, bool) or not isinstance(rpc_time, int):
        raise ValueError(f"{spec.slug} RPC returned no integer time for {display_hash}")
    if rpc_time != extracted_time:
        raise ValueError(
            f"{spec.slug} RPC time mismatch for {display_hash}: expected "
            f"{extracted_time}, got {rpc_time}"
        )

    confirmations = result.get("confirmations")
    if (
        isinstance(confirmations, bool)
        or not isinstance(confirmations, int)
        or confirmations < 0
    ):
        raise ValueError(
            f"{spec.slug} RPC reports noncanonical confirmations for "
            f"{display_hash}: {confirmations!r}"
        )

    canonical_hash = rpc.call("getblockhash", [height])
    if not isinstance(canonical_hash, str) or canonical_hash.lower() != display_hash:
        raise ValueError(
            f"{spec.slug} canonical hash mismatch at height {height}: "
            f"expected {display_hash}, got {canonical_hash!r}"
        )

    return {
        **row,
        "child_height": str(height),
        "child_block_hash": internal_hash,
        "child_block_hash_display": display_hash,
        "child_version": str(extracted_version),
        "child_block_time": str(extracted_time),
    }


def _write_csv_atomic(
    output_path: Path, fieldnames: list[str], rows: Iterable[dict[str, str]]
) -> int:
    """Write ``rows`` to ``output_path`` via a temp file + ``os.replace``.

    Fsyncs before the rename so a crash mid-write cannot leave a partial file
    at ``output_path``. On any exception the temp file is removed and the
    exception re-raised. Returns the number of rows written.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.", suffix=".tmp", dir=output_path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        rows_written = 0
        with os.fdopen(fd, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
                rows_written += 1
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary_path, output_path)
        return rows_written
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        temporary_path.unlink(missing_ok=True)
        raise


def normalize_auxpow_child_heights(
    *,
    chain: str,
    input_path: Path,
    output_path: Path,
    rpc: RpcClient,
) -> dict[str, Any]:
    """Resolve every raw child row and atomically write an exact-height CSV."""
    try:
        spec = CHAIN_SPECS[chain]
    except KeyError as exc:
        raise ValueError(f"unsupported child chain: {chain}") from exc
    if input_path.resolve() == output_path.resolve():
        raise ValueError("input and output paths must differ")

    with input_path.open(newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        if len(fieldnames) != len(set(fieldnames)):
            raise ValueError(f"{input_path}: contains duplicate column names")
        missing = REQUIRED_FIELDS - set(fieldnames)
        if missing:
            raise ValueError(
                f"{input_path}: missing required columns: {', '.join(sorted(missing))}"
            )
        first_row = next(reader, None)
        if first_row is None:
            raise ValueError(f"{input_path}: contains no candidate rows")
        if first_row.get("child_height"):
            raise ValueError(
                f"{input_path}: unresolved input child_height must be blank"
            )

        tip_height = rpc.call("getblockcount")
        if isinstance(tip_height, bool) or not isinstance(tip_height, int):
            raise ValueError(f"{spec.slug} RPC getblockcount returned no integer tip")
        if tip_height < 0:
            raise ValueError(f"{spec.slug} RPC getblockcount returned a negative tip")

        seen_hashes: set[str] = set()
        seen_heights: set[int] = set()

        def resolved_rows() -> Iterable[dict[str, str]]:
            """Yield rows, rejecting duplicate child hashes or resolved heights."""
            for row_number, row in enumerate(
                itertools.chain((first_row,), reader), start=2
            ):
                if row.get("child_height"):
                    raise ValueError(
                        f"{input_path}:{row_number}: unresolved input child_height "
                        "must be blank"
                    )
                resolved = _resolve_row(
                    row,
                    row_number=row_number,
                    input_path=input_path,
                    spec=spec,
                    rpc=rpc,
                    tip_height=tip_height,
                )
                internal_hash = resolved["child_block_hash"]
                height = int(resolved["child_height"])
                if internal_hash in seen_hashes:
                    raise ValueError(
                        f"{input_path}:{row_number}: duplicate child_block_hash "
                        f"{internal_hash}"
                    )
                if height in seen_heights:
                    raise ValueError(
                        f"{input_path}:{row_number}: duplicate canonical "
                        f"child_height {height}"
                    )
                seen_hashes.add(internal_hash)
                seen_heights.add(height)
                yield resolved

        rows_resolved = _write_csv_atomic(output_path, fieldnames, resolved_rows())
    return {
        "chain": spec.slug,
        "rows_resolved": rows_resolved,
        "node_tip": tip_height,
        "output": str(output_path),
    }


def resolve_rpc_auth(
    *,
    chain: str,
    cli_user: str | None = None,
    cli_password: str | None = None,
    conf_path: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> tuple[str, str]:
    """Resolve explicit, environment, or bitcoind-style config RPC auth."""
    try:
        spec = CHAIN_SPECS[chain]
    except KeyError as exc:
        raise ValueError(f"unsupported child chain: {chain}") from exc
    if bool(cli_user) != bool(cli_password):
        raise ValueError("both RPC user and RPC password must be provided together")
    if cli_user and cli_password:
        return cli_user, cli_password

    env = os.environ if environ is None else environ
    env_user = env.get(f"{spec.env_prefix}_RPC_USER")
    env_password = env.get(f"{spec.env_prefix}_RPC_PASSWORD") or env.get(
        f"{spec.env_prefix}_RPC_PASS"
    )
    if env_user and env_password:
        return env_user, env_password

    path = conf_path or spec.default_conf
    try:
        lines = path.read_text().splitlines()
    except FileNotFoundError as exc:
        raise ValueError(
            f"RPC credentials not supplied and config does not exist: {path}"
        ) from exc
    settings: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        settings[key.strip()] = value.strip()
    user = settings.get("rpcuser")
    password = settings.get("rpcpassword")
    if not user or not password:
        raise ValueError(f"rpcuser/rpcpassword missing from {path}")
    return user, password
