from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from stale_blocks_analysis.auxpow_child_heights import (
    ChildChainRpc,
    normalize_auxpow_child_heights,
    resolve_rpc_auth,
)


FIELDS = [
    "child_height",
    "child_block_hash",
    "child_block_hash_display",
    "child_version",
    "child_block_time",
    "btc_hash",
]

CHILD_TIME = 1_700_000_000


class FakeRpc:
    def __init__(self, responses: dict[tuple[str, tuple[Any, ...]], Any]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def call(self, method: str, params: list | None = None) -> Any:
        key = (method, tuple(params or []))
        self.calls.append(key)
        return self.responses[key]


def _child_hashes(version: int, *, nonce: int = 1) -> tuple[str, str]:
    header = (
        version.to_bytes(4, "little", signed=False)
        + b"\x11" * 32
        + b"\x22" * 32
        + (1_700_000_000).to_bytes(4, "little")
        + bytes.fromhex("1d00ffff")[::-1]
        + nonce.to_bytes(4, "little")
    )
    internal = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    return internal.hex(), internal[::-1].hex()


def _write_candidates(
    path: Path,
    rows: list[dict[str, str]],
    fieldnames: list[str] = FIELDS,
) -> None:
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def _candidate(version: int, *, nonce: int = 1) -> dict[str, str]:
    internal, display = _child_hashes(version, nonce=nonce)
    return {
        "child_height": "",
        "child_block_hash": internal,
        "child_block_hash_display": display,
        "child_version": str(version),
        "child_block_time": str(CHILD_TIME),
        "btc_hash": "33" * 32,
    }


@pytest.mark.parametrize(
    ("chain", "version", "height", "method", "verbose"),
    [
        ("lyncoin", (0x0B0D << 16) | 0x100 | 2, 260_499, "getblockheader", True),
        ("sixeleven", (1 << 16) | 0x100 | 2, 19_200, "getblock", False),
        ("blast", (0x00A4 << 16) | 0x100 | 2, 796_001, "getblockheader", True),
        # Doichain mainnet has nominal chain ID 2 but fStrictChainId=false.
        ("doichain", (99 << 16) | 0x100 | 2, 1, "getblockheader", True),
    ],
)
def test_resolves_exact_height_and_preserves_internal_hash(
    tmp_path: Path,
    chain: str,
    version: int,
    height: int,
    method: str,
    verbose: bool,
) -> None:
    input_path = tmp_path / "raw.csv"
    output_path = tmp_path / "resolved.csv"
    candidate = _candidate(version)
    _write_candidates(input_path, [candidate])
    display = candidate["child_block_hash_display"]
    params: tuple[Any, ...] = (display, True) if verbose else (display,)
    rpc = FakeRpc(
        {
            ("getblockcount", ()): 1_500_000,
            (method, params): {
                "hash": display,
                "height": height,
                "version": version,
                "time": CHILD_TIME,
                "confirmations": 10,
            },
            ("getblockhash", (height,)): display,
        }
    )

    summary = normalize_auxpow_child_heights(
        chain=chain,
        input_path=input_path,
        output_path=output_path,
        rpc=rpc,
    )

    row = _read_rows(output_path)[0]
    assert summary["rows_resolved"] == 1
    assert row["child_height"] == str(height)
    assert row["child_block_hash"] == candidate["child_block_hash"]
    assert row["child_block_hash_display"] == display
    assert row["child_version"] == str(version)
    assert row["child_block_time"] == str(CHILD_TIME)
    assert _read_rows(input_path)[0]["child_height"] == ""
    assert rpc.calls == [
        ("getblockcount", ()),
        (method, params),
        ("getblockhash", (height,)),
    ]
    assert not list(tmp_path.glob(".resolved.csv.*.tmp"))


def test_legacy_rpc_client_sends_single_json_object() -> None:
    payloads: list[bytes] = []

    def transport(payload: bytes) -> bytes:
        payloads.append(payload)
        return json.dumps(
            {"result": {"height": 19_200}, "error": None, "id": 0}
        ).encode()

    rpc = ChildChainRpc(
        url="http://127.0.0.1:8663",
        auth=("user", "password"),
        transport=transport,
    )

    assert rpc.call("getblock", ["44" * 32]) == {"height": 19_200}
    request = json.loads(payloads[0])
    assert isinstance(request, dict)
    assert request == {
        "jsonrpc": "1.0",
        "id": 0,
        "method": "getblock",
        "params": ["44" * 32],
    }


@pytest.mark.parametrize(
    ("rpc_updates", "error"),
    [
        ({"hash": "ff" * 32}, "RPC hash mismatch"),
        ({"version": (0x0B0D << 16) | 0x100 | 3}, "RPC version mismatch"),
        ({"height": 260_500}, "above the supported pre-Flex height"),
    ],
)
def test_failure_preserves_existing_output_atomically(
    tmp_path: Path, rpc_updates: dict[str, Any], error: str
) -> None:
    version = (0x0B0D << 16) | 0x100 | 2
    candidate = _candidate(version)
    input_path = tmp_path / "raw.csv"
    output_path = tmp_path / "resolved.csv"
    _write_candidates(input_path, [candidate])
    output_path.write_text("existing-good-output\n")
    response = {
        "hash": candidate["child_block_hash_display"],
        "height": 200_000,
        "version": version,
        "time": CHILD_TIME,
        "confirmations": 10,
    }
    response.update(rpc_updates)
    rpc = FakeRpc(
        {
            ("getblockcount", ()): 1_500_000,
            ("getblockheader", (candidate["child_block_hash_display"], True)): response,
        }
    )

    with pytest.raises(ValueError, match=error):
        normalize_auxpow_child_heights(
            chain="lyncoin",
            input_path=input_path,
            output_path=output_path,
            rpc=rpc,
        )

    assert output_path.read_text() == "existing-good-output\n"
    assert not list(tmp_path.glob(".resolved.csv.*.tmp"))


def test_midstream_failure_removes_partial_temp_and_preserves_output(
    tmp_path: Path,
) -> None:
    version = (1 << 16) | 0x100 | 2
    first = _candidate(version, nonce=1)
    second = _candidate(version, nonce=2)
    input_path = tmp_path / "raw.csv"
    output_path = tmp_path / "resolved.csv"
    _write_candidates(input_path, [first, second])
    output_path.write_text("existing-good-output\n")
    rpc = FakeRpc(
        {
            ("getblockcount", ()): 1_000_000,
            ("getblock", (first["child_block_hash_display"],)): {
                "hash": first["child_block_hash_display"],
                "height": 19_200,
                "version": version,
                "time": CHILD_TIME,
                "confirmations": 10,
            },
            ("getblockhash", (19_200,)): first["child_block_hash_display"],
            ("getblock", (second["child_block_hash_display"],)): {
                "hash": "ff" * 32,
                "height": 19_201,
                "version": version,
                "time": CHILD_TIME,
                "confirmations": 10,
            },
        }
    )

    with pytest.raises(ValueError, match="RPC hash mismatch"):
        normalize_auxpow_child_heights(
            chain="sixeleven",
            input_path=input_path,
            output_path=output_path,
            rpc=rpc,
        )

    assert output_path.read_text() == "existing-good-output\n"
    assert not list(tmp_path.glob(".resolved.csv.*.tmp"))


def test_rejects_internal_display_hash_mismatch_without_output(tmp_path: Path) -> None:
    version = (1 << 16) | 0x100 | 2
    candidate = _candidate(version)
    candidate["child_block_hash_display"] = "aa" * 32
    input_path = tmp_path / "raw.csv"
    output_path = tmp_path / "resolved.csv"
    _write_candidates(input_path, [candidate])
    rpc = FakeRpc({("getblockcount", ()): 1_000_000})

    with pytest.raises(ValueError, match="child hash byte-order mismatch"):
        normalize_auxpow_child_heights(
            chain="sixeleven",
            input_path=input_path,
            output_path=output_path,
            rpc=rpc,
        )

    assert not output_path.exists()
    assert rpc.calls == [("getblockcount", ())]


def test_rejects_populated_unresolved_child_height(tmp_path: Path) -> None:
    version = (1 << 16) | 0x100 | 2
    candidate = _candidate(version)
    candidate["child_height"] = "19200"
    input_path = tmp_path / "raw.csv"
    output_path = tmp_path / "resolved.csv"
    _write_candidates(input_path, [candidate])
    rpc = FakeRpc({("getblockcount", ()): 1_000_000})

    with pytest.raises(ValueError, match="unresolved input child_height must be blank"):
        normalize_auxpow_child_heights(
            chain="sixeleven",
            input_path=input_path,
            output_path=output_path,
            rpc=rpc,
        )

    assert not output_path.exists()


def test_requires_uniform_child_height_column(tmp_path: Path) -> None:
    version = (1 << 16) | 0x100 | 2
    candidate = _candidate(version)
    del candidate["child_height"]
    fields = [field for field in FIELDS if field != "child_height"]
    input_path = tmp_path / "raw.csv"
    output_path = tmp_path / "resolved.csv"
    _write_candidates(input_path, [candidate], fields)

    with pytest.raises(ValueError, match="missing required columns: child_height"):
        normalize_auxpow_child_heights(
            chain="sixeleven",
            input_path=input_path,
            output_path=output_path,
            rpc=FakeRpc({}),
        )

    assert not output_path.exists()


@pytest.mark.parametrize(
    ("updates", "extra_responses", "error"),
    [
        ({"confirmations": -1}, {}, "noncanonical confirmations"),
        ({"time": CHILD_TIME + 1}, {}, "RPC time mismatch"),
        (
            {},
            {("getblockhash", (19_200,)): "ff" * 32},
            "canonical hash mismatch",
        ),
    ],
)
def test_rejects_noncanonical_or_incoherent_child_block(
    tmp_path: Path,
    updates: dict[str, Any],
    extra_responses: dict[tuple[str, tuple[Any, ...]], Any],
    error: str,
) -> None:
    version = (1 << 16) | 0x100 | 2
    candidate = _candidate(version)
    input_path = tmp_path / "raw.csv"
    output_path = tmp_path / "resolved.csv"
    _write_candidates(input_path, [candidate])
    response = {
        "hash": candidate["child_block_hash_display"],
        "height": 19_200,
        "version": version,
        "time": CHILD_TIME,
        "confirmations": 10,
    }
    response.update(updates)
    responses = {
        ("getblockcount", ()): 1_000_000,
        ("getblock", (candidate["child_block_hash_display"],)): response,
        ("getblockhash", (19_200,)): candidate["child_block_hash_display"],
    }
    responses.update(extra_responses)

    with pytest.raises(ValueError, match=error):
        normalize_auxpow_child_heights(
            chain="sixeleven",
            input_path=input_path,
            output_path=output_path,
            rpc=FakeRpc(responses),
        )

    assert not output_path.exists()


def test_rejects_duplicate_canonical_child_height_atomically(tmp_path: Path) -> None:
    version = (1 << 16) | 0x100 | 2
    first = _candidate(version, nonce=1)
    second = _candidate(version, nonce=2)
    input_path = tmp_path / "raw.csv"
    output_path = tmp_path / "resolved.csv"
    _write_candidates(input_path, [first, second])
    responses: dict[tuple[str, tuple[Any, ...]], Any] = {
        ("getblockcount", ()): 1_000_000,
        ("getblockhash", (19_200,)): first["child_block_hash_display"],
    }
    for candidate in (first, second):
        responses[("getblock", (candidate["child_block_hash_display"],))] = {
            "hash": candidate["child_block_hash_display"],
            "height": 19_200,
            "version": version,
            "time": CHILD_TIME,
            "confirmations": 10,
        }
    # Let the second row pass its own canonical lookup so the duplicate-height
    # invariant, rather than the hash check, is what rejects the output.
    rpc = FakeRpc(responses)
    original_call = rpc.call

    def call(method: str, params: list | None = None) -> Any:
        if method == "getblockhash" and len(rpc.calls) >= 4:
            key = (method, tuple(params or []))
            rpc.calls.append(key)
            return second["child_block_hash_display"]
        return original_call(method, params)

    rpc.call = call  # type: ignore[method-assign]

    with pytest.raises(ValueError, match="duplicate canonical child_height"):
        normalize_auxpow_child_heights(
            chain="sixeleven",
            input_path=input_path,
            output_path=output_path,
            rpc=rpc,
        )

    assert not output_path.exists()


def test_resolves_auth_from_explicit_environment_and_config(tmp_path: Path) -> None:
    config = tmp_path / "611.conf"
    config.write_text("# generated\nrpcuser=config-user\nrpcpassword=config-pass\n")

    assert resolve_rpc_auth(
        chain="sixeleven",
        cli_user="cli-user",
        cli_password="cli-pass",
        conf_path=config,
        environ={},
    ) == ("cli-user", "cli-pass")
    assert resolve_rpc_auth(
        chain="sixeleven",
        conf_path=config,
        environ={
            "SIXELEVEN_RPC_USER": "env-user",
            "SIXELEVEN_RPC_PASSWORD": "env-pass",
        },
    ) == ("env-user", "env-pass")
    assert resolve_rpc_auth(chain="sixeleven", conf_path=config, environ={}) == (
        "config-user",
        "config-pass",
    )
