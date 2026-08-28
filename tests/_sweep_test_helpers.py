"""Shared synthetic-header helpers for the error-block sweep tests.

The four sweep test modules (``test_sweep_error_blocks``,
``test_sweep_error_blocks_version_bip``,
``test_sweep_error_blocks_coinbase_form``,
``test_sweep_error_blocks_time_rule``) build synthetic 80-byte Bitcoin
headers and BIP34 coinbase scriptSig prefixes. The byte-identical helpers
live here once, including the shared inventory-text / reader / epoch-table
fixtures. Each test module keeps its own ``_row`` builder (the inventory
row shape differs per sweep) and, where its header layout differs (the
rejected-rows and time-rule sweeps use a different ``_header_hex``
signature), its own local ``_header_hex``.
"""

from __future__ import annotations

import csv
import hashlib
import io
from collections.abc import Mapping


def _bip34_scriptsig(height: int) -> str:
    """Encode the exact ``CScript() << height`` coinbase prefix."""
    if height == 0:
        return "00"
    encoded = bytearray()
    value = height
    while value:
        encoded.append(value & 0xFF)
        value >>= 8
    if encoded[-1] & 0x80:
        encoded.append(0)
    return (bytes([len(encoded)]) + bytes(encoded)).hex()


def _header_hex(version: int, bits: str, nonce: int = 42) -> str:
    header = (
        version.to_bytes(4, "little", signed=True)
        + b"\x11" * 32
        + b"\x22" * 32
        + (1_500_000_000).to_bytes(4, "little")
        + bytes.fromhex(bits)[::-1]  # nBits is little-endian in the header
        + nonce.to_bytes(4, "little")
    )
    assert len(header) == 80
    return header.hex()


def _display_hash(header_hex: str) -> str:
    digest = hashlib.sha256(hashlib.sha256(bytes.fromhex(header_hex)).digest()).digest()
    return digest[::-1].hex()


def _inventory(rows: list[dict[str, str]], fieldnames: list[str]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def _reader(mapping: dict[str, str]):
    def read(chain: str, path: str) -> str:
        if path not in mapping:
            raise OSError(f"no such inventory: {path}")
        return mapping[path]

    return read


def _synthetic_nbits_from_rows(
    rows: list[dict[str, str]], easy_bits: str
) -> dict[int, int]:
    """An epoch table agreeing with the synthetic rows' easy-bits target.

    The contextual-row canonical-target check corroborates a row's
    ``expected_nbits`` against the epoch table at the claimed height's epoch
    start and fails closed on a disagreement. The synthetic rows use a
    trivially-met bits value, which disagrees with the REAL (hard) epoch-table
    value at these heights; map each row's epoch start to that easy target so
    the canonical-target check can pass for a full-PoW finding.
    """
    table: dict[int, int] = {}
    for row in rows:
        try:
            height = int(row["btc_height"])
        except ValueError:
            continue  # no parseable height: no epoch-start entry needed
        table[(height // 2016) * 2016] = int(easy_bits, 16)
    return table


def _synthetic_nbits_from_mapping(
    mapping: Mapping[str, str], easy_bits: str
) -> dict[int, int]:
    """Epoch table from a path→CSV-text mapping (the time-rule fixture)."""
    table: dict[int, int] = {}
    for text in mapping.values():
        for row in csv.DictReader(io.StringIO(text)):
            try:
                height = int((row.get("btc_height") or "").strip())
            except ValueError:
                continue
            table[(height // 2016) * 2016] = int(easy_bits, 16)
    return table
