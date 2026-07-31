"""Shared synthetic-header helpers for the error-block sweep tests.

The four sweep test modules (``test_sweep_error_blocks``,
``test_sweep_error_blocks_version_bip``,
``test_sweep_error_blocks_coinbase_form``,
``test_sweep_error_blocks_time_rule``) build synthetic 80-byte Bitcoin
headers and BIP34 coinbase scriptSig prefixes. The byte-identical helpers
live here once; each test module keeps its own ``_row`` builder (the
inventory row shape differs per sweep) and, where its header layout differs
(the rejected-rows and time-rule sweeps use a different ``_header_hex``
signature), its own local ``_header_hex``.
"""

from __future__ import annotations


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
