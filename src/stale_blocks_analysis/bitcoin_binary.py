"""Low-level Bitcoin binary parsing and address decoding.

Concerned only with bytes-to-structured-data conversions: raw block to
coinbase transaction, base58 address to hash160, and bech32 address to witness
program. These helpers have no knowledge of mining pools, stale blocks, or
analysis flow.

Checksum verification is intentionally skipped in the address decoders:
callers use the payload bytes (hash160 / witness program) to cross-reference
against a curated local dataset, not to validate arbitrary user input.
"""

import hashlib
import struct
from typing import Iterable, Optional, Sequence, Tuple, Union


def _varint(buf: bytes, off: int) -> tuple[int, int]:
    """Read a Bitcoin CompactSize integer at ``off``; return (value, new_off)."""
    b = buf[off]
    if b < 0xFD:
        return b, off + 1
    if b == 0xFD:
        return struct.unpack_from("<H", buf, off + 1)[0], off + 3
    if b == 0xFE:
        return struct.unpack_from("<I", buf, off + 1)[0], off + 5
    return struct.unpack_from("<Q", buf, off + 1)[0], off + 9


def _parse_coinbase_tx_at(raw: bytes, off: int) -> dict | None:
    """Parse a coinbase transaction starting at *off* in *raw*."""
    try:
        off += 4  # coinbase tx version
        if raw[off] == 0x00 and raw[off + 1] >= 0x01:  # segwit marker + flag
            off += 2
        nin, off = _varint(raw, off)  # input count
        # Parse inputs (just the coinbase)
        off += 36  # prev_hash(32) + prev_idx(4)
        slen, off = _varint(raw, off)  # scriptSig length
        if off + slen > len(raw):
            return None
        scriptsig = raw[off : off + slen]
        off += slen + 4  # scriptSig + sequence
        # Parse outputs
        nout, off = _varint(raw, off)
        outputs = []
        for _ in range(nout):
            value = struct.unpack_from("<Q", raw, off)[0]
            off += 8
            spk_len, off = _varint(raw, off)
            # Slicing past the end truncates silently, so a block cut short
            # inside a declared script would yield a short scriptPubKey and
            # still look parsed. Bounds-check like the scriptSig above.
            if off + spk_len > len(raw):
                return None
            spk = raw[off : off + spk_len]
            off += spk_len
            outputs.append((value, spk))
        return {"scriptsig": scriptsig, "outputs": outputs}
    except (IndexError, struct.error):
        return None


def parse_coinbase(raw: bytes) -> dict | None:
    """Parse coinbase tx from a raw block, returning scriptSig and outputs."""
    if len(raw) < 81:
        return None
    try:
        off = 80  # skip 80-byte header
        _, off = _varint(raw, off)  # tx count
    except (IndexError, struct.error):
        return None
    return _parse_coinbase_tx_at(raw, off)


def parse_coinbase_tx(raw_tx: bytes) -> dict | None:
    """Parse a raw coinbase transaction, returning scriptSig and outputs."""
    if len(raw_tx) < 10:
        return None
    return _parse_coinbase_tx_at(raw_tx, 0)


_B58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_MAP = {c: i for i, c in enumerate(_B58_CHARS)}

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_MAP = {c: i for i, c in enumerate(_BECH32_CHARSET)}


def _b58_decode_to_hash160(addr: str) -> bytes | None:
    """Decode a base58check P2PKH ('1...') or P2SH ('3...') address.

    Returns the 20-byte hash160 payload (version byte stripped, checksum
    discarded). Returns None on invalid input. Does not verify the checksum
    because the upstream dataset is curated — for audit purposes we only
    need the payload to compare against locally-stored hash160s.
    """
    try:
        n = 0
        for ch in addr:
            n = n * 58 + _B58_MAP[ch]
    except KeyError:
        return None
    full = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(addr) - len(addr.lstrip("1"))
    decoded = b"\x00" * pad + full
    if len(decoded) != 25:
        return None
    return decoded[1:-4]  # strip 1-byte version + 4-byte checksum


def _bech32_decode_to_program(addr: str) -> bytes | None:
    """Decode a bech32(m) segwit mainnet address to its witness program.

    Returns the witness program bytes (20 for P2WPKH, 32 for P2WSH/P2TR),
    or None on parse failure. Skips checksum verification because callers only
    need the program bytes to cross-reference against locally stored hash160s.
    """
    addr = addr.lower()
    if not addr.startswith("bc1") or len(addr) > 90 or len(addr) < 14:
        return None
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr):
        return None
    data_part = addr[pos + 1 : -6]  # exclude 6-char checksum
    try:
        data = [_BECH32_MAP[c] for c in data_part]
    except KeyError:
        return None
    if not data:
        return None
    program_5bit = data[1:]  # data[0] is the witness version
    acc = 0
    bits = 0
    out: list[int] = []
    for v in program_5bit:
        acc = (acc << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return bytes(out)


# ============================================================================
# Address ENCODING and coinbase-output formatting
#
# These mirror the DECODERS above (_b58_decode_to_hash160 /
# _bech32_decode_to_program). They consolidate the largest single
# address-encoding copy-paste in the extract scripts (originally inlined in
# scripts/extract/extract_bitcoin_vault_auxpow.py) plus the two coinbase-output
# formatting conventions used by the JSON-RPC and raw-hex extractors.
#
# PURE STDLIB ONLY: extract scripts run on package-less / NixOS hosts.
# ============================================================================

# bech32 / bech32m (BIP-173 / BIP-350)
_BECH32_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
_BECH32_CONST = {"bech32": 1, "bech32m": 0x2BC830A3}


def sha256d(b: bytes) -> bytes:
    """Double SHA-256, the Bitcoin block/tx hash primitive.

    The canonical definition for the package: auxpow_parse, auxpow_chainid,
    lyncoin_headers, and full_evidence all re-export or import this.
    """
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _b58_encode(data: bytes) -> str:
    """Base58-encode ``data``, preserving leading zero bytes as '1' characters."""
    n = int.from_bytes(data, "big")
    s = ""
    while n > 0:
        n, r = divmod(n, 58)
        s = _B58_CHARS[r] + s
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + s


def _b58check_encode(version: int, payload: bytes) -> str:
    """base58check-encode a version byte + payload (with 4-byte checksum)."""
    v = bytes([version]) + payload
    return _b58_encode(v + sha256d(v)[:4])


def _bech32_polymod(values: Iterable[int]) -> int:
    """BIP-173 checksum polymod over 5-bit values."""
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= _BECH32_GENERATOR[i]
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    """Expand the human-readable part for checksum computation (BIP-173)."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp: str, data: Sequence[int], spec: str) -> list[int]:
    """Compute the six 5-bit checksum values for bech32 or bech32m."""
    values = _bech32_hrp_expand(hrp) + list(data)
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ _BECH32_CONST[spec]
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _bech32_encode(hrp: str, data: Sequence[int], spec: str) -> str:
    """Assemble a bech32/bech32m string from the HRP and 5-bit data values."""
    combined = list(data) + _bech32_create_checksum(hrp, data, spec)
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in combined)


def _convertbits(
    data: Iterable[int], frombits: int, tobits: int, pad: bool = True
) -> list[int]:
    """Regroup a bit stream (e.g. 8-bit bytes to 5-bit groups for bech32)."""
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def _encode_segwit_addr(hrp: str, witver: int, witprog: bytes) -> str:
    """Encode a segwit address: bech32 for v0 programs, bech32m otherwise."""
    spec = "bech32" if witver == 0 else "bech32m"
    data = [witver] + _convertbits(witprog, 8, 5)
    return _bech32_encode(hrp, data, spec)


def encode_btc_address(spk: bytes) -> Optional[str]:
    """Encode a BTC mainnet scriptPubKey to its address string.

    Inverse of the package decoders (_b58_decode_to_hash160 /
    _bech32_decode_to_program). Covers the five script types that account
    for effectively all BTC coinbase outputs:

      P2PKH  -> base58check '1...'
      P2SH   -> base58check '3...'
      P2PK   -> base58check '1...' (hash160 of the pubkey)
      P2WPKH -> bech32  'bc1q...'
      P2WSH  -> bech32  'bc1q...'
      P2TR   -> bech32m 'bc1p...'

    Returns None for OP_RETURN / nonstandard / unrecognised scripts. Callers
    that want a passthrough label (e.g. 'OP_RETURN') should handle the None.
    """
    L = len(spk)
    # P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    if L == 25 and spk[0:3] == b"\x76\xa9\x14" and spk[23:25] == b"\x88\xac":
        return _b58check_encode(0x00, spk[3:23])
    # P2SH: OP_HASH160 <20> OP_EQUAL
    if L == 23 and spk[0:2] == b"\xa9\x14" and spk[22] == 0x87:
        return _b58check_encode(0x05, spk[2:22])
    # P2PK: <33> OP_CHECKSIG (compressed)
    if L == 35 and spk[0] == 0x21 and spk[34] == 0xAC:
        h160 = hashlib.new("ripemd160", hashlib.sha256(spk[1:34]).digest()).digest()
        return _b58check_encode(0x00, h160)
    # P2PK: <65> OP_CHECKSIG (uncompressed)
    if L == 67 and spk[0] == 0x41 and spk[66] == 0xAC:
        h160 = hashlib.new("ripemd160", hashlib.sha256(spk[1:66]).digest()).digest()
        return _b58check_encode(0x00, h160)
    # P2WPKH: OP_0 <20>
    if L == 22 and spk[0:2] == b"\x00\x14":
        return _encode_segwit_addr("bc", 0, spk[2:22])
    # P2WSH: OP_0 <32>
    if L == 34 and spk[0:2] == b"\x00\x20":
        return _encode_segwit_addr("bc", 0, spk[2:34])
    # P2TR: OP_1 <32> (BIP-341, OP_1 = 0x51)
    if L == 34 and spk[0:2] == b"\x51\x20":
        return _encode_segwit_addr("bc", 1, spk[2:34])
    return None


# Output rows arrive in several shapes across the extractors:
#   * (value, spk) tuples           — parse_coinbase() in this module
#   * {"value", "spk"}              — extract_bitcoin_vault_auxpow.py
#   * {"value", "pkscript"}         — raw-hex extractors (devcoin / blkdat)
#   * {"value", "scriptPubKey": {"address"/"type"}} — JSON-RPC extractors
_Output = Union[Tuple[int, bytes], dict]


def _output_value_spk(out: _Output) -> Tuple[int, Optional[bytes]]:
    """Normalise a heterogeneous output row to (value, spk_bytes_or_None)."""
    if isinstance(out, (tuple, list)):
        value, spk = out[0], out[1]
        return value, spk
    value = out.get("value", 0)
    spk = out.get("spk")
    if spk is None:
        spk = out.get("pkscript")
    return value, spk


def format_outputs_addr(outputs: Iterable[_Output]) -> str:
    """Format coinbase outputs as 'addr:value | addr:value' (pipe-joined).

    This is the JSON-RPC extractors' convention (e.g.
    extract_syscoin_auxpow.py format_outputs). When an output row carries a
    pre-decoded scriptPubKey dict (JSON-RPC shape), its 'address'/'type'
    fields are used directly; otherwise the scriptPubKey bytes are encoded
    with encode_btc_address(), falling back to 'OP_RETURN' for nulldata
    scripts and the raw script hex for anything nonstandard.
    """
    parts: list[str] = []
    for out in outputs:
        if isinstance(out, dict) and "scriptPubKey" in out:
            spk_meta = out.get("scriptPubKey") or {}
            value = out.get("value", 0)
            addr = spk_meta.get("address", "")
            typ = spk_meta.get("type", "")
            if addr:
                parts.append(f"{addr}:{value}")
            elif typ == "nulldata":
                parts.append(f"OP_RETURN:{value}")
            else:
                parts.append(f"{typ}:{value}")
            continue
        value, spk = _output_value_spk(out)
        if spk is None:
            parts.append(f":{value}")
            continue
        addr = encode_btc_address(spk)
        if addr is None:
            if len(spk) >= 1 and spk[0] == 0x6A:
                addr = "OP_RETURN"
            else:
                addr = f"nonstandard:{spk.hex()}"
        parts.append(f"{addr}:{value}")
    return "|".join(parts)


def format_outputs_pkhex(outputs: Iterable[_Output]) -> str:
    """Format coinbase outputs as ';'-joined raw scriptPubKey hex.

    This is the raw-hex extractors' convention (e.g.
    extract_devcoin_auxpow.py / extract_auxpow_from_blkdat.py), which preserves
    the raw pkscript hex for later attribution research.
    """
    parts: list[str] = []
    for out in outputs:
        _, spk = _output_value_spk(out)
        if spk is None:
            continue
        parts.append(spk.hex())
    return ";".join(parts)
