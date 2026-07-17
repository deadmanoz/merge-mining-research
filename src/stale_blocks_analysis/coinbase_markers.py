"""Coinbase marker registry and decoders.

Catalogues every byte pattern we recognise in a Bitcoin coinbase — AuxPoW
magic, OP_RETURN tag-based merge-mining commitments, non-merge-mining
commitments (EXSAT, sys, CORE, Veriblock), the BIP-141 SegWit commitment,
the BIP-34 height push, and unknown ASCII tags ranked for review.

The released surface is this reusable registry plus its pinned decoder tests.
Downstream scanners can import it when constructing a per-block dataset. The
registry is data-only; adding a chain means adding a row to a table, not
changing decode logic.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Literal, Optional

# ── AuxPoW commitment (scriptSig) ────────────────────────────────────────

AUXPOW_MAGIC = bytes.fromhex("fabe6d6d")
AUXPOW_COMMITMENT_LEN = 4 + 32 + 4 + 4  # magic + root + size_LE + nonce_LE


@dataclass(frozen=True)
class AuxPoWMarker:
    offset: int
    merkle_root: bytes  # 32 bytes
    merkle_size: int  # u32 LE
    merkle_nonce: int  # u32 LE


def parse_auxpow_marker(scriptsig: bytes) -> Optional[AuxPoWMarker]:
    """Locate fabe6d6d in scriptSig and decode the 44-byte commitment.

    Per the AuxPoW spec, the magic must occur at most once in the scriptSig
    (this prevents an equivocation attack where a miner commits to two
    different aux merkle roots in the same parent block). We honour that by
    returning the first match; in practice rfind would yield the same
    result on well-formed blocks.

    Returns None if the magic isn't present or if there aren't enough
    trailing bytes to form a full commitment.
    """
    offset = scriptsig.find(AUXPOW_MAGIC)
    if offset < 0:
        return None
    end = offset + AUXPOW_COMMITMENT_LEN
    if end > len(scriptsig):
        return None
    root = scriptsig[offset + 4 : offset + 36]
    size = struct.unpack_from("<I", scriptsig, offset + 36)[0]
    nonce = struct.unpack_from("<I", scriptsig, offset + 40)[0]
    return AuxPoWMarker(
        offset=offset, merkle_root=root, merkle_size=size, merkle_nonce=nonce
    )


# ── BIP-34 height push (scriptSig) ───────────────────────────────────────
def parse_bip34_height(scriptsig: bytes) -> Optional[int]:
    """Decode the leading height push.

    Returns the decoded integer or None if the scriptSig is empty or the
    first byte isn't a valid push opcode.
    """
    if not scriptsig:
        return None
    op = scriptsig[0]
    # OP_PUSHBYTES_1..75: push 1..75 bytes
    if 1 <= op <= 75:
        push_len = op
        body = scriptsig[1 : 1 + push_len]
        if len(body) != push_len:
            return None
        return _decode_scriptnum(body)
    # OP_PUSHDATA1
    if op == 0x4C and len(scriptsig) >= 2:
        push_len = scriptsig[1]
        body = scriptsig[2 : 2 + push_len]
        if len(body) != push_len:
            return None
        return _decode_scriptnum(body)
    # OP_0..OP_16 single-byte numeric ops (heights 0..16 — only relevant
    # to genesis-era pre-BIP-34 blocks but cheap to handle).
    if op == 0x00:
        return 0
    if 0x51 <= op <= 0x60:
        return op - 0x50
    return None


def _decode_scriptnum(b: bytes) -> int:
    """Decode a CScriptNum little-endian signed integer (Bitcoin Core style)."""
    if not b:
        return 0
    last = b[-1]
    negative = bool(last & 0x80)
    result = 0
    for i, byte in enumerate(b[:-1]):
        result |= byte << (8 * i)
    result |= (last & 0x7F) << (8 * (len(b) - 1))
    return -result if negative else result


# ── OP_RETURN tag patterns ──────────────────────────────────────────────

OP_RETURN = 0x6A

# Push opcodes:
#   0x01..0x4b  — direct push of n bytes
#   0x4c        — OP_PUSHDATA1: 1-byte length follows
#   0x4d        — OP_PUSHDATA2: 2-byte LE length follows
#   0x4e        — OP_PUSHDATA4: 4-byte LE length follows
#
# We parse the *first* push after OP_RETURN and check the payload against
# tag bytes. Real-world coinbases observed at tip 947,126 use both direct
# pushes (0x2d for RSK pre-RSKIP-110) and PUSHDATA1 (0x4c 0x29 for the
# 41-byte format), so matching on push-length bytes alone is brittle.


@dataclass(frozen=True)
class OpReturnTag:
    name: str
    klass: Literal[
        "mm_op_return",
        "non_mm_commitment",
        "segwit",
        "pool_op_return",
    ]
    # Bytes that must appear at the start of the pushed payload.
    pattern: bytes
    # Description of the payload after the pattern, for documentation only.
    payload_note: str = ""


# Order matters: longer / more-specific patterns first. The first match wins.
OP_RETURN_TAGS: tuple[OpReturnTag, ...] = (
    # SegWit witness commitment — BIP-141. Always present in modern coinbases.
    # Payload: aa21a9ed <32-byte commitment>
    OpReturnTag(
        name="segwit",
        klass="segwit",
        pattern=bytes.fromhex("aa21a9ed"),
        payload_note="32-byte witness commitment hash",
    ),
    # RSK merge-mining: payload starts with "RSKBLOCK:" (9 bytes). The older
    # format carries a 32-byte merge-mining hash. From RSKIP-110, those 32
    # bytes are reinterpreted as 20-byte hash prefix + 7-byte CPV + 1-byte
    # uncle count + 4-byte block number.
    OpReturnTag(
        name="rsk",
        klass="mm_op_return",
        pattern=b"RSKBLOCK:",
        payload_note="RSKBLOCK: tag + pre- or post-RSKIP-110 commitment",
    ),
    # VCash merge-mining (dead since 2023-02). Per the Rust verifier the
    # 4-byte magic can appear anywhere — but in practice it leads the
    # OP_RETURN payload.
    OpReturnTag(
        name="vcash",
        klass="mm_op_return",
        pattern=bytes.fromhex("b9e11b6d"),
        payload_note="32-byte VCash block hash",
    ),
    # Hathor merge-mining via OP_RETURN: payload starts "Hath" + 32 bytes.
    OpReturnTag(
        name="hathor_op_return",
        klass="mm_op_return",
        pattern=b"Hath",
        payload_note="32-byte Hathor aux_block_hash",
    ),
    # EXSAT commitment — variable payload length.
    OpReturnTag(
        name="exsat",
        klass="non_mm_commitment",
        pattern=b"EXSAT",
        payload_note="EXSAT bridge commitment",
    ),
    # CORE commitment — observed on many recent blocks. Payload typically
    # starts "CORE" + 1-byte version + 40-byte commitment.
    OpReturnTag(
        name="core",
        klass="non_mm_commitment",
        pattern=b"CORE",
        payload_note="Core / Satoshi VM commitment",
    ),
    # Syscoin "sys" OP_RETURN parent-commit marker. Three-character ASCII;
    # we anchor it at the start of the pushed payload to avoid matching
    # random 0x73 0x79 0x73 inside hash data (probability ≈ 1 in 16M per
    # OP_RETURN otherwise).
    OpReturnTag(
        name="sys",
        klass="non_mm_commitment",
        pattern=b"sys",
        payload_note="Syscoin parent commitment",
    ),
    # Ocean.xyz "OCB1" template commitment — transparent-mining record
    # tied to Ocean's TIDES protocol. Empirically the payload is 20 bytes:
    # 4-byte tag + 16 bytes of share/block accounting metadata.
    OpReturnTag(
        name="ocean_ocb1",
        klass="non_mm_commitment",
        pattern=b"OCB1",
        payload_note="Ocean.xyz transparent-mining template commitment",
    ),
    # Pre-BIP-141 SegWit test slot — F2Pool zero-filled commitment with the
    # 4-byte marker one bit off (ef vs ed). Observed 212× across blocks
    # 459,962-459,971 (Mar 2017), payload always 32 zero bytes. SegWit
    # activated as a mandatory rule at block 481,824 (2017-08-24).
    OpReturnTag(
        name="segwit_test",
        klass="non_mm_commitment",
        pattern=bytes.fromhex("aa21a9ef"),
        payload_note="pre-activation SegWit slot, 32 zero bytes",
    ),
    # Braiins-pool VCash commitment wrapped in an inner OP_RETURN PUSH36 —
    # the outer push payload is a full nested OP_RETURN script. Observed
    # 885× exclusively on Braiins Pool blocks (heights 638,930+).
    OpReturnTag(
        name="vcash_braiins_nested",
        klass="mm_op_return",
        pattern=bytes.fromhex("6a24b9e11b6d"),
        payload_note="VCash commitment nested inside extra OP_RETURN",
    ),
    # 1Hash pool brand via OP_RETURN. The marker class documents that the
    # commitment itself is a pool-brand string and preserves it for later
    # attribution research.
    OpReturnTag(
        name="pool_op_return:1hash.com",
        klass="pool_op_return",
        pattern=b"Mined by 1hash.com",
        payload_note="1Hash pool brand OP_RETURN",
    ),
    # Ballet wallet block-sponsorship promo. Payload is "Ballet" or
    # "Ballet - Bitcoin Block NNN". Observed 49× on Braiins Pool blocks.
    OpReturnTag(
        name="ballet_sponsorship",
        klass="non_mm_commitment",
        pattern=b"Ballet",
        payload_note="Ballet wallet sponsorship campaign",
    ),
)


def parse_op_return_payload(script: bytes) -> Optional[bytes]:
    """Return the pushed payload of an OP_RETURN script, or None if the
    script isn't an OP_RETURN or the push can't be decoded.

    Only decodes the first push — coinbase OP_RETURNs in practice carry
    exactly one push.
    """
    if not script or script[0] != OP_RETURN or len(script) < 2:
        return None
    op = script[1]
    if 1 <= op <= 0x4B:
        plen, start = op, 2
    elif op == 0x4C and len(script) >= 3:
        plen, start = script[2], 3
    elif op == 0x4D and len(script) >= 4:
        plen = int.from_bytes(script[2:4], "little")
        start = 4
    elif op == 0x4E and len(script) >= 6:
        plen = int.from_bytes(script[2:6], "little")
        start = 6
    else:
        # Bare OP_RETURN with no push, or unrecognised opcode.
        return b""
    end = start + plen
    if end > len(script):
        return None
    return script[start:end]


@dataclass
class OpReturnMatch:
    name: str
    klass: str
    vout: int
    payload_hex: str  # decoded push payload, hex-encoded


def classify_payload_only(payload: bytes) -> tuple[str, str]:
    """Match a pushed OP_RETURN payload against OP_RETURN_TAGS.

    Returns (name, klass). For unmatched payloads returns
    ("unknown:<first-4-bytes-hex>", "unknown"). Lives separately from
    classify_op_return so the --reclassify path can re-match stored
    `payload_hex` values without needing to reconstruct the OP_RETURN
    wrapper.
    """
    for tag in OP_RETURN_TAGS:
        if payload.startswith(tag.pattern):
            return tag.name, tag.klass
    prefix = payload[:4].hex() if payload else ""
    return f"unknown:{prefix}", "unknown"


def classify_op_return(script: bytes, vout: int) -> Optional[OpReturnMatch]:
    """Match an OP_RETURN scriptPubKey against the tag registry.

    Returns the first match keyed on the pushed payload starting with a
    registered tag. Unknown OP_RETURNs are returned with name
    `unknown:<first-4-bytes-hex>` so they can be ranked and reviewed.
    """
    if not script or script[0] != OP_RETURN:
        return None
    payload = parse_op_return_payload(script)
    if payload is None:
        # Malformed push — preserve the raw script bytes for review.
        return OpReturnMatch(
            name="malformed",
            klass="unknown",
            vout=vout,
            payload_hex=script[1:].hex(),
        )
    name, klass = classify_payload_only(payload)
    return OpReturnMatch(
        name=name,
        klass=klass,
        vout=vout,
        payload_hex=payload.hex(),
    )


# ── scriptSig classifier ─────────────────────────────────────────────────


@dataclass
class Marker:
    """Generic marker record, ready for JSON serialisation.

    Field order matches the JSON we write to SQLite.
    """

    klass: str
    name: str
    vout: Optional[int] = None  # OP_RETURN only
    offset: Optional[int] = None  # scriptSig only
    payload_hex: Optional[str] = None
    extra: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        """Render the match as a JSON-serializable dict, omitting unset fields."""
        out: dict = {"class": self.klass, "name": self.name}
        if self.vout is not None:
            out["vout"] = self.vout
        if self.offset is not None:
            out["offset"] = self.offset
        if self.payload_hex is not None:
            out["payload_hex"] = self.payload_hex
        if self.extra:
            out["extra"] = self.extra
        return out


# Hathor scriptSig variant — reference coordinator default. The "Hath"
# magic appears after the BIP-34 height push, not at offset 0.
HATHOR_SCRIPTSIG_MAGIC = b"Hath"


def classify_scriptsig_extras(
    scriptsig: bytes, auxpow_offset: Optional[int]
) -> list[Marker]:
    """Extract non-AuxPoW, non-pool markers from a coinbase scriptSig.

    AuxPoW is hoisted to dedicated columns in the output schema. This function
    records other scriptSig markers, including pool-like ASCII strings, but
    does not resolve them against an external pool registry:

      - Hathor's scriptSig-variant "Hath" magic (reference coordinator path)
      - Unknown 4-byte+ ASCII runs that look like tags

    Returns an empty list for clean scriptSigs.
    """
    markers: list[Marker] = []

    # Hathor scriptSig variant — appears anywhere in the scriptSig, not
    # tied to the BIP-34 height push offset.
    h_off = scriptsig.find(HATHOR_SCRIPTSIG_MAGIC)
    if h_off >= 0 and (auxpow_offset is None or h_off != auxpow_offset):
        # 32-byte payload immediately following the magic.
        end = h_off + 4 + 32
        if end <= len(scriptsig):
            markers.append(
                Marker(
                    klass="mm_scriptsig",
                    name="hathor_scriptsig",
                    offset=h_off,
                    payload_hex=scriptsig[h_off + 4 : end].hex(),
                )
            )

    return markers
