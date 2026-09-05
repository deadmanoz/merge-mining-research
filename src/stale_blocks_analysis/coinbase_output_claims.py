"""Semantic reconciliation for heterogeneous Bitcoin coinbase outputs.

Source datasets preserve different projections of the same ordered output
vector.  Some contain exact scripts without amounts, some contain decoded
addresses and BTC-denominated amounts, and some contain only an ``OP_RETURN``
type claim.  This module converts each projection into compatible per-position
claims before choosing a publication representation.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from decimal import Decimal, InvalidOperation
from functools import lru_cache
from typing import Iterable

from .bitcoin_binary import (
    _bech32_decode_to_program,
    canonical_output_token,
    parse_coinbase_tx,
)

_P2PKH_VERSIONS = frozenset({0, 52, 63})  # Bitcoin, Namecoin, Syscoin
_P2SH_VERSIONS = frozenset({5, 13})  # Bitcoin, Namecoin

# Chains whose legacy acquisition kept only the outputs the child node could
# name, so a legacy address-only cell from them is an ordered filtered
# projection rather than a complete output vector. Namecoin is the only such
# acquisition: Terracoin, Bitcoin Vault, and Syscoin retained a placeholder
# for every output they could not name, so their legacy cells are
# positionally complete.
FILTERED_ACQUISITION_CHAINS = frozenset({"namecoin"})

# Chains whose legacy cells carry the child node's *decoded addresses* rather
# than script bytes we hold. Such a decode renders a P2PK output as the same
# address as a P2PKH paying its pubkey's hash160 (verified: the Terracoin
# decode of BTC 00000000...67a249's output 1 collapses the P2PK script that
# Devcoin and Unobtanium hold in raw hex to 1Kz5Qa...), so an address in a
# legacy cell establishes only the recipient hash160 even in Bitcoin's own
# version-0 form. Bitcoin Vault is deliberately absent: its extraction
# binary-parses raw block hex, so its addresses render scripts it holds.
CHILD_DECODED_ACQUISITION_CHAINS = frozenset({"namecoin", "syscoin", "terracoin"})
# Legacy RPC producers wrote ``<scriptPubKey.type>:<value>`` placeholders for
# addressless outputs. Template types imply a script prefix, which preserves
# more than an amount-only claim; the rest establish only the amount. The
# label itself survives in the archived cell either way.
_LEGACY_TYPE_LABEL_PREFIXES = {
    "pubkeyhash": "76a914",
    "scripthash": "a914",
    "nulldata": "6a",
    "witness_v0_keyhash": "0014",
    "witness_v0_scripthash": "0020",
    "witness_v1_taproot": "5120",
}
_LEGACY_TYPE_LABELS_VALUE_ONLY = frozenset({"multisig", "witness_unknown"})
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2})+")
_UINT64_MAX = (1 << 64) - 1
_SATOSHIS_PER_BTC = Decimal(100_000_000)


def _normalized_hex(value: str, *, label: str) -> str:
    normalized = value.strip().lower()
    if not _HEX_RE.fullmatch(normalized):
        raise ValueError(f"{label} is not non-empty even-length hex: {value!r}")
    return normalized


@dataclass(frozen=True, slots=True)
class CoinbaseOutputClaim:
    """A partial claim about one output in an ordered coinbase transaction.

    ``script_hex`` is an exact scriptPubKey. ``script_prefix_hex`` is a weaker
    byte-prefix constraint, currently used when a decoded source exposes only
    the ``OP_RETURN`` output type. ``recipient_hash160`` preserves the
    destination claim exposed by legacy ``scriptPubKey.addresses`` output. A
    P2PKH-style address can describe either an exact P2PKH script or an exact
    P2PK script whose public key hashes to the same recipient.
    ``position_exact=False`` means ``position`` is only the claim's order in a
    filtered legacy address projection. Such claims must match an ordered
    subsequence of an exact output vector. A claim may know only an amount,
    only a script/destination constraint, or both.
    """

    position: int
    value_sats: int | None = None
    script_hex: str = ""
    script_prefix_hex: str = ""
    recipient_hash160: str = ""
    position_exact: bool = True

    def __post_init__(self) -> None:
        if self.position < 0:
            raise ValueError("coinbase output position must be non-negative")
        if self.value_sats is not None and not 0 <= self.value_sats <= _UINT64_MAX:
            raise ValueError("coinbase output value is outside uint64 range")

        script_hex = self.script_hex.strip().lower()
        prefix_hex = self.script_prefix_hex.strip().lower()
        recipient_hash160 = self.recipient_hash160.strip().lower()
        if script_hex:
            script_hex = _normalized_hex(script_hex, label="scriptPubKey")
        if prefix_hex:
            prefix_hex = _normalized_hex(prefix_hex, label="scriptPubKey prefix")
        if recipient_hash160:
            if not re.fullmatch(r"[0-9a-f]{40}", recipient_hash160):
                raise ValueError("recipient HASH160 must be exactly 20-byte hex")
        if script_hex and prefix_hex and not script_hex.startswith(prefix_hex):
            raise ValueError(
                f"exact script {script_hex!r} does not satisfy prefix {prefix_hex!r}"
            )
        if recipient_hash160 and script_hex:
            script_recipient = recipient_hash160_for_script(script_hex)
            if script_recipient != recipient_hash160:
                raise ValueError(
                    "exact script does not pay the claimed recipient HASH160"
                )
        if recipient_hash160 and prefix_hex and not script_hex:
            raise ValueError(
                "recipient HASH160 cannot be combined with only a script prefix"
            )
        if (
            self.value_sats is None
            and not script_hex
            and not prefix_hex
            and not recipient_hash160
        ):
            raise ValueError("coinbase output claim carries no evidence")
        object.__setattr__(self, "script_hex", script_hex)
        object.__setattr__(self, "script_prefix_hex", prefix_hex)
        object.__setattr__(self, "recipient_hash160", recipient_hash160)


def _hash160(payload: bytes) -> str:
    return hashlib.new("ripemd160", hashlib.sha256(payload).digest()).hexdigest()


def recipient_hash160_for_script(script_hex: str) -> str:
    """Return the recipient HASH160 encoded by P2PKH or P2PK, else blank."""
    script = bytes.fromhex(script_hex)
    if (
        len(script) == 25
        and script[:3] == b"\x76\xa9\x14"
        and script[-2:] == b"\x88\xac"
    ):
        return script[3:23].hex()
    if (
        len(script) in (35, 67)
        and script[0] in (33, 65)
        and len(script) == script[0] + 2
        and script[-1] == 0xAC
    ):
        public_key = script[1:-1]
        if (len(public_key) == 33 and public_key[0] in (2, 3)) or (
            len(public_key) == 65 and public_key[0] == 4
        ):
            return _hash160(public_key)
    return ""


def _b58_decode_versioned(addr: str) -> tuple[int, bytes] | None:
    """Return the version byte and payload of a valid base58check address."""
    num = 0
    for char in addr:
        index = _B58_ALPHABET.find(char)
        if index < 0:
            return None
        num = num * 58 + index
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(addr) - len(addr.lstrip("1"))) + raw
    if len(raw) != 25:
        return None
    body, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != checksum:
        return None
    return raw[0], raw[1:21]


def _bech32_encoding_ok(addr: str) -> bool:
    """Return whether a lowercased bech32/bech32m address is well formed."""
    separator = addr.rfind("1")
    if separator < 1:
        return False
    hrp, data = addr[:separator], addr[separator + 1 :]
    if len(data) < 7 or any(char not in _BECH32_CHARSET for char in data):
        return False
    values = (
        [ord(char) >> 5 for char in hrp]
        + [0]
        + [ord(char) & 31 for char in hrp]
        + [_BECH32_CHARSET.index(char) for char in data]
    )
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for index in range(5):
            checksum ^= generator[index] if ((top >> index) & 1) else 0
    version = _BECH32_CHARSET.index(data[0])
    if checksum != (1 if version == 0 else 0x2BC830A3):
        return False
    leftover = (len(data[1:-6]) * 5) % 8
    if leftover >= 5:
        return False
    return not (leftover and _BECH32_CHARSET.index(data[-7]) & ((1 << leftover) - 1))


def address_to_script_pubkey(addr: str) -> bytes | None:
    """Convert a supported Bitcoin/Namecoin/Syscoin address to scriptPubKey."""
    decoded = _b58_decode_versioned(addr)
    if decoded is not None:
        version, hash160 = decoded
        if version in _P2PKH_VERSIONS:
            return b"\x76\xa9\x14" + hash160 + b"\x88\xac"
        if version in _P2SH_VERSIONS:
            return b"\xa9\x14" + hash160 + b"\x87"
        return None

    lowered = addr.lower()
    separator = lowered.rfind("1")
    hrp = lowered[:separator] if separator >= 0 else ""
    if hrp not in ("bc", "nc", "sys"):
        return None
    if addr != lowered and addr != addr.upper():
        return None
    if not _bech32_encoding_ok(lowered):
        return None
    program = _bech32_decode_to_program("bc1" + lowered[separator + 1 :])
    if program is None:
        return None
    data = lowered[separator + 1 :]
    if not data or data[0] not in _BECH32_CHARSET:
        return None
    version = _BECH32_CHARSET.index(data[0])
    if version > 16 or not 2 <= len(program) <= 40:
        return None
    if version == 0 and len(program) not in (20, 32):
        return None
    opcode = 0 if version == 0 else 0x50 + version
    return bytes([opcode, len(program)]) + program


def _coin_value_to_sats(value: str) -> int:
    try:
        coins = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(f"invalid BTC-denominated output value: {value!r}") from exc
    if not coins.is_finite() or coins < 0:
        raise ValueError(f"invalid BTC-denominated output value: {value!r}")
    sats = coins * _SATOSHIS_PER_BTC
    integral = sats.to_integral_value()
    if sats != integral:
        raise ValueError(f"output value has sub-satoshi precision: {value!r}")
    result = int(integral)
    if result > _UINT64_MAX:
        raise ValueError(f"output value is outside uint64 range: {value!r}")
    return result


def _satoshi_value(value: str) -> int:
    normalized = value.strip()
    if not normalized.isdigit():
        raise ValueError(f"invalid satoshi output value: {value!r}")
    result = int(normalized)
    if result > _UINT64_MAX:
        raise ValueError(f"output value is outside uint64 range: {value!r}")
    return result


def amount_to_sats(value: str) -> int:
    """Parse an amount that may be canonical satoshis or a legacy BTC decimal.

    The canonical rendering emits integer satoshis, while the legacy
    address/BTC-value forms emitted decimals such as ``12.50000000`` or
    ``1e-08``. A decimal point or exponent marks the BTC form; a bare integer
    is satoshis. Reading a canonical satoshi amount as BTC would inflate it by
    a factor of 100,000,000.
    """
    normalized = value.strip()
    if "." in normalized or "e" in normalized.lower():
        return _coin_value_to_sats(normalized)
    return _satoshi_value(normalized)


def _canonical_claim(position: int, script: str, value: str) -> CoinbaseOutputClaim:
    value_sats = _satoshi_value(value) if value else None
    if script.endswith("*"):
        prefix = _normalized_hex(script[:-1], label="scriptPubKey prefix")
        return CoinbaseOutputClaim(position, value_sats, script_prefix_hex=prefix)
    if script:
        return CoinbaseOutputClaim(
            position,
            value_sats,
            script_hex=_normalized_hex(script, label="scriptPubKey"),
        )
    return CoinbaseOutputClaim(position, value_sats)


def _address_claim(
    address: str,
    position: int,
    value_btc: str | None,
    *,
    child_decoded: bool = False,
) -> CoinbaseOutputClaim | None:
    """Return the semantic claim carried by a supported decoded address."""
    decoded = _b58_decode_versioned(address)
    if (
        decoded is not None
        and decoded[0] in _P2PKH_VERSIONS
        and (decoded[0] != 0 or child_decoded)
    ):
        # A child-chain rendering (Namecoin 52, Syscoin 63) preserves only the
        # hash160: the acquisition decoded it through the child node, so the
        # template behind it is unknown. Bitcoin's own version 0 normally
        # falls through to an exact P2PKH script claim, because the canonical
        # rendering shows P2PK as raw hex and so an address really does mean
        # P2PKH -- unless ``child_decoded`` says the cell came from a child
        # node whose decode collapses P2PK to the same version-0 address
        # (Terracoin's Bitcoin-style base58). A P2SH address stays exact in
        # both cases: only a P2SH script derives it.
        value_sats = None if value_btc is None else amount_to_sats(value_btc)
        return CoinbaseOutputClaim(
            position,
            value_sats,
            recipient_hash160=decoded[1].hex(),
        )
    script = address_to_script_pubkey(address)
    if script is None:
        return None
    value_sats = None if value_btc is None else amount_to_sats(value_btc)
    return CoinbaseOutputClaim(position, value_sats, script_hex=script.hex())


def _parse_output_token(
    token: str, position: int, *, child_decoded: bool = False
) -> CoinbaseOutputClaim:
    if token.startswith("OP_RETURN:"):
        return CoinbaseOutputClaim(
            position,
            amount_to_sats(token.removeprefix("OP_RETURN:")),
            script_prefix_hex="6a",
        )

    if token.startswith("nonstandard:"):
        payload = token.removeprefix("nonstandard:")
        if ":" not in payload:
            return CoinbaseOutputClaim(position, amount_to_sats(payload))
        script, value = payload.rsplit(":", 1)
        return CoinbaseOutputClaim(
            position,
            amount_to_sats(value),
            script_hex=_normalized_hex(script, label="nonstandard scriptPubKey"),
        )

    if token.startswith("pubkey:"):
        return CoinbaseOutputClaim(
            position, amount_to_sats(token.removeprefix("pubkey:"))
        )

    if ":" not in token:
        if token.startswith("pkh(") and token.endswith(")"):
            # A recipient-only claim with no amount: the source established
            # the payout hash160 but not the script behind it.
            return CoinbaseOutputClaim(
                position,
                None,
                recipient_hash160=_normalized_hex(
                    token[4:-1], label="recipient hash160"
                ),
            )
        address_claim = _address_claim(
            token, position, None, child_decoded=child_decoded
        )
        if address_claim is not None:
            return address_claim
        if token.endswith("*") and _HEX_RE.fullmatch(token[:-1]):
            # An amount-less script-prefix claim, symmetric with bare script
            # hex: the column renderer emits it without a value delimiter.
            return _canonical_claim(position, token, "")
        return CoinbaseOutputClaim(
            position, script_hex=_normalized_hex(token, label="scriptPubKey")
        )

    if token.count(":") != 1:
        raise ValueError(f"unrecognized coinbase output token: {token!r}")
    left, right = (part.strip() for part in token.split(":", 1))

    if left.startswith("pkh(") and left.endswith(")"):
        return CoinbaseOutputClaim(
            position,
            _satoshi_value(right) if right else None,
            recipient_hash160=left.removeprefix("pkh(").removesuffix(")"),
        )

    if left in _LEGACY_TYPE_LABEL_PREFIXES:
        return CoinbaseOutputClaim(
            position,
            amount_to_sats(right),
            script_prefix_hex=_LEGACY_TYPE_LABEL_PREFIXES[left],
        )
    if left in _LEGACY_TYPE_LABELS_VALUE_ONLY:
        return CoinbaseOutputClaim(position, amount_to_sats(right))

    address_claim = _address_claim(left, position, right, child_decoded=child_decoded)
    if address_claim is not None:
        return address_claim

    if not left:
        value_sats = amount_to_sats(right)
        return CoinbaseOutputClaim(position, value_sats)
    if left.endswith("*") and _HEX_RE.fullmatch(left[:-1]):
        return _canonical_claim(position, left, right)
    if _HEX_RE.fullmatch(left):
        return _canonical_claim(position, left, right)
    raise ValueError(f"unrecognized coinbase output token: {token!r}")


def _merge_two_claims(
    existing: CoinbaseOutputClaim, incoming: CoinbaseOutputClaim
) -> CoinbaseOutputClaim:
    if existing.position != incoming.position:
        raise ValueError("cannot merge claims for different output positions")
    if existing.position_exact != incoming.position_exact:
        raise ValueError("cannot merge exact and filtered output positions directly")
    if (
        existing.value_sats is not None
        and incoming.value_sats is not None
        and existing.value_sats != incoming.value_sats
    ):
        raise ValueError(
            f"conflicting values at coinbase output {existing.position}: "
            f"{existing.value_sats} != {incoming.value_sats}"
        )
    value_sats = (
        existing.value_sats if existing.value_sats is not None else incoming.value_sats
    )

    exacts = {value for value in (existing.script_hex, incoming.script_hex) if value}
    if len(exacts) > 1:
        raise ValueError(
            f"conflicting scripts at coinbase output {existing.position}: "
            + " != ".join(sorted(exacts))
        )
    script_hex = next(iter(exacts), "")
    recipients = {
        value
        for value in (existing.recipient_hash160, incoming.recipient_hash160)
        if value
    }
    if len(recipients) > 1:
        raise ValueError(
            f"conflicting recipients at coinbase output {existing.position}: "
            + " != ".join(sorted(recipients))
        )
    recipient_hash160 = next(iter(recipients), "")
    if recipient_hash160 and script_hex:
        script_recipient = recipient_hash160_for_script(script_hex)
        if script_recipient != recipient_hash160:
            raise ValueError(
                f"script at coinbase output {existing.position} does not pay "
                f"recipient {recipient_hash160}"
            )
        # The exact script is the stronger, canonical form of this same
        # recipient claim. Keeping both would make equivalent alignments look
        # materially different without preserving additional evidence.
        recipient_hash160 = ""
    prefixes = [
        value
        for value in (existing.script_prefix_hex, incoming.script_prefix_hex)
        if value
    ]
    script_prefix_hex = ""
    for prefix in prefixes:
        if script_hex:
            if not script_hex.startswith(prefix):
                raise ValueError(
                    f"script at coinbase output {existing.position} does not "
                    f"satisfy prefix {prefix}"
                )
            continue
        if not script_prefix_hex:
            script_prefix_hex = prefix
        elif prefix.startswith(script_prefix_hex):
            script_prefix_hex = prefix
        elif not script_prefix_hex.startswith(prefix):
            raise ValueError(
                f"conflicting script prefixes at coinbase output {existing.position}: "
                f"{script_prefix_hex} != {prefix}"
            )
    return CoinbaseOutputClaim(
        existing.position,
        value_sats,
        script_hex=script_hex,
        script_prefix_hex=script_prefix_hex,
        recipient_hash160=recipient_hash160,
        position_exact=existing.position_exact,
    )


def _normalize_claim_set(
    claims: Iterable[CoinbaseOutputClaim],
) -> tuple[CoinbaseOutputClaim, ...]:
    normalized = tuple(sorted(claims, key=lambda claim: claim.position))
    if not normalized:
        return ()
    if len({claim.position for claim in normalized}) != len(normalized):
        raise ValueError("duplicate coinbase output claim position")
    position_kinds = {claim.position_exact for claim in normalized}
    if len(position_kinds) != 1:
        raise ValueError("one output claim set mixes exact and filtered positions")
    if not normalized[0].position_exact and tuple(
        claim.position for claim in normalized
    ) != tuple(range(len(normalized))):
        raise ValueError("filtered output claims must use contiguous sequence ordinals")
    return normalized


def _merge_exact_claim_sets(
    claim_sets: Iterable[tuple[CoinbaseOutputClaim, ...]],
) -> tuple[CoinbaseOutputClaim, ...]:
    merged: dict[int, CoinbaseOutputClaim] = {}
    for claim_set in claim_sets:
        for claim in claim_set:
            current = merged.get(claim.position)
            merged[claim.position] = (
                claim if current is None else _merge_two_claims(current, claim)
            )
    return tuple(merged[position] for position in sorted(merged))


def _merge_filtered_into_exact(
    exact: tuple[CoinbaseOutputClaim, ...],
    filtered: tuple[CoinbaseOutputClaim, ...],
) -> tuple[CoinbaseOutputClaim, ...]:
    """Merge one ordered filtered projection into an exact-position vector.

    Every compatible alignment is considered. Multiple alignments are allowed
    only when they produce the same maximal claim vector; otherwise the
    evidence is materially ambiguous and publication fails closed.
    """
    if not filtered:
        return exact

    @lru_cache(maxsize=None)
    def align(
        filtered_index: int,
        exact_start: int,
        current: tuple[CoinbaseOutputClaim, ...],
    ) -> frozenset[tuple[CoinbaseOutputClaim, ...]]:
        if filtered_index == len(filtered):
            return frozenset({current})
        remaining = len(filtered) - filtered_index
        outcomes: set[tuple[CoinbaseOutputClaim, ...]] = set()
        for exact_index in range(exact_start, len(current) - remaining + 1):
            incoming = replace(
                filtered[filtered_index],
                position=current[exact_index].position,
                position_exact=True,
            )
            try:
                merged_claim = _merge_two_claims(current[exact_index], incoming)
            except ValueError:
                continue
            next_current = (
                current[:exact_index] + (merged_claim,) + current[exact_index + 1 :]
            )
            outcomes.update(align(filtered_index + 1, exact_index + 1, next_current))
            if len(outcomes) > 1:
                break
        return frozenset(outcomes)

    outcomes = align(0, 0, exact)
    if not outcomes:
        raise ValueError("filtered output claims do not match the exact output vector")
    if len(outcomes) > 1:
        raise ValueError("filtered output claims have materially ambiguous alignments")
    return next(iter(outcomes))


def _as_filtered(
    exact: tuple[CoinbaseOutputClaim, ...],
) -> tuple[CoinbaseOutputClaim, ...]:
    return tuple(
        replace(claim, position=index, position_exact=False)
        for index, claim in enumerate(exact)
    )


def _as_exact(
    filtered: tuple[CoinbaseOutputClaim, ...],
) -> tuple[CoinbaseOutputClaim, ...]:
    return tuple(
        replace(claim, position=index, position_exact=True)
        for index, claim in enumerate(filtered)
    )


def _merge_filtered_claim_sets(
    claim_sets: list[tuple[CoinbaseOutputClaim, ...]],
) -> tuple[CoinbaseOutputClaim, ...]:
    current = claim_sets[0]
    for incoming in claim_sets[1:]:
        outcomes: set[tuple[CoinbaseOutputClaim, ...]] = set()
        for exact_base, projection in (
            (_as_exact(current), incoming),
            (_as_exact(incoming), current),
        ):
            try:
                outcomes.add(
                    _as_filtered(_merge_filtered_into_exact(exact_base, projection))
                )
            except ValueError:
                continue
        if not outcomes:
            raise ValueError("filtered output projections are incompatible")
        if len(outcomes) > 1:
            raise ValueError("filtered output projections are materially ambiguous")
        current = next(iter(outcomes))
    return current


def merge_coinbase_output_claim_sets(
    *claim_sets: Iterable[CoinbaseOutputClaim],
) -> tuple[CoinbaseOutputClaim, ...]:
    """Return the maximal compatible union of any number of claim sets."""
    normalized = [
        claim_set
        for claims in claim_sets
        if (claim_set := _normalize_claim_set(claims))
    ]
    if not normalized:
        return ()
    exact_sets = [claim_set for claim_set in normalized if claim_set[0].position_exact]
    filtered_sets = [
        claim_set for claim_set in normalized if not claim_set[0].position_exact
    ]
    if exact_sets:
        merged = _merge_exact_claim_sets(exact_sets)
        for filtered in filtered_sets:
            merged = _merge_filtered_into_exact(merged, filtered)
        return merged
    return _merge_filtered_claim_sets(filtered_sets)


def parse_coinbase_output_claims(
    outputs: str,
    full_coinbase_hex: str = "",
    *,
    child_decoded_addresses: bool = False,
) -> tuple[CoinbaseOutputClaim, ...]:
    """Parse and reconcile heterogeneous output text and a raw coinbase tx.

    Canonical text is pipe-joined ``scripthex:value_sats``. An empty value
    denotes an unknown amount, a trailing ``*`` denotes a script prefix, and
    ``pkh(<hash160>)`` preserves an address-derived recipient claim when no
    exact script is available. A leading ``~`` marks an ordered filtered
    projection whose ordinals are not absolute transaction positions. Legacy
    raw-script, address, and address/BTC-value forms are also accepted;
    ``child_decoded_addresses`` marks the text as a child node's address
    decode, where even a version-0 address establishes only the recipient
    hash160 because such a decode collapses P2PK to the same address.
    Filtered projections must say so with ``~``: an acquisition that dropped
    outputs without a decoded address is not inferable from the rendering,
    because the canonical rendering shows every address-bearing script as an
    address.
    """
    explicit: list[CoinbaseOutputClaim] = []
    normalized = (outputs or "").strip()
    if normalized and normalized != "[]":
        delimiter = "|" if "|" in normalized else ";"
        raw_tokens = [raw_token.strip() for raw_token in normalized.split(delimiter)]
        nonempty_tokens = [token for token in raw_tokens if token]
        marked_filtered = any(token.startswith("~") for token in nonempty_tokens)
        if marked_filtered and not all(
            token.startswith("~") for token in nonempty_tokens
        ):
            raise ValueError("output text mixes exact and filtered position tokens")
        stripped_tokens = [
            token.removeprefix("~") if token else "" for token in raw_tokens
        ]
        # A bare address list no longer implies a filtered projection: the
        # committed rendering shows every address-bearing script as an
        # address, so completeness is signalled explicitly with "~" rather
        # than inferred from the rendering.
        filtered_projection = marked_filtered
        if filtered_projection and any(not token for token in stripped_tokens):
            raise ValueError("filtered output projections cannot contain gaps")
        for position, token in enumerate(stripped_tokens):
            if token:
                claim = _parse_output_token(
                    token, position, child_decoded=child_decoded_addresses
                )
                if filtered_projection:
                    claim = replace(claim, position_exact=False)
                explicit.append(claim)

    raw_claims: list[CoinbaseOutputClaim] = []
    full_coinbase = (full_coinbase_hex or "").strip()
    if full_coinbase:
        try:
            parsed = parse_coinbase_tx(bytes.fromhex(full_coinbase))
        except ValueError as exc:
            raise ValueError("full coinbase transaction is not valid hex") from exc
        if parsed is None:
            raise ValueError("full coinbase transaction could not be parsed")
        raw_claims.extend(
            CoinbaseOutputClaim(position, value_sats, script_hex=script.hex())
            for position, (value_sats, script) in enumerate(parsed["outputs"])
        )
    return merge_coinbase_output_claim_sets(explicit, raw_claims)


def render_coinbase_outputs_column(claims: Iterable[CoinbaseOutputClaim]) -> str:
    """Render claims in the committed ``coinbase_outputs`` column contract.

    Semicolon-joined, in coinbase order, each entry ``<payout>`` or
    ``<payout>:<value_sats>``, with the Bitcoin address for address-bearing
    standard templates and raw scriptPubKey hex otherwise. This is the form
    published datasets carry; ``render_coinbase_output_claims`` renders the
    module's own reconciliation form instead, which differs only in separator
    and in always emitting the amount field. Both carry script prefixes and
    recipient-only claims.
    """
    merged = merge_coinbase_output_claim_sets(claims)
    if not merged:
        return ""
    filtered_projection = not merged[0].position_exact
    marker = "~" if filtered_projection else ""
    by_position = {claim.position: claim for claim in merged}
    tokens: list[str] = []
    for position in range(merged[-1].position + 1):
        claim = by_position.get(position)
        if claim is None:
            tokens.append("")
            continue
        if claim.script_hex:
            payout = canonical_output_token(bytes.fromhex(claim.script_hex))
        elif claim.recipient_hash160:
            payout = f"pkh({claim.recipient_hash160})"
        elif claim.script_prefix_hex:
            payout = claim.script_prefix_hex + "*"
        else:
            payout = ""
        value = "" if claim.value_sats is None else f":{claim.value_sats}"
        tokens.append(f"{marker}{payout}{value}" if payout or value else marker + ":")
    return ";".join(tokens)


def render_coinbase_output_claims(
    claims: Iterable[CoinbaseOutputClaim],
) -> str:
    """Render claims in canonical exact-position or filtered-sequence form."""
    merged = merge_coinbase_output_claim_sets(claims)
    if not merged:
        return ""
    filtered_projection = not merged[0].position_exact
    by_position = {claim.position: claim for claim in merged}
    tokens: list[str] = []
    for position in range(merged[-1].position + 1):
        claim = by_position.get(position)
        if claim is None:
            tokens.append("")
            continue
        script = claim.script_hex
        if not script and claim.script_prefix_hex:
            script = claim.script_prefix_hex + "*"
        if not script and claim.recipient_hash160:
            script = f"pkh({claim.recipient_hash160})"
        value = "" if claim.value_sats is None else str(claim.value_sats)
        marker = "~" if filtered_projection else ""
        tokens.append(f"{marker}{script}:{value}")
    return "|".join(tokens)


def _coerce_claims(
    value: str | Iterable[CoinbaseOutputClaim],
) -> tuple[CoinbaseOutputClaim, ...]:
    if isinstance(value, str):
        return parse_coinbase_output_claims(value)
    return merge_coinbase_output_claim_sets(value)


def _claim_refines(old: CoinbaseOutputClaim, new: CoinbaseOutputClaim) -> bool:
    if old.value_sats is not None and old.value_sats != new.value_sats:
        return False
    if old.script_hex and old.script_hex != new.script_hex:
        return False
    if old.script_prefix_hex:
        new_constraint = new.script_hex or new.script_prefix_hex
        if not new_constraint.startswith(old.script_prefix_hex):
            return False
    if old.recipient_hash160:
        new_recipient = new.recipient_hash160
        if new.script_hex:
            new_recipient = recipient_hash160_for_script(new.script_hex)
        if new_recipient != old.recipient_hash160:
            return False
    return True


def _ordered_projection_refines(
    old: tuple[CoinbaseOutputClaim, ...],
    new: tuple[CoinbaseOutputClaim, ...],
) -> bool:
    @lru_cache(maxsize=None)
    def matches(old_index: int, new_start: int) -> bool:
        if old_index == len(old):
            return True
        remaining = len(old) - old_index
        for new_index in range(new_start, len(new) - remaining + 1):
            if _claim_refines(old[old_index], new[new_index]) and matches(
                old_index + 1, new_index + 1
            ):
                return True
        return False

    return matches(0, 0)


def coinbase_output_claims_refine(
    committed: str | Iterable[CoinbaseOutputClaim],
    staged: str | Iterable[CoinbaseOutputClaim],
) -> bool:
    """Return whether ``staged`` preserves or strengthens every old claim."""
    old = _coerce_claims(committed)
    new = _coerce_claims(staged)
    if not old:
        return True
    if not new:
        return False
    if old[0].position_exact:
        if not new[0].position_exact:
            return False
        new_by_position = {claim.position: claim for claim in new}
        return all(
            (candidate := new_by_position.get(claim.position)) is not None
            and _claim_refines(claim, candidate)
            for claim in old
        )
    return _ordered_projection_refines(old, new)
