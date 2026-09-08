"""Recognize RSKj's variable-width RLP fallback signature representation.

This checks representation and scalar constraints, not the recovered signing
key or the chain's activation/difficulty rules. The trusted RSKj source owns
those consensus checks. See ProofOfWorkRule.validFallbackBlockSignature in
RSKj VETIVER-9.0.1.
"""

from .config import (
    RSK_FALLBACK_MAX_PROOF_BYTES,
    RSK_FALLBACK_MIN_PROOF_BYTES,
    SECP256K1_ORDER,
)


def is_fallback_signature(proof: bytes) -> bool:
    """Accept one canonical RLP list of v and two signed-positive scalars."""
    if not RSK_FALLBACK_MIN_PROOF_BYTES <= len(proof) <= RSK_FALLBACK_MAX_PROOF_BYTES:
        return False
    prefix = proof[0]
    if 0xC0 <= prefix <= 0xF7:
        cursor, payload_size = 1, prefix - 0xC0
    elif prefix == 0xF8 and proof[1] > 55:
        cursor, payload_size = 2, proof[1]
    else:
        return False
    if cursor + payload_size != len(proof):
        return False

    fields = []
    while cursor < len(proof):
        prefix = proof[cursor]
        cursor += 1
        if prefix < 0x80:
            field = bytes([prefix])
        elif 0x81 <= prefix <= 0xA1:
            size = prefix - 0x80
            if cursor + size > len(proof):
                return False
            field = proof[cursor : cursor + size]
            cursor += size
            if size == 1 and field[0] < 0x80:
                return False
        else:
            return False
        fields.append(field)
        if len(fields) > 3:
            return False
    if len(fields) != 3 or len(fields[0]) != 1 or not 27 <= fields[0][0] <= 31:
        return False

    scalars = []
    for field in fields[1:]:
        # Match positive BigInteger.toByteArray(): a leading zero is required
        # exactly when the next byte would otherwise set the sign bit.
        if field[0] & 0x80 or (
            len(field) > 1 and field[0] == 0 and not field[1] & 0x80
        ):
            return False
        scalars.append(int.from_bytes(field, "big"))
    r, s = scalars
    return 0 < r < SECP256K1_ORDER and 0 < s < SECP256K1_ORDER // 2
