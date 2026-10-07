"""Common commitment rules, using fixed independent Merkle/slot vectors."""

import struct

import pytest

from stale_blocks_analysis.auxpow_commitment import (
    CommitmentFailure,
    child_commitment_failure,
    parent_merkle_matches,
)

LEAF = bytes(range(32))
BRANCH = [b"\x11" * 32, b"\x22" * 32]
# SHA256d(SHA256d(11*32 || LEAF) || 22*32), displayed big endian.
ROOT = bytes.fromhex("f1d664ff867cd821fa4d6187e80cce053d4f0be5de65cf8ce8b056771e699ce3")
MAGIC = bytes.fromhex("fabe6d6d")
# For chain 47, nonce 0 selects slot 1 in a four-leaf tree; nonce 1 selects 2.
FOOTER = struct.pack("<II", 4, 0)


@pytest.mark.parametrize("prefix", [MAGIC, b"\x51" * 20])
def test_child_commitment_accepts_nonzero_branch_slot_and_legacy_boundary(prefix):
    assert child_commitment_failure(LEAF, BRANCH, 1, prefix + ROOT + FOOTER, 47) is None


def test_single_slot_legacy_commitment_accepts_any_nonce():
    assert (
        child_commitment_failure(
            LEAF, [], 0, LEAF[::-1] + struct.pack("<II", 1, 0xFFFFFFFF), 47
        )
        is None
    )


@pytest.mark.parametrize(
    "script,failure",
    [
        (MAGIC + ROOT[::-1] + FOOTER, CommitmentFailure("missing_root")),
        (MAGIC * 2, CommitmentFailure("missing_root")),
        (MAGIC * 2 + ROOT + FOOTER, CommitmentFailure("duplicate_marker")),
        (MAGIC + b"\x51" + ROOT + FOOTER, CommitmentFailure("misplaced_marker")),
        # A later adjacent occurrence must not hide the earlier root.
        (ROOT + MAGIC + ROOT + FOOTER, CommitmentFailure("misplaced_marker")),
        (b"\x51" * 21 + ROOT + FOOTER, CommitmentFailure("late_legacy_root")),
        (MAGIC + ROOT + FOOTER[:7], CommitmentFailure("short_footer")),
        (
            MAGIC + ROOT + struct.pack("<II", 2, 1),
            CommitmentFailure("wrong_size", 2, 4),
        ),
        (
            MAGIC + ROOT + struct.pack("<II", 4, 1),
            CommitmentFailure("wrong_slot", 1, 2),
        ),
    ],
)
def test_child_commitment_first_failure(script, failure):
    assert child_commitment_failure(LEAF, BRANCH, 1, script, 47) == failure


def test_parent_inclusion_uses_internal_order_and_branch_index():
    assert parent_merkle_matches(LEAF, BRANCH, 1, ROOT[::-1])
    assert not parent_merkle_matches(LEAF, BRANCH, 1, ROOT)
    assert not parent_merkle_matches(LEAF, BRANCH, 0, ROOT[::-1])
    assert parent_merkle_matches(LEAF, [], 0, LEAF)
