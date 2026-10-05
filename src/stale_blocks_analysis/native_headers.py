"""Genesis-linked heights for stored native block-file headers.

These heights count authenticated predecessor links. They do not establish
native active-chain membership or replay child-chain consensus.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from pathlib import Path

from .auxpow_chainid import hash_from_display_hex, hash_from_header_bytes
from .auxpow_parse import ChildHeaderValidationError


def native_block_files(blocks_dir: Path) -> list[Path]:
    """Select numbered block files, excluding legacy blkindex.dat."""
    paths = sorted(p for p in blocks_dir.glob("blk*.dat") if p.name[3:-4].isdigit())
    if not paths:
        raise ChildHeaderValidationError(f"no numbered block files in {blocks_dir}")
    return paths


def decode_block_file(path: Path, xor_key: bytes = b"") -> bytes:
    """Read one bounded native block file and undo its optional XOR envelope."""
    data = path.read_bytes()
    if not any(xor_key):
        return data
    decoded = bytearray(data)
    for offset, key in enumerate(xor_key):
        table = bytes(value ^ key for value in range(256))
        decoded[offset :: len(xor_key)] = decoded[offset :: len(xor_key)].translate(
            table
        )
    return bytes(decoded)


def framed_blocks(data: bytes, magic: bytes) -> Iterator[tuple[int, bytes]]:
    """Yield exact records; allow zero reserve gaps, never skip nonzero bytes."""
    if len(magic) != 4 or magic == b"\0" * 4:
        raise ChildHeaderValidationError(
            "native block magic must be four nonzero bytes"
        )
    offset = 0
    while offset < len(data):
        if len(data) - offset < 8:
            if not data[offset:].strip(b"\0"):
                return
            raise ChildHeaderValidationError(
                f"invalid native framing at offset {offset}"
            )
        if data[offset : offset + 4] != magic:
            following = data.find(magic, offset)
            gap = data[offset:following] if following >= 0 else data[offset:]
            if not gap.strip(b"\0"):
                if following < 0:
                    return
                offset = following
                continue
            raise ChildHeaderValidationError(
                f"invalid native framing at offset {offset}"
            )
        size = struct.unpack_from("<I", data, offset + 4)[0]
        end = offset + 8 + size
        if size < 80 or end > len(data):
            raise ChildHeaderValidationError(
                f"truncated native block at offset {offset}"
            )
        yield offset, data[offset + 8 : end]
        offset = end


class NativeHeaderIndex:
    """Authenticate stored header ancestry against one declared genesis."""

    def __init__(self, genesis_hash_display: str):
        self.genesis = hash_from_display_hex(genesis_hash_display)
        self.predecessors: dict[bytes, bytes] = {}
        self.heights: dict[bytes, int] = {}

    def add(self, raw_header: bytes) -> bytes:
        block_hash = hash_from_header_bytes(raw_header)
        predecessor = raw_header[4:36]
        existing = self.predecessors.get(block_hash)
        if existing is not None and existing != predecessor:
            raise ChildHeaderValidationError("contradictory native header identity")
        self.predecessors[block_hash] = predecessor
        return block_hash

    def resolve(self) -> dict[bytes, int]:
        if self.predecessors.get(self.genesis) != b"\0" * 32:
            raise ChildHeaderValidationError(
                "declared genesis missing or has a predecessor"
            )
        self.heights = {self.genesis: 0}
        for block_hash in self.predecessors:
            path = []
            visiting = set()
            cursor = block_hash
            while cursor not in self.heights:
                if cursor in visiting:
                    raise ChildHeaderValidationError("cyclic native header ancestry")
                if cursor not in self.predecessors:
                    raise ChildHeaderValidationError(
                        f"missing native predecessor {cursor[::-1].hex()}"
                    )
                visiting.add(cursor)
                path.append(cursor)
                cursor = self.predecessors[cursor]
            height = self.heights[cursor]
            for child in reversed(path):
                height += 1
                self.heights[child] = height
        return self.heights
