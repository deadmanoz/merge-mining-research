#!/usr/bin/env python3
"""Extract Bitcoin AuxPoW evidence from the foundational Huntercoin native dump.

SHA-256d proofs are authenticated against the child target and commitment.
Stored heights follow predecessor links to genesis; active-chain membership
and complete native consensus are not asserted.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from stale_blocks_analysis.huntercoin_extraction import extract_native_blocks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--blocks-dir",
        type=Path,
        required=True,
        help="Directory of native blk*.dat files",
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="Private raw CSV destination"
    )
    parser.add_argument(
        "--workers", type=int, default=1, help="Block-file worker processes"
    )
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be positive")
    print(extract_native_blocks(args.blocks_dir, args.output, workers=args.workers))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
