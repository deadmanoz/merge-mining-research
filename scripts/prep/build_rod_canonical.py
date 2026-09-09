#!/usr/bin/env python3
"""Build the reviewed ROD canonical companion from sealed private evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from stale_blocks_analysis.rod_canonical import build_rod_canonical


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extraction-root", type=Path, required=True)
    parser.add_argument("--audit-root", type=Path, required=True)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--candidates-sha256", required=True)
    parser.add_argument("--review-root", type=Path, required=True)
    parser.add_argument("--review-receipt-sha256", required=True)
    parser.add_argument("--framing", type=Path, required=True)
    parser.add_argument("--extractor", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    receipt = build_rod_canonical(
        extraction_root=args.extraction_root,
        audit_root=args.audit_root,
        candidates_path=args.candidates,
        candidates_sha256=args.candidates_sha256,
        review_root=args.review_root,
        review_receipt_sha256=args.review_receipt_sha256,
        framing_path=args.framing,
        extractor_path=args.extractor,
        output_dir=args.output_dir,
    )
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
