#!/usr/bin/env python3
"""Extract authenticated Bitcoin-parent evidence from native Xaya block files."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from stale_blocks_analysis.xaya_extraction import main  # noqa: E402

if __name__ == "__main__":
    main()
