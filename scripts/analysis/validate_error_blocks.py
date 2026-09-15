#!/usr/bin/env python3
"""Validate local error-block rules, external body evidence and exact witnesses."""

from __future__ import annotations

import sys

from stale_blocks_analysis.error_block_validation import main


if __name__ == "__main__":
    sys.exit(main())
