#!/usr/bin/env python3
"""Validate the canonical error-block module from committed evidence."""

from __future__ import annotations

import sys

from stale_blocks_analysis.error_block_validation import main


if __name__ == "__main__":
    sys.exit(main())
