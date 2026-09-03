#!/usr/bin/env python3
"""Validate the committed body-invalid-stales overlay."""

from __future__ import annotations

import sys

from stale_blocks_analysis.body_invalid_overlay import main


if __name__ == "__main__":
    sys.exit(main())
