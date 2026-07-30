#!/usr/bin/env python3
"""Resolve provisional AuxPoW child rows to exact child-chain RPC heights."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from stale_blocks_analysis.auxpow_child_heights import (  # noqa: E402
    CHAIN_SPECS,
    ChildChainRpc,
    normalize_auxpow_child_heights,
    resolve_rpc_auth,
)


def main() -> None:
    """Fill exact consensus child heights in unresolved blk-file rows via RPC."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chain", required=True, choices=sorted(CHAIN_SPECS))
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rpc-url")
    parser.add_argument("--rpc-user")
    parser.add_argument("--rpc-pass")
    parser.add_argument("--rpc-conf", type=Path)
    parser.add_argument("--rpc-timeout", type=float, default=30.0)
    args = parser.parse_args()

    spec = CHAIN_SPECS[args.chain]
    auth = resolve_rpc_auth(
        chain=args.chain,
        cli_user=args.rpc_user,
        cli_password=args.rpc_pass,
        conf_path=args.rpc_conf,
    )
    rpc = ChildChainRpc(
        url=args.rpc_url or spec.default_rpc_url,
        auth=auth,
        timeout=args.rpc_timeout,
    )
    summary = normalize_auxpow_child_heights(
        chain=args.chain,
        input_path=args.input,
        output_path=args.output,
        rpc=rpc,
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
