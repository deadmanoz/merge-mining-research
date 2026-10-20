"""Shared CLI for the thin ``run_classifier`` fleet.

``--rpc-url`` / ``--rpc-user`` / ``--rpc-pass`` resolve through ``get_btc_auth``
(``BTC_RPC_URL``, else ``http://127.0.0.1:8332``; omitted user/pass use
cookie/conf). Output defaults come from ``ChainSpec``. Overrides exist only
where a historical default differs: syscoin's ``data/auxpow_raw.csv``,
terracoin's directory-less paths, and unobtanium's ``~/uno-extract``.

Normalizer-fronted wrappers (emercoin, huntercoin) take the RPC helpers but
keep their own input/output argparse. Classifiers that never call
``run_classifier`` (elastos, geistgeld, groupcoin, coiledcoin,
``classify_auxpow_candidates``) take the RPC helpers only. RSK and Hathor
keep their own proof and output handling.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional

from .btc_classify import run_classifier
from .btc_rpc import BtcRpc, get_btc_auth
from .btc_rpc_transports import make_rpc
from .config import PROJECT_ROOT, ChainSpec

DEFAULT_RPC_URL = "http://127.0.0.1:8332"


def _spec_relative_default(spec_path: Path) -> str:
    """Absolute ``ChainSpec`` paths print as the historical repo-relative ``--help`` default."""
    return os.path.relpath(spec_path, PROJECT_ROOT)


def add_rpc_args(parser: argparse.ArgumentParser) -> None:
    """``--rpc-url`` defaults to ``BTC_RPC_URL`` or ``http://127.0.0.1:8332``.

    Omitted user/pass stay ``None`` so ``rpc_from_args`` uses ``get_btc_auth``.
    """
    parser.add_argument(
        "--rpc-url",
        default=os.environ.get("BTC_RPC_URL", DEFAULT_RPC_URL),
        help="Bitcoin Core JSON-RPC URL; forward a remote node with "
        "ssh -L 8332:localhost:8332 <host>.",
    )
    parser.add_argument(
        "--rpc-user",
        default=None,
        help="Bitcoin Core RPC user (defaults to cookie/conf/env auto-discovery)",
    )
    parser.add_argument(
        "--rpc-pass",
        default=None,
        help="Bitcoin Core RPC password (defaults to cookie/conf/env auto-discovery)",
    )


def rpc_from_args(args: argparse.Namespace) -> BtcRpc:
    """Flags, then ``BITCOIN_RPC_*``, cookie, then ``bitcoin.conf``.

    Missing credentials surface at the first RPC call, not here.
    """
    auth = get_btc_auth(args.rpc_user, args.rpc_pass)
    return make_rpc(args.rpc_url, auth)


def _default_all_valid(output_default: str, key: str) -> str:
    """``<output directory>/<key>_btc_valid.csv``, so historical ``--all-valid`` defaults follow ``--output``."""
    return str(Path(output_default).parent / f"{key}_btc_valid.csv")


def add_standard_output_args(
    parser: argparse.ArgumentParser,
    spec: ChainSpec,
    *,
    input_default: Optional[str] = None,
    output_default: Optional[str] = None,
    validated_output_default: Optional[str] = None,
    all_valid_default: Optional[str] = None,
) -> None:
    """``--input`` / ``--output`` / ``--validated-output`` / ``--all-valid`` / ``--keep-near`` from ``spec`` unless overridden."""
    resolved_input = (
        input_default
        if input_default is not None
        else _spec_relative_default(spec.input_csv)
    )
    resolved_output = (
        output_default
        if output_default is not None
        else _spec_relative_default(spec.output_csv)
    )
    resolved_validated = (
        validated_output_default
        if validated_output_default is not None
        else _spec_relative_default(spec.validated_csv)
    )
    resolved_all_valid = (
        all_valid_default
        if all_valid_default is not None
        else _default_all_valid(resolved_output, spec.key)
    )

    parser.add_argument(
        "--input", default=resolved_input, help="Input CSV from extraction"
    )
    parser.add_argument(
        "--output",
        default=resolved_output,
        help="Output CSV with stale/unknown blocks",
    )
    parser.add_argument(
        "--validated-output",
        default=resolved_validated,
        help="Output CSV with validated stale blocks only (committed loader input)",
    )
    parser.add_argument(
        "--all-valid",
        default=resolved_all_valid,
        help="Output CSV with all self-target-PoW-valid headers (for debugging)",
    )
    parser.add_argument(
        "--keep-near",
        action="store_true",
        help="Also retain headers that fail their encoded self-target ('near') as sibling "
        "evidence for shared-parent fork detection",
    )


# Thin run_classifier chains: the shared command and the 13 delegate wrappers.
# Qbit is shared-command-only and deliberately has no sibling wrapper script.
# Huntercoin / emercoin / doichain (normalizers) and the bespoke classifiers
# are intentionally absent.
THIN_CLASSIFIER_CHAINS = frozenset(
    {
        "argentum",
        "bitmark",
        "bitcoin-vault",
        "crown",
        "devcoin",
        "elcash",
        "fractal",
        "ixcoin",
        "myriadcoin",
        "qbit",
        "syscoin",
        "terracoin",
        "unobtanium",
        "xaya",
    }
)

_SUMMARY_KEYS = (
    "total",
    "btc_valid",
    "stale",
    "unknown",
    "valid",
    "rejected",
    "validation_unknown",
    "output_path",
    "validated_output_path",
)


def cli_path_overrides(key: str) -> dict[str, str]:
    """Path defaults that differ from ``ChainSpec``. Unobtanium's ``~/`` default is expanded here."""
    if key == "syscoin":
        return {"input_default": "data/auxpow_raw.csv"}
    if key == "terracoin":
        return {
            "input_default": "terracoin_auxpow_raw.csv",
            "output_default": "terracoin_stale_blocks.csv",
        }
    if key == "unobtanium":
        return {
            "input_default": os.path.expanduser(
                "~/uno-extract/unobtanium_auxpow_raw.csv"
            ),
            "output_default": os.path.expanduser(
                "~/uno-extract/unobtanium_stale_blocks.csv"
            ),
        }
    return {}


def run_standard_classifier_cli(argv: list[str] | None, spec: ChainSpec) -> int:
    """One thin wrapper. Refuses a chain outside ``THIN_CLASSIFIER_CHAINS``."""
    if spec.key not in THIN_CLASSIFIER_CHAINS:
        print(
            f"error: {spec.key} is not a thin run_classifier chain",
            file=sys.stderr,
        )
        return 2

    parser = argparse.ArgumentParser(
        description=f"Classify {spec.display_name} AuxPoW as stale/unknown"
    )
    add_standard_output_args(parser, spec, **cli_path_overrides(spec.key))
    add_rpc_args(parser)
    args = parser.parse_args(argv)

    summary = run_classifier(
        spec,
        input_path=args.input,
        output_path=args.output,
        validated_output_path=args.validated_output,
        all_valid=True,
        all_valid_path=args.all_valid,
        keep_near=args.keep_near,
        bits_source_is_decimal=spec.bits_source_is_decimal,
        rpc=rpc_from_args(args),
    )
    print(f"{spec.display_name} classification complete")
    for key in _SUMMARY_KEYS:
        print(f"  {key}: {summary[key]}")
    if args.keep_near:
        print(f"  near: {summary['near']}")
        print(f"  near_output_path: {summary['near_output_path']}")
    return 0
