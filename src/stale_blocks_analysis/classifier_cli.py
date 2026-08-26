"""Shared CLI helpers for the ``scripts/classify/*.py`` classifier fleet.

Before this module, the ``classify_<chain>_stales.py`` wrappers each
hand-rolled their own argparse for the Bitcoin Core RPC endpoint and the
classifier's output paths. The RPC flags alone had drifted into five
different spellings across the fleet: hyphenated user/pass, hyphenated
user/password, a squashed no-hyphen user/password pair, a combined URL flag
with embedded ``user:pass``, and a ``btc``-prefixed rpc/user/pass trio. The
output-argument surface was similarly inconsistent: ``--validated-output``,
``--all-valid``, and ``--keep-near`` appeared on some scripts and not others.

This module is the one place both surfaces now live:

* ``add_rpc_args`` / ``rpc_from_args`` add and resolve the standard
  ``--rpc-url`` / ``--rpc-user`` / ``--rpc-pass`` trio into a ready
  ``BtcRpc``. ``--rpc-url`` defaults to the ``BTC_RPC_URL`` env var, falling
  back to ``http://127.0.0.1:8332``; ``--rpc-user`` / ``--rpc-pass`` default
  to ``None`` so ``rpc_from_args`` falls back to ``get_btc_auth``'s
  cookie/conf/env-var discovery. The client is built via
  ``btc_rpc_transports.make_rpc`` (a ``requests``-backed ``BtcRpc``), the
  transport the classifiers had already been converging on since the
  SSH-tunnel transport was retired.

* ``add_standard_output_args`` adds the standard
  ``--input`` / ``--output`` / ``--validated-output`` / ``--all-valid`` /
  ``--keep-near`` surface for the thin ``run_classifier`` wrappers. Every
  default derives from the chain's ``ChainSpec`` (``input_csv`` /
  ``output_csv`` / ``validated_csv``; ``--all-valid`` derives to
  ``<output's directory>/<key>_btc_valid.csv``, the convention every
  wrapper already used) unless the caller passes an explicit override --
  needed only where a script's historical default differs from the spec
  (syscoin's ``data/auxpow_raw.csv`` input, terracoin's directory-less
  paths, unobtanium's private ``~/uno-extract`` archive).

Not every classifier in ``scripts/classify/`` adopts both helpers. The
normalizer-fronted wrappers (emercoin, huntercoin) adopt ``add_rpc_args``
but keep their own input/output argparse -- their legacy-schema input needs
a ``Path``-typed, existence-checked default that ``add_standard_output_args``
does not model -- and add ``--keep-near`` directly, since they do route
through ``run_classifier``'s Phase 1. The fully bespoke classifiers
(elastos, geistgeld, groupcoin, coiledcoin,
``classify_auxpow_candidates``)
adopt ``add_rpc_args`` for the RPC surface but keep their own chain-specific
output flags -- they never call ``run_classifier``, so ``--keep-near`` (a
Phase 1 concept) does not apply. RSK adopts ``add_rpc_args`` and
``rpc_from_args`` while retaining its bespoke proof and output handling.
The unified Hathor classifier keeps its chain-specific interface.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Optional

from .btc_rpc import BtcRpc, get_btc_auth
from .btc_rpc_transports import make_rpc
from .config import PROJECT_ROOT, ChainSpec

DEFAULT_RPC_URL = "http://127.0.0.1:8332"


def _spec_relative_default(spec_path: Path) -> str:
    """Render a ``ChainSpec`` path as the historical relative CLI default.

    ``ChainSpec`` paths (``input_csv``/``output_csv``/``validated_csv``) are
    always absolute (built from ``config.DATA_DIR``, itself resolved from
    ``PROJECT_ROOT``), but every wrapper's historical literal default was a
    repo-relative string like ``"data/ixcoin_auxpow_raw.csv"``. Re-deriving
    that relative form (instead of stringifying the absolute ``Path``
    directly) keeps the new flags' defaults byte-identical to what the
    wrappers printed in ``--help`` before this module existed.
    """
    return os.path.relpath(spec_path, PROJECT_ROOT)


def add_rpc_args(parser: argparse.ArgumentParser) -> None:
    """Add the standard ``--rpc-url``/``--rpc-user``/``--rpc-pass`` trio.

    ``--rpc-url`` defaults to the ``BTC_RPC_URL`` env var, falling back to
    ``http://127.0.0.1:8332``. ``--rpc-user``/``--rpc-pass`` default to
    ``None`` so :func:`rpc_from_args` falls back to ``get_btc_auth``'s
    cookie/conf/env-var discovery when the caller omits them.
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
    """Build a ready ``BtcRpc`` from the parsed ``--rpc-*`` args.

    Auth resolves via ``get_btc_auth(args.rpc_user, args.rpc_pass)``:
    explicit flags first, then ``BITCOIN_RPC_USER``/``BITCOIN_RPC_PASSWORD``,
    then the node's ``.cookie``, then ``bitcoin.conf``. Returns a
    requests-backed client (``btc_rpc_transports.make_rpc``) even when no
    credentials are found -- an unreachable or unauthenticated endpoint
    surfaces at the first real RPC call (``run_classifier``'s preflight, or
    a script's own connectivity probe), not here.
    """
    auth = get_btc_auth(args.rpc_user, args.rpc_pass)
    return make_rpc(args.rpc_url, auth)


def _default_all_valid(output_default: str, key: str) -> str:
    """Derive the ``--all-valid`` default: ``<output's dir>/<key>_btc_valid.csv``.

    Every existing wrapper's ``--all-valid`` default followed this pattern
    (``data/ixcoin_btc_valid.csv`` alongside ``data/ixcoin_stale_blocks.csv``,
    ``~/uno-extract/unobtanium_btc_valid.csv`` alongside that archive's
    output, terracoin's directory-less ``terracoin_btc_valid.csv``), so
    deriving it from the (possibly overridden) ``--output`` default
    reproduces every historical default without a separate override for it.
    """
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
    """Add ``--input``/``--output``/``--validated-output``/``--all-valid``/``--keep-near``.

    Defaults derive from ``spec`` unless overridden: ``--input`` from
    ``spec.input_csv``, ``--output`` from ``spec.output_csv``,
    ``--validated-output`` from ``spec.validated_csv``, and ``--all-valid``
    from :func:`_default_all_valid` against the (possibly overridden)
    ``--output`` default. Pass an explicit override only where a script's
    historical default differs from the spec.
    """
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
