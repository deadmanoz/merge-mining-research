"""Optional ``requests`` transport for ``BtcRpc``. Kept out of ``btc_rpc`` so that module stays stdlib-only.

A transport is ``Callable[[bytes], bytes]``. A remote node is reached by an
operator-owned ``ssh -L`` forward, not by this pipeline.
"""

from __future__ import annotations

import requests

from .btc_rpc import BtcRpc

BTC_RPC_HEADERS = {"content-type": "application/json"}


def make_requests_transport(url: str, auth: tuple | None, timeout: int = 120):
    """A ``BtcRpc`` transport that POSTs the JSON-RPC batch via ``requests``."""

    def _post(payload: bytes) -> bytes:
        resp = requests.post(
            url, data=payload, auth=auth, headers=BTC_RPC_HEADERS, timeout=timeout
        )
        resp.raise_for_status()
        return resp.content

    return _post


def make_rpc(url: str, auth: tuple | None, *, timeout: int = 120) -> BtcRpc:
    """Build a ``BtcRpc`` that reaches Bitcoin Core over HTTP with ``requests``."""
    return BtcRpc(
        url=url, auth=auth, transport=make_requests_transport(url, auth, timeout)
    )
