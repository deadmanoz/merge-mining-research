"""Optional ``requests``-backed transport for ``BtcRpc``.

Kept separate from ``btc_rpc`` (which is stdlib-only, urllib-based) so the base
client carries no third-party dependency. Import this in the classifiers that
reach Bitcoin Core over HTTP with ``requests`` (a shared session with
connection pooling helps a large classification run).

A ``BtcRpc`` transport is a ``Callable[[bytes], bytes]``: it takes the encoded
JSON-RPC batch payload and returns the raw response body for ``BtcRpc`` to
parse.

When Bitcoin Core runs on another host, forward its RPC port to localhost with
``ssh -L 8332:localhost:8332 <host>`` and point ``--rpc-url`` at the forward.
Reaching the node is the operator's concern, not the pipeline's; see
``node-infra/README.md``.
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
