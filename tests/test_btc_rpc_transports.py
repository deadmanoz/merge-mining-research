"""Unit tests for the shared BtcRpc requests transport.

This backs the HTTP RPC in the committed-data classifiers (huntercoin,
geistgeld, groupcoin, emercoin, coiledcoin), so a regression in the shared
module would silently break all of them at once.
"""

from __future__ import annotations

from unittest import mock

from stale_blocks_analysis import btc_rpc_transports as T
from stale_blocks_analysis.btc_rpc import BtcRpc


def test_requests_transport_wires_url_auth_and_timeout() -> None:
    with mock.patch.object(T.requests, "post") as post:
        post.return_value = mock.Mock(
            content=b'{"id":0,"result":1}', raise_for_status=lambda: None
        )
        transport = T.make_requests_transport("http://node:1", ("u", "p"), timeout=60)
        out = transport(b'[{"id":0}]')

    assert post.call_args.args[0] == "http://node:1"
    assert post.call_args.kwargs["auth"] == ("u", "p")
    assert post.call_args.kwargs["timeout"] == 60
    assert out == b'{"id":0,"result":1}'


def test_make_rpc_builds_a_requests_backed_client() -> None:
    rpc = T.make_rpc("http://n:1", ("u", "p"))
    assert isinstance(rpc, BtcRpc)
    assert rpc.url == "http://n:1"
    assert rpc.auth == ("u", "p")
