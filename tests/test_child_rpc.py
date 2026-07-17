"""Unit tests for the shared child-chain JSON-RPC client.

Backs the Elastos (JSON-RPC 2.0, no auth) and Emercoin (JSON-RPC 1.0, basic
auth) extractors, both of which produce committed loader inputs, so the
version/auth contract is pinned here.
"""

from __future__ import annotations

from unittest import mock

from stale_blocks_analysis import child_rpc


def _mock_session(response_json):
    session = mock.Mock()
    session.headers = {}
    session.post.return_value = mock.Mock(
        status_code=200, raise_for_status=lambda: None, json=lambda: response_json
    )
    return session


def test_call_uses_configured_jsonrpc_and_no_auth_by_default() -> None:
    with mock.patch.object(child_rpc.requests, "Session") as Session:
        Session.return_value = _mock_session({"id": 0, "result": 42})
        result = child_rpc.RpcClient("http://ela", jsonrpc="2.0").call(
            "getblockcount", []
        )

    post = Session.return_value.post
    assert result == 42
    assert post.call_args.kwargs["json"]["jsonrpc"] == "2.0"
    assert post.call_args.kwargs["auth"] is None


def test_call_sends_basic_auth_when_credentials_given() -> None:
    with mock.patch.object(child_rpc.requests, "Session") as Session:
        Session.return_value = _mock_session({"id": 0, "result": 7})
        client = child_rpc.RpcClient(
            "http://emc", jsonrpc="1.0", user="u", password="p"
        )
        result = client.call("getblockcount", [])

    post = Session.return_value.post
    assert result == 7
    assert post.call_args.kwargs["json"]["jsonrpc"] == "1.0"
    assert post.call_args.kwargs["auth"] == ("u", "p")


def test_call_raises_on_rpc_level_error() -> None:
    with mock.patch.object(child_rpc.requests, "Session") as Session:
        Session.return_value = _mock_session(
            {"id": 0, "error": {"code": -1, "message": "boom"}}
        )
        try:
            child_rpc.RpcClient("http://x").call("bad", [])
        except RuntimeError as exc:
            assert "boom" in str(exc)
        else:
            raise AssertionError("expected RuntimeError on an RPC-level error")


def test_batch_posts_the_call_list_verbatim_and_returns_the_response_list() -> None:
    calls = [
        {"jsonrpc": "1.0", "id": 0, "method": "getblockhash", "params": [1]},
        {"jsonrpc": "1.0", "id": 1, "method": "getblockhash", "params": [2]},
    ]
    response = [{"id": 0, "result": "aa"}, {"id": 1, "result": "bb"}]
    with mock.patch.object(child_rpc.requests, "Session") as Session:
        Session.return_value = _mock_session(response)
        client = child_rpc.RpcClient("http://x", user="u", password="p")
        result = client.batch(calls)

    post = Session.return_value.post
    assert result == response
    assert post.call_args.kwargs["json"] is calls
    assert post.call_args.kwargs["auth"] == ("u", "p")


def test_batch_does_not_raise_on_per_item_error() -> None:
    # A batch response can carry per-call errors; batch() returns them for the
    # caller to inspect by id rather than raising (that is call()'s job).
    response = [{"id": 0, "result": "ok"}, {"id": 1, "error": {"message": "nope"}}]
    with mock.patch.object(child_rpc.requests, "Session") as Session:
        Session.return_value = _mock_session(response)
        result = child_rpc.RpcClient("http://x").batch([{"id": 0}, {"id": 1}])
    assert result == response
