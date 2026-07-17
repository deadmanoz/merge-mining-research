"""Unit tests for the shared Bitcoin Core JSON-RPC client.

All tests use a fake in-process transport (no network) and temp cookie/conf
files (no real node, no real ~/.bitcoin).
"""

from __future__ import annotations

import json

import pytest

from stale_blocks_analysis import btc_rpc
from stale_blocks_analysis.btc_rpc import BtcRpc, get_btc_auth, rpc_batch


class FakeTransport:
    """Records the decoded request payload and returns canned bytes."""

    def __init__(self, responses):
        self._responses = responses
        self.requests = []

    def __call__(self, payload: bytes) -> bytes:
        self.requests.append(json.loads(payload))
        return json.dumps(self._responses).encode("utf-8")


# ── batch ordering ──────────────────────────────────────────────────────


def test_batch_sorts_by_id():
    # Node returns results out of id order; client must sort by id.
    fake = FakeTransport(
        [
            {"id": 2, "result": "two", "error": None},
            {"id": 0, "result": "zero", "error": None},
            {"id": 1, "result": "one", "error": None},
        ]
    )
    rpc = BtcRpc(transport=fake)
    calls = [
        {"jsonrpc": "1.0", "id": i, "method": "getblockheader", "params": [str(i)]}
        for i in range(3)
    ]
    out = rpc.batch(calls)
    assert [r["id"] for r in out] == [0, 1, 2]
    assert [r["result"] for r in out] == ["zero", "one", "two"]
    # Payload was sent verbatim (3 calls).
    assert len(fake.requests[0]) == 3


def test_batch_empty_short_circuits():
    fake = FakeTransport([])
    rpc = BtcRpc(transport=fake)
    assert rpc.batch([]) == []
    # No transport invocation for an empty batch.
    assert fake.requests == []


def test_rpc_batch_functional_drop_in():
    fake = FakeTransport(
        [
            {"id": 1, "result": "b", "error": None},
            {"id": 0, "result": "a", "error": None},
        ]
    )
    calls = [
        {"jsonrpc": "1.0", "id": 0, "method": "getblockcount", "params": []},
        {"jsonrpc": "1.0", "id": 1, "method": "getblockcount", "params": []},
    ]
    out = rpc_batch(calls, auth=("u", "p"), transport=fake)
    assert [r["id"] for r in out] == [0, 1]
    assert [r["result"] for r in out] == ["a", "b"]


# ── single call + error handling ─────────────────────────────────────────


def test_call_returns_result():
    fake = FakeTransport([{"id": 0, "result": 850000, "error": None}])
    rpc = BtcRpc(transport=fake)
    assert rpc.call("getblockcount") == 850000
    sent = fake.requests[0][0]
    assert sent["method"] == "getblockcount"
    assert sent["params"] == []


def test_call_with_params():
    fake = FakeTransport([{"id": 0, "result": {"height": 7}, "error": None}])
    rpc = BtcRpc(transport=fake)
    assert rpc.call("getblockheader", ["deadbeef"]) == {"height": 7}
    assert fake.requests[0][0]["params"] == ["deadbeef"]


def test_call_raises_on_error():
    fake = FakeTransport(
        [{"id": 0, "result": None, "error": {"code": -5, "message": "not found"}}]
    )
    rpc = BtcRpc(transport=fake)
    with pytest.raises(RuntimeError) as exc:
        rpc.call("getblockheader", ["bad"])
    assert "not found" in str(exc.value)


def test_call_none_result_no_error_returns_none():
    # getblockheader on a non-canonical hash: result null, no error.
    fake = FakeTransport([{"id": 0, "result": None, "error": None}])
    rpc = BtcRpc(transport=fake)
    assert rpc.call("getblockheader", ["unknownhash"]) is None


# ── injected transport sees encoded bytes ────────────────────────────────


def test_transport_receives_bytes():
    captured = {}

    def transport(payload: bytes) -> bytes:
        captured["type"] = type(payload)
        captured["decoded"] = json.loads(payload)
        return json.dumps([{"id": 0, "result": "ok", "error": None}]).encode()

    rpc = BtcRpc(transport=transport)
    assert rpc.call("ping") == "ok"
    assert captured["type"] is bytes
    assert captured["decoded"][0]["method"] == "ping"


# ── auth resolution ──────────────────────────────────────────────────────


def test_auth_cli_override_wins():
    assert get_btc_auth(cli_user="alice", cli_pass="secret") == ("alice", "secret")


def test_auth_cli_partial_ignored(monkeypatch):
    # Only one of user/pass set -> falls through. With nothing else, None.
    monkeypatch.delenv("BITCOIN_RPC_USER", raising=False)
    monkeypatch.delenv("BITCOIN_RPC_PASSWORD", raising=False)
    monkeypatch.setattr(btc_rpc, "_COOKIE_PATHS", ["/nonexistent/.cookie"])
    monkeypatch.setattr(btc_rpc, "_CONF_PATHS", ["/nonexistent/bitcoin.conf"])
    assert get_btc_auth(cli_user="alice", cli_pass=None) is None


def test_auth_env_vars(monkeypatch):
    monkeypatch.setenv("BITCOIN_RPC_USER", "envuser")
    monkeypatch.setenv("BITCOIN_RPC_PASSWORD", "envpass")
    assert get_btc_auth() == ("envuser", "envpass")


def test_auth_cookie_file(monkeypatch, tmp_path):
    monkeypatch.delenv("BITCOIN_RPC_USER", raising=False)
    monkeypatch.delenv("BITCOIN_RPC_PASSWORD", raising=False)
    cookie = tmp_path / ".cookie"
    cookie.write_text("__cookie__:abc123token\n")
    monkeypatch.setattr(btc_rpc, "_COOKIE_PATHS", [str(cookie)])
    monkeypatch.setattr(btc_rpc, "_CONF_PATHS", ["/nonexistent/bitcoin.conf"])
    assert get_btc_auth() == ("__cookie__", "abc123token")


def test_auth_cookie_with_colon_in_token(monkeypatch, tmp_path):
    # Token may itself contain colons; split only on the first.
    monkeypatch.delenv("BITCOIN_RPC_USER", raising=False)
    monkeypatch.delenv("BITCOIN_RPC_PASSWORD", raising=False)
    cookie = tmp_path / ".cookie"
    cookie.write_text("__cookie__:tok:en:with:colons")
    monkeypatch.setattr(btc_rpc, "_COOKIE_PATHS", [str(cookie)])
    monkeypatch.setattr(btc_rpc, "_CONF_PATHS", ["/nonexistent/bitcoin.conf"])
    assert get_btc_auth() == ("__cookie__", "tok:en:with:colons")


def test_auth_conf_fallback(monkeypatch, tmp_path):
    monkeypatch.delenv("BITCOIN_RPC_USER", raising=False)
    monkeypatch.delenv("BITCOIN_RPC_PASSWORD", raising=False)
    conf = tmp_path / "bitcoin.conf"
    conf.write_text("server=1\nrpcuser=confuser\nrpcpassword=confpass\n")
    monkeypatch.setattr(btc_rpc, "_COOKIE_PATHS", ["/nonexistent/.cookie"])
    monkeypatch.setattr(btc_rpc, "_CONF_PATHS", ["/nonexistent/bitcoin.conf"])
    assert get_btc_auth(conf_path=str(conf)) == ("confuser", "confpass")


def test_auth_conf_default_paths(monkeypatch, tmp_path):
    monkeypatch.delenv("BITCOIN_RPC_USER", raising=False)
    monkeypatch.delenv("BITCOIN_RPC_PASSWORD", raising=False)
    conf = tmp_path / "bitcoin.conf"
    conf.write_text("rpcuser=defuser\nrpcpassword=defpass\n")
    monkeypatch.setattr(btc_rpc, "_COOKIE_PATHS", ["/nonexistent/.cookie"])
    monkeypatch.setattr(btc_rpc, "_CONF_PATHS", [str(conf)])
    assert get_btc_auth() == ("defuser", "defpass")


def test_auth_none_when_nothing_found(monkeypatch):
    monkeypatch.delenv("BITCOIN_RPC_USER", raising=False)
    monkeypatch.delenv("BITCOIN_RPC_PASSWORD", raising=False)
    monkeypatch.setattr(btc_rpc, "_COOKIE_PATHS", ["/nonexistent/.cookie"])
    monkeypatch.setattr(btc_rpc, "_CONF_PATHS", ["/nonexistent/bitcoin.conf"])
    assert get_btc_auth() is None


def test_auth_cookie_takes_precedence_over_conf(monkeypatch, tmp_path):
    monkeypatch.delenv("BITCOIN_RPC_USER", raising=False)
    monkeypatch.delenv("BITCOIN_RPC_PASSWORD", raising=False)
    cookie = tmp_path / ".cookie"
    cookie.write_text("__cookie__:cookietoken")
    conf = tmp_path / "bitcoin.conf"
    conf.write_text("rpcuser=confuser\nrpcpassword=confpass\n")
    monkeypatch.setattr(btc_rpc, "_COOKIE_PATHS", [str(cookie)])
    monkeypatch.setattr(btc_rpc, "_CONF_PATHS", [str(conf)])
    assert get_btc_auth() == ("__cookie__", "cookietoken")
