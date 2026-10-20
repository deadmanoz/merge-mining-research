"""Stdlib Bitcoin Core JSON-RPC client. Inject ``transport`` for requests or an SSH tunnel.

``get_btc_auth`` tries explicit flags, then ``BITCOIN_RPC_USER`` /
``BITCOIN_RPC_PASSWORD``, then ``.cookie``, then ``bitcoin.conf``.
"""

from __future__ import annotations

import base64
import json
import os
import re
from typing import Callable, Optional

import urllib.request

# A transport takes the raw request body (already JSON-encoded bytes) and
# returns the raw response body (bytes). This abstraction lets tests feed
# canned responses with no network, and lets callers swap in requests or an
# SSH-tunnelled helper without changing BtcRpc.
Transport = Callable[[bytes], bytes]

DEFAULT_URL = "http://127.0.0.1:8332"
DEFAULT_TIMEOUT = 30
_RPC_HEADERS = {"content-type": "application/json"}

# Standard locations, in resolution order.
_COOKIE_PATHS = [
    os.path.expanduser("~/.bitcoin/.cookie"),
]
_CONF_PATHS = [
    "/etc/bitcoin/bitcoin.conf",
    os.path.expanduser("~/.bitcoin/bitcoin.conf"),
]


def get_btc_auth(
    cli_user: Optional[str] = None,
    cli_pass: Optional[str] = None,
    conf_path: Optional[str] = None,
) -> Optional[tuple[str, str]]:
    """First match: both CLI values, env vars, ``.cookie``, then ``bitcoin.conf``.

    A supplied ``conf_path`` is searched before the defaults. Returns None
    when nothing matches. The cookie token is the password.
    """
    if cli_user and cli_pass:
        return (cli_user, cli_pass)

    env_user = os.environ.get("BITCOIN_RPC_USER")
    env_pass = os.environ.get("BITCOIN_RPC_PASSWORD")
    if env_user and env_pass:
        return (env_user, env_pass)

    for path in _COOKIE_PATHS:
        try:
            with open(path) as f:
                cookie = f.read().strip()
            user, password = cookie.split(":", 1)
            return (user, password)
        except (FileNotFoundError, ValueError):
            continue

    conf_paths = ([conf_path] if conf_path else []) + _CONF_PATHS
    for path in conf_paths:
        try:
            with open(path) as f:
                content = f.read()
        except FileNotFoundError:
            continue
        user_match = re.search(r"rpcuser=(.+)", content)
        pass_match = re.search(r"rpcpassword=(.+)", content)
        if user_match and pass_match:
            return (user_match.group(1).strip(), pass_match.group(1).strip())

    return None


def _urllib_transport(
    url: str,
    auth: Optional[tuple[str, str]],
    timeout: float,
) -> Transport:
    """Urllib POST. The callable takes the request body and returns the response body."""

    def _post(payload: bytes) -> bytes:
        """POST the payload over urllib with optional basic auth; return the body."""
        headers = dict(_RPC_HEADERS)
        if auth is not None:
            user, password = auth
            token = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
            headers["Authorization"] = f"Basic {token}"
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()

    return _post


class BtcRpc:
    """Batched client. Default transport is urllib so package-less hosts can import it."""

    def __init__(
        self,
        url: str = DEFAULT_URL,
        auth: Optional[tuple[str, str]] = None,
        timeout: float = DEFAULT_TIMEOUT,
        transport: Optional[Transport] = None,
    ) -> None:
        self.url = url
        self.auth = auth
        self.timeout = timeout
        self._transport = transport or _urllib_transport(url, auth, timeout)

    def batch(self, calls: list[dict]) -> list:
        """Results sorted by ``id`` so callers can zip them back to ``calls``."""
        if not calls:
            return []
        payload = json.dumps(calls).encode("utf-8")
        raw = self._transport(payload)
        responses = json.loads(raw)
        responses.sort(key=lambda x: x["id"])
        return responses

    def call(self, method: str, params: Optional[list] = None):
        """Make a single JSON-RPC call and return its ``result``.

        Raises ``RuntimeError`` if the node returns a JSON-RPC ``error``.
        """
        call = {
            "jsonrpc": "1.0",
            "id": 0,
            "method": method,
            "params": params if params is not None else [],
        }
        responses = self.batch([call])
        resp = responses[0]
        if resp.get("error") is not None:
            raise RuntimeError(f"RPC error for {method}: {resp['error']}")
        return resp.get("result")


def rpc_batch(
    calls: list[dict],
    auth: Optional[tuple[str, str]],
    url: str = DEFAULT_URL,
    transport: Optional[Transport] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> list:
    """Same sorted batch. ``transport`` overrides the urllib POST."""
    return BtcRpc(url=url, auth=auth, timeout=timeout, transport=transport).batch(calls)
