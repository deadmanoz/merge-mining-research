"""Shared Bitcoin Core JSON-RPC client and auth resolution.

This module unifies the batched JSON-RPC + auth logic shared by the per-chain
classifiers under ``scripts/classify/`` and extractors under
``scripts/extract/``.

It is deliberately **stdlib-only**: the default transport uses
``urllib.request`` so the module imports and runs on package-less hosts
(some extract scripts run on NixOS / dependency-light boxes, and one
deliberately avoids ``requests``). A caller may inject an alternative
``transport`` callable -- for example a ``requests`` POST, or the
SSH-tunnel helper used by ``classify_emercoin_stales.py`` /
``classify_groupcoin_stales.py``.

Auth resolution (``get_btc_auth``) mirrors the harvested logic from
``classify_ixcoin_stales.py`` and ``classify_syscoin_stales.py``: try the
Bitcoin Core ``.cookie`` first, then parse ``bitcoin.conf`` for
``rpcuser`` / ``rpcpassword``. CLI overrides and the
``BITCOIN_RPC_USER`` / ``BITCOIN_RPC_PASSWORD`` env vars (from the
emercoin/groupcoin variant) are honoured first.
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
    """Resolve Bitcoin Core RPC ``(user, password)`` credentials.

    Resolution order (first match wins):

      1. Explicit ``cli_user`` / ``cli_pass`` (both must be set).
      2. ``BITCOIN_RPC_USER`` / ``BITCOIN_RPC_PASSWORD`` env vars.
      3. The Bitcoin Core ``.cookie`` file (``__cookie__:<token>``).
      4. ``rpcuser`` / ``rpcpassword`` in ``bitcoin.conf``.

    ``conf_path``, when provided, is searched ahead of the default conf
    locations. The cookie token is returned verbatim as a ``(user, password)``
    tuple, matching the inline copies being replaced.

    Returns ``None`` when no credentials can be found.
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
    """Build a stdlib ``urllib.request`` POST transport.

    Returned callable takes the JSON-encoded request body (bytes) and returns
    the raw response body (bytes). HTTP basic auth is applied from ``auth``.
    """

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
    """Batched Bitcoin Core JSON-RPC client.

    By default uses a stdlib ``urllib.request`` transport so it runs on
    dependency-light hosts. Inject ``transport`` -- a callable taking the
    JSON-encoded request body (bytes) and returning the raw response body
    (bytes) -- to use ``requests``, an SSH-tunnelled helper, or canned
    responses in tests.
    """

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
        """Send a JSON-RPC batch and return results sorted by ``id``.

        ``calls`` is a list of JSON-RPC call dicts (each carrying ``id``,
        ``method``, ``params``). The response list is sorted by ``id`` so
        callers can zip results back to inputs positionally, matching the
        ``responses.sort(key=lambda x: x["id"])`` pattern in the inline copies.
        """
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
    """Functional drop-in for the inline ``btc_rpc_batch`` copies.

    Returns the batch responses sorted by ``id``. Provide ``transport`` to
    reuse an SSH-tunnel/requests sender; otherwise a stdlib urllib POST is
    used.
    """
    return BtcRpc(url=url, auth=auth, timeout=timeout, transport=transport).batch(calls)
