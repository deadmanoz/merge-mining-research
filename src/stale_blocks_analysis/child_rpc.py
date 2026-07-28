"""Shared child-chain JSON-RPC client with 429-aware retry/backoff.

A thread-pooled ``requests`` client for the merge-mined child chains' own
nodes/APIs (distinct from ``btc_rpc``, which talks to Bitcoin Core). Each
worker thread keeps its own keep-alive session; connection errors and HTTP 429
retry with jittered backoff. Parameterized by JSON-RPC version and optional
basic auth so both the JSON-RPC-2.0 chains (e.g. Elastos) and the
JSON-RPC-1.0-with-auth chains (e.g. Emercoin) use one implementation.
"""

from __future__ import annotations

import random
import threading
import time

import requests
from requests.adapters import HTTPAdapter


class RpcClient:
    """Thread-pooled child-chain JSON-RPC client with jittered 429 backoff."""

    def __init__(
        self,
        url: str,
        *,
        jsonrpc: str = "1.0",
        user: str = "",
        password: str = "",
        timeout: float = 30.0,
        max_retries: int = 40,
        pool_size: int = 32,
    ):
        """Store the endpoint, JSON-RPC version, optional basic-auth
        credentials, and retry/pool-sizing config for later calls.
        """
        self.url = url
        self.jsonrpc = jsonrpc
        self.auth = (user, password) if user else None
        self.timeout = timeout
        self.max_retries = max_retries
        self.pool_size = pool_size
        # Thread-local Session avoids cross-thread lock contention around the
        # connection pool; each worker keeps its own keep-alive connections.
        self._tls = threading.local()

    def _session(self) -> requests.Session:
        """Return this thread's ``requests.Session``, creating it on first use."""
        s = getattr(self._tls, "session", None)
        if s is None:
            s = requests.Session()
            s.headers.update({"content-type": "application/json"})
            adapter = HTTPAdapter(
                pool_connections=self.pool_size,
                pool_maxsize=self.pool_size,
            )
            s.mount("http://", adapter)
            s.mount("https://", adapter)
            self._tls.session = s
        return s

    def _request(self, payload, label: str):
        """POST ``payload`` with the shared retry/backoff and return the parsed
        JSON body (a dict for a single call, a list for a batch).

        Retries on connection errors and HTTP 429 with jittered backoff
        (capped at 3s per attempt, up to ``max_retries`` attempts). ``label``
        is only used in the exhausted-retries message. Does not interpret
        RPC-level errors; the caller decides what an error payload means.
        """
        session = self._session()
        backoff = 0.1
        for attempt in range(self.max_retries):
            try:
                resp = session.post(
                    self.url, json=payload, auth=self.auth, timeout=self.timeout
                )
            except requests.RequestException:
                if attempt == self.max_retries - 1:
                    raise
                time.sleep(min(backoff, 3.0) + random.uniform(0, 0.3))
                backoff = min(backoff * 1.5, 3.0)
                continue
            if resp.status_code == 429:
                time.sleep(min(backoff, 3.0) + random.uniform(0, 0.3))
                backoff = min(backoff * 1.5, 3.0)
                continue
            resp.raise_for_status()
            return resp.json()
        raise RuntimeError(f"Exceeded {self.max_retries} retries for {label}")

    def call(self, method: str, params: list | dict):
        """Issue one JSON-RPC call and return its ``result``.

        ``params`` is positional (list) or named (dict; JSON-RPC 2.0 chains
        such as Elastos take named params). Retries per ``_request`` and
        raises ``RuntimeError`` on an RPC-level error or once retries are
        exhausted.
        """
        payload = {"jsonrpc": self.jsonrpc, "id": 0, "method": method, "params": params}
        data = self._request(payload, f"{method}({params})")
        if data.get("error"):
            raise RuntimeError(f"RPC error for {method}({params}): {data['error']}")
        return data["result"]

    def batch(self, calls: list) -> list:
        """POST a pre-built JSON-RPC batch (a list of call dicts) and return the
        parsed response list.

        Unlike ``call``, this does not raise on per-item RPC errors: batch
        callers match responses by ``id`` and inspect per-call errors
        themselves. Retries per ``_request``; raises ``RuntimeError`` once
        retries are exhausted.
        """
        return self._request(calls, f"a batch of {len(calls)} calls")
