"""Child-chain JSON-RPC. Per-thread sessions; connection errors and HTTP 429 retry with jitter.

JSON-RPC 2.0 (Elastos named params) and 1.0-with-auth (Emercoin) share this client.
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
        """POST with retry. Does not interpret an RPC-level error payload."""
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
        """One call. ``params`` may be a list or a dict. An RPC error raises."""
        payload = {"jsonrpc": self.jsonrpc, "id": 0, "method": method, "params": params}
        data = self._request(payload, f"{method}({params})")
        if data.get("error"):
            raise RuntimeError(f"RPC error for {method}({params}): {data['error']}")
        return data["result"]

    def batch(self, calls: list) -> list:
        """A batch returns per-item errors to the caller. Exhausted retries raise."""
        return self._request(calls, f"a batch of {len(calls)} calls")
