"""Shared Hathor REST client for the prep scripts.

A thread-pooled ``requests`` client with jittered backoff on connection errors
and 429/502/503/504 responses, mirroring extract_hathor_auxpow.py's
session/backoff pattern. Both backfill_hathor_gaps.py and
supplement_hathor_funds_graph.py use it, differing only in the user-agent.
Co-located under scripts/prep/ and imported by the scripts (whose own
directory is on sys.path when run directly).
"""

from __future__ import annotations

import random
import threading
import time

import requests
from requests.adapters import HTTPAdapter


class HathorClient:
    """Thread-pooled Hathor REST client with jittered backoff."""

    def __init__(
        self,
        base_url: str,
        user_agent: str,
        timeout: float = 30.0,
        max_retries: int = 30,
        pool_size: int = 16,
    ):
        self.base_url = base_url.rstrip("/")
        self.user_agent = user_agent
        self.timeout = timeout
        self.max_retries = max_retries
        self.pool_size = pool_size
        self._tls = threading.local()

    def _session(self) -> requests.Session:
        """Return this thread's pooled ``requests.Session``, creating it on first use."""
        s = getattr(self._tls, "session", None)
        if s is None:
            s = requests.Session()
            s.headers.update(
                {
                    "user-agent": self.user_agent,
                    "accept": "application/json",
                }
            )
            adapter = HTTPAdapter(
                pool_connections=self.pool_size,
                pool_maxsize=self.pool_size,
            )
            s.mount("http://", adapter)
            s.mount("https://", adapter)
            self._tls.session = s
        return s

    def get_json(self, path: str, params: dict | None = None) -> dict:
        """GET ``path`` and return the parsed JSON body, retrying with backoff
        on a connection error or a 429/502/503/504 status.

        Raises ``RuntimeError`` if ``max_retries`` is exhausted.
        """
        url = f"{self.base_url}{path}"
        session = self._session()
        backoff = 0.2
        for attempt in range(self.max_retries):
            try:
                resp = session.get(url, params=params, timeout=self.timeout)
            except requests.RequestException:
                if attempt == self.max_retries - 1:
                    raise
                time.sleep(min(backoff, 5.0) + random.uniform(0, 0.3))
                backoff = min(backoff * 1.7, 5.0)
                continue
            if resp.status_code in (429, 502, 503, 504):
                time.sleep(min(backoff, 5.0) + random.uniform(0, 0.3))
                backoff = min(backoff * 1.7, 5.0)
                continue
            resp.raise_for_status()
            return resp.json()
        raise RuntimeError(f"Exceeded {self.max_retries} retries for GET {url}")
