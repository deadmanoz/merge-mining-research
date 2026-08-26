"""Shared schema, row seal, and HTTP transport for Hathor acquisition."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from http.client import IncompleteRead
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


ACQUISITION_COLUMNS = [
    "hathor_height",
    "hathor_block_hash",
    "hathor_timestamp",
    "aux_pow_hex",
    "funds_graph_hex",
    "raw_hex",
    "endpoint",
    "http_status",
    "attempt_count",
    "record_sha256",
]


@dataclass(frozen=True)
class HttpResult:
    status: int | None
    payload: dict[str, Any] | None
    error: str | None
    retryable: bool


class PacedHttpClient:
    """Sequential JSON client with request pacing and bounded retries."""

    def __init__(
        self,
        requests_per_second: float,
        timeout: float,
        max_attempts: int,
        *,
        user_agent: str = "merge-mining-research/hathor-acquisition",
        opener: Callable[..., Any] = urlopen,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.min_interval = 1.0 / requests_per_second
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.user_agent = user_agent
        self.opener = opener
        self.sleep = sleep
        self.monotonic = monotonic
        self._last_request_start: float | None = None

    def get_json(
        self,
        endpoint: str,
        path: str,
        params: Mapping[str, str | int],
    ) -> HttpResult:
        """Fetch a paced JSON response without hiding terminal failures."""
        url = f"{endpoint.rstrip('/')}{path}?{urlencode(params)}"
        request = Request(
            url,
            headers={"accept": "application/json", "user-agent": self.user_agent},
        )
        now = self.monotonic()
        if self._last_request_start is not None:
            remaining = self.min_interval - (now - self._last_request_start)
            if remaining > 0:
                self.sleep(remaining)
        self._last_request_start = self.monotonic()
        try:
            with self.opener(request, timeout=self.timeout) as response:
                status = response.getcode()
                try:
                    body = response.read()
                except IncompleteRead:
                    return HttpResult(status, None, "IncompleteRead", True)
                try:
                    payload = json.loads(body)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return HttpResult(status, None, "invalid_json", True)
                if not isinstance(payload, dict):
                    return HttpResult(status, None, "json_not_object", True)
                return HttpResult(status, payload, None, False)
        except HTTPError as error:
            return HttpResult(
                error.code,
                None,
                f"http_{error.code}",
                error.code in {429, 500, 502, 503, 504},
            )
        except (URLError, TimeoutError, OSError, IncompleteRead) as error:
            return HttpResult(None, None, type(error).__name__, True)


def acquisition_record_sha256(row: Mapping[str, object]) -> str:
    """Return the seal over every acquisition field except the seal itself."""
    digest = hashlib.sha256()
    for column in ACQUISITION_COLUMNS[:-1]:
        value = row.get(column)
        if value is None:
            raise ValueError(f"acquisition row is missing {column}")
        encoded = str(value).encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()
