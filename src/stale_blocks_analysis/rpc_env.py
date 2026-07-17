"""Load private RPC credentials for chain extraction scripts."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[2]
LOCAL_ENV_FILES = (
    PROJECT_ROOT / ".env",
    PROJECT_ROOT / ".env.local",
    PROJECT_ROOT / ".env.rpc",
)
_LOADED = False


def load_local_rpc_env() -> None:
    """Load ignored local env files without overriding the process env."""
    global _LOADED
    if _LOADED:
        return
    for env_path in LOCAL_ENV_FILES:
        if env_path.exists():
            load_dotenv(env_path, override=False)
    _LOADED = True


def rpc_auth_from_env(prefix: str) -> tuple[str, str]:
    """Return RPC auth from PREFIX_RPC_* env vars or PREFIX_RPC_COOKIEFILE."""
    load_local_rpc_env()
    user = os.environ.get(f"{prefix}_RPC_USER")
    password = os.environ.get(f"{prefix}_RPC_PASSWORD") or os.environ.get(
        f"{prefix}_RPC_PASS"
    )
    if user and password:
        return user, password

    cookie_file = os.environ.get(f"{prefix}_RPC_COOKIEFILE")
    if cookie_file:
        raw = Path(cookie_file).read_text().strip()
        if ":" not in raw:
            raise RuntimeError(f"{prefix}_RPC_COOKIEFILE must contain user:password")
        cookie_user, cookie_password = raw.split(":", 1)
        return cookie_user, cookie_password

    raise RuntimeError(
        f"Set {prefix}_RPC_USER/{prefix}_RPC_PASSWORD or {prefix}_RPC_COOKIEFILE"
    )
