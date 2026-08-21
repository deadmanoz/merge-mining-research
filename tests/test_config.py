"""Contract tests for acquisition-side data-source paths in config.py."""

import importlib
from pathlib import Path

from stale_blocks_analysis import config


def test_local_mining_pools_dir_defaults_under_data(monkeypatch):
    monkeypatch.delenv("LOCAL_MINING_POOLS_DIR", raising=False)
    reloaded = importlib.reload(config)
    try:
        assert isinstance(reloaded.LOCAL_MINING_POOLS_DIR, Path)
        assert reloaded.LOCAL_MINING_POOLS_DIR == reloaded.DATA_DIR / "mining-pools"
    finally:
        importlib.reload(config)


def test_local_mining_pools_dir_honors_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCAL_MINING_POOLS_DIR", str(tmp_path / "pools-clone"))
    reloaded = importlib.reload(config)
    try:
        assert reloaded.LOCAL_MINING_POOLS_DIR == tmp_path / "pools-clone"
    finally:
        monkeypatch.delenv("LOCAL_MINING_POOLS_DIR", raising=False)
        importlib.reload(config)
