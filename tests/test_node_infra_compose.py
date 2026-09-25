"""Rendered Compose policy tests for the Terracoin and Fractal node workspaces.

Each test renders a real committed profile combination with
`docker compose config --format json` under an empty env file, a controlled
synthetic environment and a bounded timeout, then asserts the operational
policy documented in `node-infra/`: noncreating retained binds, disabled
restart by default, offline port resets and isolation flags, omitted bootstrap
import, live RPC scoping and live resource limits. Rendering never starts
containers, builds or pulls images, or contacts an RPC endpoint.

The Docker Compose CLI is a hard prerequisite: a missing or failing renderer
fails these tests instead of skipping them, so the policy coverage cannot
silently disappear. The unsafe-case tests render temporary mutated copies of
the real profiles and require the policy assertions to reject them; the
committed profiles themselves are never modified.
"""

import functools
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TERRACOIN_DIR = REPO_ROOT / "node-infra" / "terracoin"
FRACTAL_DIR = REPO_ROOT / "node-infra" / "fractal"

RENDER_TIMEOUT_SECONDS = 60
PROJECT_NAME = "mmr-compose-policy-test"

TERRACOIN_DATADIR = "/home/terracoin/.terracoincore"
FRACTAL_DATADIR = "/home/fractal/.fractal"

# Synthetic, publicly reserved (TEST-NET-2) addresses stand in for the private
# live RPC selections; no real host, datadir or node is ever contacted.
RPC_BIND = "198.51.100.23"
RPC_CLIENT = "198.51.100.24"

TERRACOIN_ENV = {"TERRACOIN_DATA_DIR": "/srv/mmr-compose-policy-test/terracoin"}
FRACTAL_ENV = {"FRACTAL_DATA_DIR": "/srv/mmr-compose-policy-test/fractal"}
TERRACOIN_LIVE_ENV = {
    **TERRACOIN_ENV,
    "TERRACOIN_RPC_BIND": RPC_BIND,
    "TERRACOIN_RPC_CLIENT": RPC_CLIENT,
}

TERRACOIN_BASE = [TERRACOIN_DIR / "docker-compose.yml"]
TERRACOIN_OFFLINE = [
    TERRACOIN_DIR / "docker-compose.yml",
    TERRACOIN_DIR / "compose.offline.yml",
]
TERRACOIN_LIVE = [
    TERRACOIN_DIR / "docker-compose.yml",
    TERRACOIN_DIR / "compose.live.yml",
]
FRACTAL_BASE = [FRACTAL_DIR / "docker-compose.yml"]
FRACTAL_OFFLINE = [
    FRACTAL_DIR / "docker-compose.yml",
    FRACTAL_DIR / "compose.offline.yml",
]

FOUR_PROFILES = [
    (
        "terracoin-offline",
        TERRACOIN_OFFLINE,
        TERRACOIN_ENV,
        "terracoind",
        TERRACOIN_DATADIR,
    ),
    (
        "terracoin-live",
        TERRACOIN_LIVE,
        TERRACOIN_LIVE_ENV,
        "terracoind",
        TERRACOIN_DATADIR,
    ),
    ("fractal-base", FRACTAL_BASE, FRACTAL_ENV, "fractald", FRACTAL_DATADIR),
    ("fractal-offline", FRACTAL_OFFLINE, FRACTAL_ENV, "fractald", FRACTAL_DATADIR),
]

_renderer_checked = False


def _require_renderer():
    """Fail loudly when the Docker Compose CLI cannot render configs."""
    global _renderer_checked
    if _renderer_checked:
        return
    if shutil.which("docker") is None:
        raise RuntimeError(
            "docker is not on PATH: the node-infra Compose policy tests require "
            "the Docker Compose CLI (see README test prerequisites)"
        )
    result = subprocess.run(
        ["docker", "compose", "version"],
        capture_output=True,
        text=True,
        timeout=RENDER_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "docker compose is unavailable: the node-infra Compose policy tests "
            f"require the Compose CLI: {result.stderr.strip()}"
        )
    _renderer_checked = True


def render(files, env_vars):
    """Render the ordered Compose files and return the parsed JSON model."""
    _require_renderer()
    with tempfile.TemporaryDirectory() as tmp:
        empty_env = Path(tmp) / "empty.env"
        empty_env.write_text("")
        command = [
            "docker",
            "compose",
            "--project-name",
            PROJECT_NAME,
            "--env-file",
            str(empty_env),
        ]
        for path in files:
            command += ["-f", str(path)]
        command += ["config", "--format", "json"]
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            **env_vars,
        }
        return subprocess.run(
            command,
            cwd=files[0].parent,
            env=env,
            capture_output=True,
            text=True,
            timeout=RENDER_TIMEOUT_SECONDS,
        )


def render_service(files, env_vars, service_name):
    result = render(files, env_vars)
    assert result.returncode == 0, (
        f"compose render failed for {[p.name for p in files]}: {result.stderr.strip()}"
    )
    return json.loads(result.stdout)["services"][service_name]


def _mutated_profile(tmp_path, files, filename, old, new):
    """Copy a profile combination into tmp_path with one exact mutation."""
    mutated = []
    for source in files:
        text = source.read_text()
        if source.name == filename:
            assert old in text, f"mutation anchor missing in {source}"
            text = text.replace(old, new, 1)
        target = tmp_path / source.name
        target.write_text(text)
        mutated.append(target)
    return mutated


# ── Shared policy assertions ──────────────────────────────────────────────


@functools.cache
def rendered_create_host_path(create_host_path):
    """How this renderer writes a bind declared with an explicit value.

    Compose versions disagree on which value they omit: newer renderers
    normalize the permissive default (true) away and print an explicit false,
    while older ones (v2.38 in CI) omit false and print true. Rendering a probe
    lets the policy check compare like with like on either kind.
    """
    value = "true" if create_host_path else "false"
    with tempfile.TemporaryDirectory() as tmp:
        probe = Path(tmp) / "docker-compose.yml"
        probe.write_text(
            "services:\n"
            "  probe:\n"
            "    image: busybox\n"
            "    volumes:\n"
            "      - type: bind\n"
            "        source: /srv/mmr-compose-policy-test/probe\n"
            "        target: /data\n"
            "        bind:\n"
            f"          create_host_path: {value}\n"
        )
        service = render_service([probe], {}, "probe")
    return service["volumes"][0].get("bind", {}).get("create_host_path")


def assert_retained_bind_noncreating(service, datadir_target):
    volumes = [v for v in service.get("volumes", []) if v["target"] == datadir_target]
    assert len(volumes) == 1, "exactly one retained datadir bind is expected"
    volume = volumes[0]
    assert volume["type"] == "bind"
    assert volume["target"] == datadir_target
    noncreating = rendered_create_host_path(False)
    assert noncreating != rendered_create_host_path(True), (
        "the Compose renderer cannot distinguish creating and noncreating binds"
    )
    assert volume.get("bind", {}).get("create_host_path") == noncreating


def assert_default_restart_disabled(service):
    assert service["restart"] == "no"


def assert_no_published_ports(service):
    assert not service.get("ports"), "offline profiles must reset published ports"


def assert_rpc_loopback_only(command, extra_peers=()):
    binds = [a.split("=", 1)[1] for a in command if a.startswith("-rpcbind=")]
    allows = [a.split("=", 1)[1] for a in command if a.startswith("-rpcallowip=")]
    assert binds, "an explicit rpcbind selection is required"
    assert set(binds) <= {"127.0.0.1", *extra_peers}
    assert set(allows) <= {"127.0.0.1", *extra_peers}


def assert_no_bootstrap_import(command):
    assert not any(a.startswith("-loadblock") for a in command), (
        "retained-state profiles must not import bootstrap.dat"
    )


def assert_live_resource_limits(service):
    assert int(service.get("mem_limit", 0)) == 4 * 1024**3
    assert float(service.get("cpus", 0)) == 2
    assert service.get("pids_limit") == 256


def assert_rpc_port_loopback(service, rpc_port):
    rpc = [p for p in service["ports"] if p["target"] == rpc_port]
    assert rpc, f"expected a published RPC port {rpc_port}"
    assert all(p.get("host_ip") == "127.0.0.1" for p in rpc), (
        "the RPC port must stay bound to loopback"
    )


# ── Shared retained-state rules across all four profiles ──────────────────


@pytest.mark.parametrize(
    "profile,files,env_vars,service_name,datadir",
    FOUR_PROFILES,
    ids=[p[0] for p in FOUR_PROFILES],
)
def test_retained_bind_is_noncreating(profile, files, env_vars, service_name, datadir):
    service = render_service(files, env_vars, service_name)
    assert_retained_bind_noncreating(service, datadir)
    bind = next(v for v in service["volumes"] if v["target"] == datadir)
    assert (
        bind["source"]
        == env_vars[
            "TERRACOIN_DATA_DIR" if service_name == "terracoind" else "FRACTAL_DATA_DIR"
        ]
    )
    assert service["image"], "profiles select the retained image"


@pytest.mark.parametrize(
    "profile,files,env_vars,service_name,datadir",
    FOUR_PROFILES,
    ids=[p[0] for p in FOUR_PROFILES],
)
def test_default_restart_is_disabled(profile, files, env_vars, service_name, datadir):
    assert_default_restart_disabled(render_service(files, env_vars, service_name))


@pytest.mark.parametrize(
    "profile,files,env_vars,service_name,datadir",
    FOUR_PROFILES,
    ids=[p[0] for p in FOUR_PROFILES],
)
def test_foreground_datadir_command(profile, files, env_vars, service_name, datadir):
    command = render_service(files, env_vars, service_name)["command"]
    assert isinstance(command, list), "command stays an argument array"
    assert "-daemon=0" in command
    assert f"-datadir={datadir}" in command


# ── Terracoin offline profile ─────────────────────────────────────────────


def test_terracoin_offline_isolation():
    service = render_service(TERRACOIN_OFFLINE, TERRACOIN_ENV, "terracoind")
    assert service["network_mode"] == "host"
    assert_no_published_ports(service)
    command = service["command"]
    assert "-server=1" in command
    for flag in ("-listen=0", "-dnsseed=0", "-connect=0"):
        assert flag in command
    assert_rpc_loopback_only(command)
    assert_no_bootstrap_import(command)


# ── Terracoin live profile ────────────────────────────────────────────────


def test_terracoin_live_rpc_scoping_and_resource_limits():
    service = render_service(TERRACOIN_LIVE, TERRACOIN_LIVE_ENV, "terracoind")
    assert service["network_mode"] == "host"
    assert_no_published_ports(service)
    command = service["command"]
    assert f"-rpcbind={RPC_BIND}" in command
    assert f"-rpcallowip={RPC_CLIENT}" in command
    assert "-rpcport=13332" in command
    assert "-printtoconsole" in command
    assert_rpc_loopback_only(command, extra_peers=(RPC_BIND, RPC_CLIENT))
    assert_no_bootstrap_import(command)
    assert_live_resource_limits(service)
    logging = service["logging"]
    assert logging["driver"] == "json-file"
    assert logging["options"]["max-size"] == "20m"
    assert logging["options"]["max-file"] == "3"


def test_terracoin_live_missing_required_params_fail():
    env = {k: v for k, v in TERRACOIN_LIVE_ENV.items() if k != "TERRACOIN_RPC_BIND"}
    result = render(TERRACOIN_LIVE, env)
    assert result.returncode != 0
    assert "TERRACOIN_RPC_BIND" in result.stderr

    env = {k: v for k, v in TERRACOIN_LIVE_ENV.items() if k != "TERRACOIN_RPC_CLIENT"}
    result = render(TERRACOIN_LIVE, env)
    assert result.returncode != 0
    assert "TERRACOIN_RPC_CLIENT" in result.stderr


def test_terracoin_live_explicit_restart_override():
    service = render_service(
        TERRACOIN_LIVE,
        {**TERRACOIN_LIVE_ENV, "TERRACOIN_RESTART_POLICY": "unless-stopped"},
        "terracoind",
    )
    assert service["restart"] == "unless-stopped"


def test_terracoin_base_sync_profile_imports_bootstrap():
    """The initial-sync profile keeps -loadblock; the retained-state overlays drop it."""
    service = render_service(TERRACOIN_BASE, TERRACOIN_ENV, "terracoind")
    command = service["command"]
    assert f"-loadblock={TERRACOIN_DATADIR}/bootstrap.dat" in command


# ── Fractal profiles ──────────────────────────────────────────────────────


def test_fractal_base_policy():
    service = render_service(FRACTAL_BASE, FRACTAL_ENV, "fractald")
    assert "network_mode" not in service
    assert_rpc_port_loopback(service, 18332)
    p2p = [p for p in service["ports"] if p["target"] == 18333]
    assert p2p and all("host_ip" not in p for p in p2p), "P2P stays publicly published"
    command = service["command"]
    assert f"-conf={FRACTAL_DATADIR}/bitcoin.conf" in command
    assert "-server=1" in command


def test_fractal_offline_isolation():
    service = render_service(FRACTAL_OFFLINE, FRACTAL_ENV, "fractald")
    assert service["network_mode"] == "none"
    assert_no_published_ports(service)
    command = service["command"]
    for flag in ("-listen=0", "-dnsseed=0", "-connect=0"):
        assert flag in command
    assert_rpc_loopback_only(command)


def test_fractal_explicit_restart_override():
    service = render_service(
        FRACTAL_BASE,
        {**FRACTAL_ENV, "FRACTAL_RESTART_POLICY": "unless-stopped"},
        "fractald",
    )
    assert service["restart"] == "unless-stopped"


# ── Profile differences that must be preserved ────────────────────────────


def test_offline_network_modes_differ_by_chain():
    terracoin = render_service(TERRACOIN_OFFLINE, TERRACOIN_ENV, "terracoind")
    fractal = render_service(FRACTAL_OFFLINE, FRACTAL_ENV, "fractald")
    assert terracoin["network_mode"] == "host"
    assert fractal["network_mode"] == "none"


def test_live_keeps_outbound_peers_unlike_offline():
    live = render_service(TERRACOIN_LIVE, TERRACOIN_LIVE_ENV, "terracoind")
    offline = render_service(TERRACOIN_OFFLINE, TERRACOIN_ENV, "terracoind")
    assert "-connect=0" not in live["command"]
    assert "-connect=0" in offline["command"]


# ── Unsafe mutations must fail the policy assertions ──────────────────────


def test_mutated_creating_bind_is_rejected(tmp_path):
    files = _mutated_profile(
        tmp_path,
        TERRACOIN_OFFLINE,
        "docker-compose.yml",
        "create_host_path: false",
        "create_host_path: true",
    )
    service = render_service(files, TERRACOIN_ENV, "terracoind")
    with pytest.raises(AssertionError):
        assert_retained_bind_noncreating(service, TERRACOIN_DATADIR)


def test_mutated_public_rpc_bind_is_rejected(tmp_path):
    files = _mutated_profile(
        tmp_path,
        FRACTAL_BASE,
        "docker-compose.yml",
        "${FRACTAL_RPC_BIND:-127.0.0.1}",
        "${FRACTAL_RPC_BIND:-0.0.0.0}",
    )
    service = render_service(files, FRACTAL_ENV, "fractald")
    with pytest.raises(AssertionError):
        assert_rpc_port_loopback(service, 18332)


def test_mutated_live_default_restart_is_rejected(tmp_path):
    files = _mutated_profile(
        tmp_path,
        TERRACOIN_LIVE,
        "compose.live.yml",
        "${TERRACOIN_RESTART_POLICY:-no}",
        "${TERRACOIN_RESTART_POLICY:-unless-stopped}",
    )
    service = render_service(files, TERRACOIN_LIVE_ENV, "terracoind")
    with pytest.raises(AssertionError):
        assert_default_restart_disabled(service)


def test_mutated_live_without_resource_limits_is_rejected(tmp_path):
    files = _mutated_profile(
        tmp_path,
        TERRACOIN_LIVE,
        "compose.live.yml",
        "    mem_limit: 4g\n",
        "",
    )
    service = render_service(files, TERRACOIN_LIVE_ENV, "terracoind")
    with pytest.raises(AssertionError):
        assert_live_resource_limits(service)


def test_mutated_live_bootstrap_import_is_rejected(tmp_path):
    files = _mutated_profile(
        tmp_path,
        TERRACOIN_LIVE,
        "compose.live.yml",
        '      - "-rpcport=13332"',
        f'      - "-rpcport=13332"\n      - "-loadblock={TERRACOIN_DATADIR}/bootstrap.dat"',
    )
    service = render_service(files, TERRACOIN_LIVE_ENV, "terracoind")
    with pytest.raises(AssertionError):
        assert_no_bootstrap_import(service["command"])
