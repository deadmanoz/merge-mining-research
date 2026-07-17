# ixcoind (Docker)

Build `ixcoind` from `IXCore/IXCoin` at commit `8207734` (the `v0.14.1`
release-tag commit, "Merge pull request #2 from IXCore/DocUpdate", 2018-01-30) in
a container for AuxPoW stale-block extraction. Context: 465 accepted direct-stale
candidates (50 chronologically novel; 478 stale-labelled before the 13-row
consensus-invalid overlay) from IXC 45,001 to tip.

## Why patches are needed

IXCore v0.14.1 is a 2018-era fork of Bitcoin Core 0.14 and hasn't had a
release since. The source compiles cleanly against the toolchains of its
day (GCC 5–7 / Boost 1.58–1.65) but trips over four kinds of breakage on
modern systems:

1. **Missing `<deque>` include in `httpserver.cpp`** - Boost 1.66+ stopped
   pulling it in transitively.
2. **Boost signals2 disconnection scoping in `init.cpp`** - the modern
   `disconnect()` API requires saving the `connection` object returned by
   `connect()`, rather than calling `disconnect(slot)` on the signal.
3. **Missing `const` on five functor `operator()`s** (`main.cpp`, `miner.h`,
   `txmempool.h`) - Boost.MultiIndex now requires `const`-qualified
   comparators since 1.66+.
4. **`boost::placeholders` import in `validationinterface.cpp`** - Boost
   1.74+ moved `_1`, `_2` etc. out of the global namespace.

`patches/0001-modern-toolchain.patch` is the captured `git diff` from the
working build on `<archival-host>` (Ubuntu 24.04, GCC 13.3, Boost 1.83). 6 source
files, 142 lines.

## One-time setup

```sh
cd /opt/merge-mining-research/node-infra/ixcoin   # wherever you clone
just build      # builds image merge-mining-research/ixcoind:0.14.1
# put ixcoin.conf in ./data/ before first up (rpcuser, rpcpassword, addnode=...)
just up
just logs
```

Wallet is disabled in the build - the daemon only reads blocks. RPC is
bound to `127.0.0.1:8337` on the host; P2P listens on `0.0.0.0:8338`.

## Useful commands

```sh
just height
just peers
just status     # blockchain + peer snapshot
just shell      # drop into a shell inside the container
```

## Files

- `Dockerfile` - multi-stage, ubuntu:24.04, applies the patch to a fresh
  upstream clone pinned to the last known-good commit
- `docker-compose.yml` - runtime (volumes, ports, healthcheck)
- `patches/0001-modern-toolchain.patch` - 6-file diff; see "Why patches are
  needed" above
- `justfile` - common operations
