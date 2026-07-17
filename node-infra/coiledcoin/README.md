# coiledcoind (Docker)

Build `coiledcoind` from `mmpool/coiledcoin` at commit `0aa503c` (the last
commit on the upstream repo, "Add checkpoint at block 438,000") in a
container, for cross-confirmation of AuxPoW stale blocks against ixcoin and
devcoin recovery.

See `../../docs/chains/coiledcoin.md` for recovery details - 27 stales,
zero novel (full overlap with ixcoin + devcoin); retained as cross-evidence.

## Why the unusual base image and fetched Berkeley DB tarball

CoiledCoin is a 2012 Bitcoin 0.6-era codebase. The build needs:

- **GCC 5.4 / Boost 1.58 / OpenSSL 1.0.2** - pre-`std::auto_ptr` removal,
  pre-OpenSSL-1.1 opaque structs. `ubuntu:16.04` (xenial) ships these
  versions; building on anything newer requires patching dozens of call sites.
- **Berkeley DB 4.8.30 with C++ bindings** - required for the wallet/db code.
  Xenial doesn't package it, so we build it from the Oracle source tarball
  (`db-4.8.30.NC.tar.gz`). Rather than vendor a 22 MB binary into this
  repository, the Dockerfile fetches it at build time with a pinned SHA-256
  (`12edc0df…364ef`) from the Bitcoin Core `depends` mirror, which has hosted
  this exact file for years; override `BDB_URL` to use your own mirror.
  `bdb-atomic.patch` fixes one `__atomic_compare_exchange` clash with modern
  libc; `config.guess` and `config.sub` are refreshed copies that teach BDB's
  old autotools about modern arches (the originals from 2010 don't recognise
  `aarch64`).

Berkeley DB 4.8.30 ships under the Sleepycat License (the Oracle Berkeley DB
1.x to 6.0 license; the full text is in `LICENSE` inside the tarball). The
checksum pin makes the fetched source verifiable and reproducible. Newer
Berkeley DB (6.0 and later) is AGPL-licensed; 4.8.30 predates that
relicensing.

## The chain is dead

CoiledCoin was killed by Luke-Jr / Eligius merge-mining its hashrate to
extinction in early 2012 - see Luke-Jr's
["Why I am attacking CoiledCoin"](https://bitcointalk.org/index.php?topic=56675).
There's no live network to sync from; the daemon is run only to read the
pre-existing block database (`blk*.dat`, in the original Berkeley DB-based
format used by Bitcoin pre-LevelDB) for AuxPoW extraction.

You need to seed `./data/` with a recovered chaindata snapshot before
starting the container. On `<archival-host>` this lives at `<chain-data-dir>`.

## One-time setup

```sh
cd /opt/merge-mining-research/node-infra/coiledcoin   # wherever you clone
# populate ./data/ with the recovered chaindata (blk0001.dat ... addr.dat etc.)
just build      # builds image coiledcoind:local
just up         # start the container against the seeded data dir
just height     # 1379337 if the seed is intact
```

## Useful commands

```sh
just status     # legacy `getinfo` - closest thing to getblockchaininfo
just shell      # drop into a root shell in the container
```

## Files

- `Dockerfile` - multi-stage build, libdb 4.8 + coiledcoind from upstream git
  (the Berkeley DB 4.8.30 source is fetched at build time, checksum-pinned)
- `docker-compose.yml` - runtime (no ports published; chain is dead)
- `bdb-atomic.patch` - one-line atomic-op fix against modern libc
- `config.guess`, `config.sub` - modern autotools host helpers for BDB's build
- `justfile` - common operations
