# Node and archive operations

Read before touching node-infra, private archives or deployment inputs, then read the relevant workspace README and justfile. These restrictions protect retained evidence and legacy datadirs.
All paths and commands are relative to the repository root.

## Contents

- [Node Infrastructure](#node-infrastructure)

## Node Infrastructure

`node-infra/qbit/` owns the pinned Qbit archival build and explicit acquisition
worker and uses the same profile model as the other node workspaces: the base
Compose file publishes RPC only on the selected host address in
`QBIT_RPC_BIND` (loopback by default) with the restart policy in
`QBIT_RESTART_POLICY` (enable only after acceptance), and
`compose.offline.yml` serves networkless reads. Keep `prune=0`,
`prunewitnesses=0`, `assumevalid=0` and `txindex=1`, noncreating data/config
binds, and `rpcauth` for any remote poller in the private config; `just up`
and `just start` never build or pull.
`qbit.py` validates its distinct header/proof envelope using existing bounded
wire helpers; `qbit_acquisition.py` accounts for every native active-chain
height and writes private receipts. `--from-acquisition` authenticates sealed
captures and replays the same producer into a fresh generation. Failed runs
remain incomplete. Qbit uses the shared classifier, loader and publication
registry; leading arbitrary commitment pushes are not Bitcoin height evidence.
Its 24 zero-predecessor synthetic parents remain unknown and are excluded by
Bitcoin epoch targets. See `docs/chains/qbit.md`.

`node-infra/rod/` owns the pinned SpaceXpanse ROD archival build. Keep its
source archive ignored and digest-verified, use noncreating data/config binds,
and retain `prune=0`, `txindex=1` and `assumevalid=0` for comprehensive recovery.
RPC stays inside the container. Node sync and complete parent-evidence
extraction are separate from Research publication and Monitor registration. The tracked
`download-window.patch` is an archival throughput variant: it changes only the
per-peer in-flight block cap after source digest verification, keeps the global
download window and native consensus validation unchanged, and must use its
distinct image tag or an explicit `ROD_IMAGE` rollback selection.

`node-infra/research-worker/` defines the one-off research container. It installs
Python dependencies in a venv and includes Git/Git LFS for classifier provenance
checks. `just build` uses the explicit selected checkout; `just run` mounts that
checkout and the private archive read-only at `/repo` and `/archive`, with
disposable output under `/work`. Use a clean standalone clone owned by UID 1000
for provenance-checked classification. Git LFS scratch objects belong under
`/work/.git-lfs`; the source bind
must remain read-only. Rebuild when the checkout or dependencies
change. Never start extraction or publication automatically, and keep private
inputs out of the Docker build context. Read the workspace README for RPC
environment forwarding and the optional Linux host-network overlay.

Treat private archive payloads as immutable. Historical paths may share storage
through hardlinks; an in-place write could alter several retained runs. Copy
inputs into a working directory before editing or regenerating them. Replace
disposable build inputs instead of overwriting preserved binaries in place.
Keep original path and metadata receipts when consolidating exact duplicates.
For curated current-family promotion, stage fresh copies and retain the previous
family as dated provenance with before/after digests. Replace the directory
selection; never write preserved payloads in place.

The archive dashboard is maintained in the separate private
`deadmanoz/mmr-archive-dashboard` repository, including its Dockerfile,
collector, Compose recipes and operating instructions. This is the explicit
exception to MMR's image-ownership policy below. The directory
`node-infra/archive-dashboard/` contains only a pointer. Make dashboard changes
in its own checkout and follow its `AGENTS.md`; do not restore a duplicate
runtime here. The dashboard distinguishes transfer verification from research
coverage and serves only cached metadata.

The separately managed Monitor deployment workspace owns both production and
development deployments. This repository supplies published Research artifacts
to the Monitor as a read-only input; do not recreate a Monitor deployment
workspace under `node-infra/`.

Each `node-infra/<chain>/` directory is its own operational workspace with a
README and usually a local `justfile`. Read the chain README before building or
starting a node.

Every Research-owned project image, including node and research-worker images,
must have its canonical Dockerfile or pinned image reference, required patches,
Compose configuration and operating instructions in `node-infra/<workspace>/`.
Add supported build/runtime
variants there rather than maintaining private recipe forks. Keep generated
image exports, source bundles, datadirs and host-specific settings private.

Host runtime startup must wait for required data mounts and private network
interfaces before automatically starting containers whose RPC endpoints bind
those addresses. Verify this ordering in the normal reboot acceptance check.

Namecoin and Syscoin use preserved native Linux binaries, verified by hash
at image build time. Their ignored `binaries/` inputs come from the private
source archive. Keep the separate config bind read-only and both bind sources
noncreating. Review old host-specific settings before offline starts. Preserve
the observed index state, and enable live restart only after acceptance.

Elastos packages preserved release binaries and mounts the complete node root
at `/data`, keeping the daemon's database in its `elastos` child. RSK packages
the preserved JAR and matching Java runtime, with one noncreating data bind
containing the active `mainnet/database/unitrie` directory. Preserve those path
relationships, keep logs inside the data binds, and use networkless overlays for initial reads. Image defaults must
exit harmlessly without initializing node state. The RSK JSON-RPC recipe uses
quoted positional arguments so JSON values retain their argument boundaries.

Fractal adoption uses the retained image and existing datadir with an explicit
`bitcoin.conf`, a noncreating bind and initial networkless reads. Do not run
initialization or rebuild/reindex the node while adopting a disk. Set the live
restart policy and private RPC publish address only after acceptance.

Devcoin is operated on demand as a retained historical container. Its
workspace uses `just stop` / `just start` to preserve the container, disables
automatic restart, and excludes node data from the Docker build context.
Its Dockerfile supports upstream and local-bundle builds; `compose.offline.yml`
provides offline Linux operation. Keep host paths and selections in `.env`.

Argentum, Bitmark, Crown, Doichain, Elcash, Emercoin, IXCoin, Myriadcoin,
Terracoin and Unobtanium also support an explicit `compose.offline.yml` overlay and private
image/datadir selections. Adopt preserved data with the verified existing
image first, without rebuilding, reindexing, loading bootstrap files or
running an initialization recipe. Validate tip and historical block reads,
then stop the retained container. Automatic restart defaults to disabled;
ordinary online configurations remain available for explicit use. Check each
workspace's README rather than assuming every historical node has identical
flags, credentials or RPC ports.
Terracoin also has a private `compose.live.yml` overlay for verified populated
state. It omits bootstrap loading, requires private RPC bind and client
selections, and stays separate from the offline research profile. Set
`TERRACOIN_RESTART_POLICY=unless-stopped` only after live acceptance and host
startup ordering are verified; the live profile defaults to no restart.
Bitmark's legacy daemon ignores `rpcbind`; any `rpcallowip` selects wildcard
listening. Its offline profile relies on omitting both and removing both
from the copied config so only IPv4/IPv6 loopback sockets are opened.

CoiledCoin and SixEleven use `network_mode: none` in their archival overlays
and retain CLI access through `docker compose exec`. Keep SixEleven's wrapper
that suppresses upstream credential output; its image runs the daemon as UID
999, and generic version/help probes may try to initialize a database. Do not
substitute newer daemon assumptions or run initialization against preserved
data. Missing-config errors require restoring its private configuration.

All historical and surveyed node workspaces default to no automatic restart,
including Doichain, Blast, Jincoin, Lyncoin and Xaya. Their ordinary online
recipes may still contact peers when explicitly started. Apply a documented
offline profile where one exists and distinguish a scaffold from a verified
recovered node. Live sources enable their restart policy only after acceptance.

Keep generated node datadirs, RPC credentials, logs, block indexes, and
chainstate files out of git. Some chain directories already have local
`.gitignore` files for `data/`; if you introduce a new generated datadir, add
an ignore rule before running long-lived node commands.
