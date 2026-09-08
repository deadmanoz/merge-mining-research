# Merge Mining Research worker

This workspace provides the MMR-defined container for one-off recovery and
analysis commands on the migration VM. The image installs the package from an
explicit local MMR checkout supplied as the Docker build context. It does not
clone source, fetch datasets, run a job at startup, or publish repository
outputs.

The Compose service keeps three locations separate:

- `MMR_REPO_DIR` is mounted read-only at `/repo`.
- `MMR_ARCHIVE_ROOT` is mounted read-only at `/archive`.
- `MMR_WORK_DIR` is mounted read-write at `/work` for disposable
  command output.

These are required bind sources. Create and verify the directories before
running Compose; a missing path is an operator setup error. The archive mount
preserves the migration layout, including `chains/<chain>/` and
`runs/<original-name>/`. Use the existing command flags and the container path
`/archive` for each job. For example, inspect a command before running it:

```sh
cd node-infra/research-worker
cp .env.example .env
# Edit .env with existing host paths before continuing.
just config
just build
just run python scripts/analysis/reconcile_unknown_stale_ancestry.py --help
```

Some preserved archive views contain absolute symlinks. For those reads, use
a private Compose overlay with read-only binds from the corresponding archived
directories to their original container paths. Preserve the original links,
require existing bind sources, and verify representative linked-file reads
before using the view. These extra mounts do not duplicate the archive data.

When running a real diagnostic, pass its normal archive-root options and send
all generated files to a subdirectory of `/work`, such as
`--output-dir /work/<run>`. Publication commands retain their normal
fail-closed behavior and must not be pointed at a committed `data/` or
`results/` path from this worker. The repository checkout remains read-only so
an omitted disposable output path fails visibly instead of changing the
source tree.

The mounted `/repo/src` is first on `PYTHONPATH`, preserving the package's
existing project-root discovery for committed inputs. Dependencies and the
package build are installed into the image venv from the explicit checkout
used as the Docker build context.

The worker is one-shot: the Compose service's default `python --version`
command exits immediately, while `just run` creates a temporary container for
the explicitly supplied command. The Compose restart policy is `"no"`. No
polling, automatic extraction, broad reclassification, or publication is part
of this workspace.

Keep the repository's pinned upstream revisions and Git LFS payloads in the
selected checkout/archive. Rebuild the image whenever the mounted checkout's
source revision or dependencies change. The mounted checkout supplies the
scripts, package source and data at runtime, while the image venv supplies the
tested dependency installation from the build context. RPC settings can be
supplied with the command's normal options or environment for a single run.

The image includes Git and Git LFS so the RSK classifier can verify the mounted
checkout's exact revision and clean state. Use a clean standalone clone with
its `.git` directory inside `MMR_REPO_DIR`; a worktree whose Git metadata lives
outside that bind is not sufficient. Materialise the pinned upstream inputs
and LFS payloads before mounting it read-only. The container runs as UID 1000,
which must own the selected checkout and writable work directory.
Git LFS places its scratch objects under `/work/.git-lfs`, and optional Git
index writes are disabled. This lets the revision check inspect LFS files
without writing into the read-only source bind.

For RSK acquisition, pass the endpoint by environment to the one-off command:

```sh
export RSK_RPC_URL
docker compose run --rm --env RSK_RPC_URL research-worker \
  python scripts/extract/extract_rsk_auxpow.py \
  --start 0 --end <settled-height-plus-one> \
  --output /work/<run>/rsk_auxpow_raw.csv
```

Choose and record the settled endpoint as described in `docs/chains/rsk.md`.
Use the same explicit range and `--resume` only with its matching checkpoint.
The RPC route must already work from the selected container network. The
worker does not create tunnels or change firewall rules.

For the historical Devcoin pilot, select `compose.host-rpc.yml` explicitly on
Linux when the offline daemon is bound to host loopback. Set
`COMPOSE_FILE=docker-compose.yml:compose.host-rpc.yml` in the untracked `.env`
before `just config` and `just build`. Keep the default Compose file for normal
bridge networking. The overlay does not start Devcoin or any research job.

RPC variables in the shell are not forwarded automatically. Pass their names
to `docker compose run --env` so their existing values are used without putting
credentials in the command line. With the Devcoin daemon already running, the
small representative extraction command is:

```sh
export DEVCOIN_RPC_URL DEVCOIN_RPC_USER DEVCOIN_RPC_PASSWORD
docker compose run --rm \
  --env DEVCOIN_RPC_URL \
  --env DEVCOIN_RPC_USER \
  --env DEVCOIN_RPC_PASSWORD \
  research-worker python scripts/extract/extract_devcoin_auxpow.py \
  --start 25000 --end 25001 \
  --output /work/devcoin-extract-smoke.csv
```

The output is disposable and remains under the writable work bind. This is a
small read/extract check, not a broad extraction or publication run.
