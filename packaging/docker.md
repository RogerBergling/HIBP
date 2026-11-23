# Production build

The development build (`make build`) uses the legacy spike driver. The
production artifact must be built with the maintained `mattn/go-sqlite3` driver
linked against a current SQLCipher.

```bash
docker build -f packaging/Dockerfile -t hibp-production .
docker run --rm hibp-production version
```

Published image: `ghcr.io/rogerbergling/hibp:latest` (also tagged by release).
The release workflow builds and pushes it on every `v*` tag. The
`Production image` workflow publishes `:edge` and `:sha-<commit>` from `main`;
`:edge` is an unreleased build, so pin `:latest`, a release tag, or a digest for
production.

The Dockerfile:

- builds SQLCipher `4.20.0` from source with the OpenSSL backend
- links it statically with musl
- uses the local `third_party/go-sqlite3` patch, which calls `sqlite3_key`
  immediately after `sqlite3_open_v2`
- builds with `sqlcipher_mattn libsqlcipher netgo osusergo`
- verifies that the resulting ELF has no dynamic dependencies

## Compose example

The repository includes `compose.production.yaml` and
`.env.production.example` for a GHCR-based controller:

```bash
cp .env.production.example .env.production
# Prepare /var/lib/hibp, /etc/hibp/ssh, and /etc/hibp/db.passphrase first.
# First run only: add --create to the command, complete setup, then restart.
docker compose --env-file .env.production -f compose.production.yaml up -d
```

The example uses host networking so the controller listens on the Docker host's
loopback. It is a starting point; review the volumes, resource limits, and
systemd/SSH-tunnel policy before production use.

The image contains `/tmp` and an empty `/var/lib/hibp`, so plain `docker run`
works for package uploads and first-run database creation. Persist
`/var/lib/hibp` with a local volume for real use. The container runs as UID/GID
`65532`.

## Migrating a local/desktop HIBP database

There is no desktop client and no direct "import a desktop database" button.
Migration means moving the encrypted database pair into the container:

1. Stop the local HIBP process.
2. Use the local UI **Backup database** action, or copy the stopped `hibp.db`
   and `hibp.db.meta` pair.
3. Put the pair at the mounted database path, for example
   `/var/lib/hibp/hibp.db` and `/var/lib/hibp/hibp.db.meta`.
4. Mount the passphrase file and the controller SSH keys.
5. Start without `--create`; `--create` would refuse the existing database.
6. Update each host's `key_path` if the container path differs from the old
   desktop path.
7. Keep the matching or newer HIBP binary and keep a verified backup.

Do not open a live database with two HIBP processes, do not copy a live WAL by
hand, and do not import a `cmdb-lite` database directly. Export cmdb-lite or
other inventory data as CSV/JSON and use **Hosts → CMDB import** or
**Hosts → Import CSV** in the browser.

The production image runs as UID/GID `65532`. Mount the database directory with
permissions for that user, for example:

```bash
mkdir -p /var/lib/hibp
chown 65532:65532 /var/lib/hibp
docker run --rm -it \
  --network host \
  -v /var/lib/hibp:/var/lib/hibp \
  hibp-production server \
  --db /var/lib/hibp/hibp.db --create --listen 127.0.0.1:8443
```

The scratch image has no home-directory key defaults. To use SSH keys or a
passphrase file, mount them and pass explicit flags:

```bash
docker run --rm -it \
  --network host \
  -v /var/lib/hibp:/var/lib/hibp \
  -v /etc/hibp/ssh:/etc/hibp/ssh:ro \
  -v /etc/hibp/db.passphrase:/etc/hibp/db.passphrase:ro \
  hibp-production server \
  --db /var/lib/hibp/hibp.db --create --listen 127.0.0.1:8443 \
  --key-dir /etc/hibp/ssh --ssh-config /etc/hibp/ssh/config \
  --passphrase-file /etc/hibp/db.passphrase
```

The server intentionally refuses to bind a non-loopback address. Host networking
is used for the container so `127.0.0.1` remains the only listening address.
For laptop access, use an SSH tunnel to the Docker host or run the binary
directly on the host with the systemd unit. Do not place the database on a
network filesystem.
