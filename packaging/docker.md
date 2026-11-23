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
- includes `/tmp` and a writable `/var/lib/hibp` so plain `docker run` supports
  package uploads and first-run database creation

## Self-contained deployment

Keep runtime data and secrets next to the Compose and environment files:

```text
HIBP/
├── compose.production.yaml
├── .env.production
├── data/
│   ├── hibp.db
│   ├── hibp.db.meta
│   ├── hibp-jobs/
│   └── backups/
└── secrets/
    ├── db.passphrase
    └── ssh/
        ├── config
        └── id_ed25519
```

`data/` and `secrets/` are ignored by Git and bind-mounted into the container.
Relative paths in `.env.production` are resolved from the Compose file directory.

```bash
sudo install -d -o 65532 -g 65532 -m 0700 data data/backups
sudo install -d -o 65532 -g 65532 -m 0700 secrets secrets/ssh
sudo install -o 65532 -g 65532 -m 0600 /dev/null secrets/ssh/config
cp .env.production.example .env.production
docker compose --env-file .env.production -f compose.production.yaml up -d
```

The example uses host networking so the controller listens on the Docker host's
loopback. First run with a new database only: add `--create` to the command,
complete admin/MFA setup, then remove `--create` and restart. Do not use
`--create` when migrating an existing database.

### Trusted TLS proxy

If HAProxy/Nginx terminates TLS, keep the backend listener plain HTTP but make
the trust explicit:

```dotenv
HIBP_PUBLIC_URL=https://hibp.example.com
HIBP_LISTEN=0.0.0.0:8017
HIBP_TRUST_PROXY=true
HIBP_TRUSTED_PROXY_CIDRS=10.20.0.10/32
```

The proxy must preserve `Host` and set `X-Forwarded-Proto: https`. The source
CIDR allowlist is mandatory for a non-loopback listener. Do not use
`0.0.0.0/0` or expose the backend port to arbitrary clients. When the proxy is
on the same Docker host, `HIBP_LISTEN=127.0.0.1:8017` and
`HIBP_TRUSTED_PROXY_CIDRS=127.0.0.1/32` is the least-privilege setup.

## Migrating a local database

The complete local-to-container procedure is in
[README.md: Docker deployment and local migration](../README.md#docker-deployment-and-local-migration).
The short version:

1. Stop the local HIBP process and record `hibp version`.
2. Create a UI backup, or copy the stopped `hibp.db` and `hibp.db.meta` pair.
3. Put the pair in `data/hibp.db` and `data/hibp.db.meta`.
4. Put the same passphrase in `secrets/db.passphrase`.
5. Copy the required keys to `secrets/ssh` and update each host's `key_path` to
   `/etc/hibp/ssh/...`.
6. Start with `HIBP_TAG=edge` (schema 15) and **without** `--create`.
7. Verify login, audit, schedules, and one host connection before removing the
   local copy.

Do not open a live database with two HIBP processes, do not copy a live WAL by
hand, and do not import a `cmdb-lite` database directly. Export cmdb-lite or
other inventory data as CSV/JSON and use **Hosts → CMDB import** or
**Hosts → Import CSV** in the browser.

## Plain docker run

The image contains `/tmp` and an empty `/var/lib/hibp`, but persist runtime data
with a bind mount. The container runs as UID/GID `65532`:

```bash
sudo install -d -o 65532 -g 65532 -m 0700 data secrets secrets/ssh

docker run --rm -it \
  --network host \
  -v "$PWD/data:/var/lib/hibp" \
  -v "$PWD/secrets/db.passphrase:/etc/hibp/db.passphrase:ro" \
  -v "$PWD/secrets/ssh:/etc/hibp/ssh:ro" \
  ghcr.io/rogerbergling/hibp:latest \
  server --db /var/lib/hibp/hibp.db --create \
    --listen 127.0.0.1:8443 \
    --key-dir /etc/hibp/ssh \
    --ssh-config /etc/hibp/ssh/config \
    --passphrase-file /etc/hibp/db.passphrase
```

Omit `--create` when opening an existing database. The server refuses a
non-loopback plaintext listener unless explicit trusted-proxy mode is enabled
with a proxy CIDR allowlist. Host networking is used so `127.0.0.1` remains the
only listening address by default. For laptop access, use an SSH tunnel to the
Docker host or run the binary directly on the host with the systemd unit. Do not
place the database on a network filesystem.
