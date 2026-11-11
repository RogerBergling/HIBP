# Production build

The development build (`make build`) uses the legacy spike driver. The
production artifact must be built with the maintained `mattn/go-sqlite3` driver
linked against a current SQLCipher.

```bash
docker build -f packaging/Dockerfile -t hibp-production .
docker run --rm hibp-production version
```

Published image: `ghcr.io/rogerbergling/hibp:latest` (also tagged by release).
The release workflow builds and pushes it on every `v*` tag.

The Dockerfile:

- builds SQLCipher `4.20.0` from source with the OpenSSL backend
- links it statically with musl
- uses the local `third_party/go-sqlite3` patch, which calls `sqlite3_key`
  immediately after `sqlite3_open_v2`
- builds with `sqlcipher_mattn libsqlcipher netgo osusergo`
- verifies that the resulting ELF has no dynamic dependencies

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
