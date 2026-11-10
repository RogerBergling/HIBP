# Production build

The development build (`make build`) uses the M1 spike driver. The production
artifact must be built with the maintained `mattn/go-sqlite3` driver linked
against a current SQLCipher.

```bash
docker build -f packaging/Dockerfile -t hibp-production .
docker run --rm hibp-production version
```

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

The server intentionally refuses to bind a non-loopback address. Host networking
is used for the container so `127.0.0.1` remains the only listening address.
For laptop access, use an SSH tunnel to the Docker host or run the binary
directly on the host with the systemd unit.
