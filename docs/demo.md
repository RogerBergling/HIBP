# Public demo container

The demo image runs the real HIBP browser UI and encrypted database against a
fake fleet. It is intended for a public web-hotel deployment, not for production
host management.

## What is real and what is fake

Real:

- Browser UI, authentication flow, TOTP verification, sessions, CSRF/Host/Origin
  checks, SQLCipher database, audit chain, job queue, scheduler, and monitoring
  state.
- Host CRUD, CSV/CMDB import, settings, schedules, jobs, monitors, and audit
  views.
- The activity dock and package-deployment UI.

Fake:

- Every SSH connection.
- Every helper action: facts, preview, check, apply, cleanup, reboot, metrics,
  system information, Docker, and package installation.
- SMTP delivery.
- HTTP, TCP, and TLS monitor probes.
- Backup and restore writes.
- Helper installation.

The demo does not contact real hosts, send email, execute package managers, or
make outbound HTTP/TCP/TLS probes.

## Login

The sign-in page displays:

```text
Username: guest
Password: guest
TOTP secret and current code: shown on the page
```

The TOTP secret is fixed for the demo. Real TOTP validation is used, but the
replay lockout is bypassed in demo mode so multiple visitors can use the same
displayed code. Passkeys are disabled.

## Run locally

With the Compose example in this repository:

```bash
cp .env.demo.example .env.demo
docker compose --env-file .env.demo -f compose.demo.yaml up -d
```

Open <http://localhost:8080/>.

Or with plain Docker:

```bash
docker run --rm -p 8080:8080 \
  -e HIBP_DEMO_PUBLIC_URL=http://localhost:8080 \
  ghcr.io/rogerbergling/hibp-demo:edge
```

The Compose file pulls the image from GHCR, runs it read-only with a tmpfs
`/tmp`, drops all capabilities, and applies memory/CPU limits.

## Deploy behind a TLS-terminating proxy

The demo listens on HTTP and expects the proxy to terminate HTTPS. The public
URL must be the exact browser origin: scheme, hostname, and port, with no path.

Edit `.env.demo`:

```dotenv
HIBP_DEMO_TAG=edge
HIBP_DEMO_PUBLIC_URL=https://demo.example.com
HIBP_DEMO_BIND=127.0.0.1
HIBP_DEMO_PORT=8080
```

Then start it:

```bash
docker compose --env-file .env.demo -f compose.demo.yaml up -d
```

Or with plain Docker:

```bash
docker run --rm -p 127.0.0.1:8080:8080 \
  -e HIBP_DEMO_PUBLIC_URL=https://demo.example.com \
  -e HIBP_DEMO_LISTEN=0.0.0.0:8080 \
  ghcr.io/rogerbergling/hibp-demo:edge
```

The proxy must:

- preserve the original `Host` header;
- set `X-Forwarded-Proto: https`;
- forward WebSocket-free HTTP traffic normally;
- not add a path prefix.

Example Caddy configuration:

```caddyfile
demo.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Example Nginx location:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

Do not expose the container directly to the internet without TLS. The demo
trusts `X-Forwarded-Proto` only because `HIBP_DEMO_PUBLIC_URL` is HTTPS and the
demo binary enables trusted-proxy mode.

## Environment variables

| Variable | Default | Notes |
|---|---|---|
| `HIBP_DEMO_LISTEN` | `0.0.0.0:8080` | Container listener. |
| `PORT` | none | Used when `HIBP_DEMO_LISTEN` is empty. |
| `HIBP_DEMO_PUBLIC_URL` | `http://localhost:8080` | Exact public origin. Set this in production. |

## Reset

The demo database is created in a temporary directory on every container start.
Restart the container to reset all hosts, settings, schedules, jobs, and audit
state. There is no persistent volume and no periodic in-process reset.

Visitors share one database. A visitor can change demo settings or delete demo
hosts; a restart restores the seed data.

## Security posture

- Runs as UID/GID `65532`.
- No Docker socket, host mounts, SSH keys, or real credentials.
- No real outbound network probes or SMTP delivery.
- Account security is read-only so one visitor cannot break the shared login.
- Package uploads are limited and discarded; installation is simulated.
- Backup and restore return simulated success without writing arbitrary paths.
- The sign-in page and application expose demo-only credentials and TOTP data.
- `X-Robots-Tag: noindex, nofollow` is set on demo responses.
- Use container resource limits and proxy rate limiting for a public deployment.

Recommended container flags:

```bash
docker run --rm \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --memory 512m \
  --cpus 1 \
  -p 127.0.0.1:8080:8080 \
  -e HIBP_DEMO_PUBLIC_URL=https://demo.example.com \
  ghcr.io/rogerbergling/hibp-demo:edge
```

## Publishing

The demo image is built from the same commit as the production image:

- `main`: `ghcr.io/<owner>/hibp-demo:edge` and `:sha-<short>`
- release tag `vX.Y.Z`: `ghcr.io/<owner>/hibp-demo:vX.Y.Z` and `:latest`
- pull requests: local build and smoke test, no push

The demo build uses the `demo` Go build tag. Fake SSH, fake email, fake network
probes, and the seed data are not compiled into the production `hibp` binary.

Build locally:

```bash
make demo-test
make demo-image
```

## Limitations

- Shared state, not per-visitor isolation.
- No real backup/restore, email delivery, package installation, SSH, or network
  monitoring.
- The demo is not a substitute for the production deployment checklist.
