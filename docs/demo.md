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

The **Sign in with demo credentials** button completes the password and TOTP
steps in one click using a freshly generated code. You can also enter the shown
username, password, and current code manually.

The TOTP secret is fixed for the demo. Real TOTP validation is used, but the
replay lockout is bypassed in demo mode so multiple visitors can use the same
displayed code. Passkeys are disabled.

## Run locally

With the Compose example in this repository:

```bash
cp .env.demo.example .env.demo
docker compose --env-file .env.demo up -d
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
docker compose --env-file .env.demo up -d
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

## Port mapping

The container always listens on `8080`. `HIBP_DEMO_PORT` is the published
**host** port:

```dotenv
HIBP_DEMO_LISTEN=0.0.0.0:8080
HIBP_DEMO_PORT=8011
```

This maps host `8011` to container `8080`; open <http://localhost:8011/>. Do not
change `HIBP_DEMO_LISTEN` to `8011`; the container target must stay `8080`.

`HIBP_DEMO_BIND=127.0.0.1` makes the host port local-only. To listen on all
interfaces at port `8011` for a trusted LAN:

```dotenv
HIBP_DEMO_PUBLIC_URL=http://192.168.1.50:8011
HIBP_DEMO_ALLOW_INSECURE_HTTP=true
HIBP_DEMO_BIND=0.0.0.0
HIBP_DEMO_PORT=8011
```

Replace `192.168.1.50` with the Docker host's LAN address, and use exactly that
name or address in the browser. Then open <http://192.168.1.50:8011/>. This is a
demo-only opt-in; never expose port `8011` directly to the internet. For a LAN
hostname instead of an IP, set `HIBP_DEMO_PUBLIC_URL` to that hostname.

Without the opt-in, a direct non-loopback HTTP URL is rejected. In that case,
put an HTTPS reverse proxy in front and use an `https://` origin in
`HIBP_DEMO_PUBLIC_URL`.

Check the rendered mapping:

```bash
docker compose --env-file .env.demo config | sed -n '/ports:/,/restart:/p'
```

## Environment variables

| Variable | Default | Notes |
|---|---|---|
| `HIBP_DEMO_LISTEN` | `0.0.0.0:8080` | Container listener. |
| `PORT` | none | Used when `HIBP_DEMO_LISTEN` is empty. |
| `HIBP_DEMO_PUBLIC_URL` | `http://localhost:8080` | Exact public origin. Set this for LAN or public access. |
| `HIBP_DEMO_ALLOW_INSECURE_HTTP` | `false` | Demo-only opt-in for a non-loopback `http://` LAN origin. Never enable on an internet-facing host. |

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
- `HIBP_DEMO_ALLOW_INSECURE_HTTP=true` disables the HTTPS requirement for a
  non-loopback origin. It is only for a trusted LAN; do not use it on an
  internet-facing host.
- Use container resource limits and proxy rate limiting for a public deployment.

Recommended container flags. The demo runs as UID/GID `65532`; the `/tmp`
tmpfs must be writable by that user or the container cannot create its ephemeral
database and demo SSH files. `mode=1777` is the standard sticky `/tmp` mode and
is accepted by Docker/Compose versions that reject `uid`/`gid` tmpfs options.

```bash
docker run --rm \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=256m,mode=1777 \
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

## Troubleshooting

### Sign-in returns to the login page

The demo keeps its session in the `hibp_demo_session` cookie. The demo cookie
name is separate from the production `hibp_session` cookie so multiple HIBP
instances on the same hostname do not overwrite each other.

If sign-in succeeds but the page returns to the login form, the browser did not
keep the cookie. Check:

1. **The browser URL matches the configured origin.** Compare the address bar
   with:

   ```bash
   docker compose --env-file .env.demo config | grep HIBP_DEMO_PUBLIC_URL
   ```

   `http://` and `https://` are different origins. Do not configure `https://`
   and browse over `http://`, or the reverse.

2. **Cookies are allowed for this host.** Private browsing, cookie blockers, or
   a site setting can discard the session cookie.

3. **You are using the expected hostname.** The Host header must match
   `HIBP_DEMO_PUBLIC_URL` or be a loopback name. A different LAN IP gets
   `403 unexpected Host header`, not a login loop.

4. **An HTTPS proxy sets `X-Forwarded-Proto: https`.** Without it the demo may
   treat the backend request as plain HTTP.

Clear the site's cookies for the demo host and retry. If the problem persists,
check the browser developer tools console and the response headers for
`Set-Cookie`.

### `demo public URL must use https for a non-loopback host`

`HIBP_DEMO_PUBLIC_URL` is set to an `http://` URL for a non-loopback hostname.
The demo is designed to sit behind a TLS-terminating proxy, so the value must be
the exact **external HTTPS origin** the browser uses:

```dotenv
HIBP_DEMO_PUBLIC_URL=https://demo.example.com
```

For a trusted LAN-only deployment over plain HTTP, opt in explicitly:

```dotenv
HIBP_DEMO_PUBLIC_URL=http://192.168.1.50:8011
HIBP_DEMO_ALLOW_INSECURE_HTTP=true
```

Do not use the internal container URL (`http://hibp-demo:8080`), an IP address
without TLS (unless the LAN opt-in above is set), or the proxy's backend URL. If
the public origin has a non-default port, include it exactly as the browser
sees it:

```dotenv
HIBP_DEMO_PUBLIC_URL=https://demo.example.com:8443
```

Check what Compose actually renders:

```bash
docker compose --env-file .env.demo config | grep HIBP_DEMO_PUBLIC_URL
```

A shell environment variable with the same name overrides `.env.demo`. Check:

```bash
echo "$HIBP_DEMO_PUBLIC_URL"
```

Then recreate the container:

```bash
docker compose --env-file .env.demo up -d --force-recreate
```

The reverse proxy must preserve the original `Host` header and set
`X-Forwarded-Proto: https`. For local access without a proxy, use
`HIBP_DEMO_PUBLIC_URL=http://localhost:8080`.

## Limitations

- Shared state, not per-visitor isolation.
- No real backup/restore, email delivery, package installation, SSH, or network
  monitoring.
- The demo is not a substitute for the production deployment checklist.
