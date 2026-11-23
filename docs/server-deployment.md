# Server deployment and local migration

This guide moves an existing HIBP installation from a local computer to a
long-lived Linux server, runs it under systemd, survives a reboot, and
optionally exposes the browser UI to a trusted local intranet over HTTPS.

It applies to HIBP v0.11.0 and later.

> **Default access model:** HIBP listens on `127.0.0.1:8443`. The supported
> remote-access model is an SSH tunnel. LAN HTTPS mode is an explicit opt-in
> for a trusted private network. Do not expose HIBP directly to the internet.

## Contents

- [Choose an access model](#choose-an-access-model)
- [What has to move](#what-has-to-move)
- [1. Prepare the database on the local machine](#1-prepare-the-database-on-the-local-machine)
- [2. Install the service account and binary](#2-install-the-service-account-and-binary)
- [3. Move the database, passphrase, and SSH keys](#3-move-the-database-passphrase-and-ssh-keys)
- [4. Test the server manually](#4-test-the-server-manually)
- [5. Run HIBP under systemd](#5-run-hibp-under-systemd)
- [6. Test a reboot](#6-test-a-reboot)
- [7. Optional LAN HTTPS access](#7-optional-lan-https-access)
- [8. Post-migration checklist](#8-post-migration-checklist)
- [9. Backups and upgrades](#9-backups-and-upgrades)
- [10. Troubleshooting](#10-troubleshooting)
- [11. Security checklist](#11-security-checklist)

## Choose an access model

HIBP supports three access models:

| Model | Use when | Requirements |
| --- | --- | --- |
| Loopback + SSH tunnel | Default. The server is remote, internet-facing, or you do not want a LAN listener. | SSH access to the server. Nothing else is exposed. |
| LAN HTTPS | The server is on a trusted private network and operators need browser access without an SSH tunnel. | A DNS name, a TLS certificate trusted by the clients, a firewall rule limited to the LAN, and `--listen`, `--public-url`, `--tls-cert`, and `--tls-key`. |
| Trusted TLS proxy | An existing HAProxy/Nginx already terminates TLS and cannot be moved. | An explicit `--trust-proxy`, `--public-url https://...`, a proxy source CIDR allowlist, and a firewall rule that only the proxy can reach the backend listener. |

All models keep the same application behavior. HIBP is still a single-operator
controller. There is no RBAC or WAF. A reverse proxy is supported only through
the explicit trusted-proxy mode below; it is never enabled implicitly.

LAN HTTPS mode binds one listener and replaces the default loopback listener.
If you need local-only access as well, open the LAN URL from the server or keep
the default loopback unit and use an SSH tunnel. Do not run two HIBP processes
against the same database.

**Do not port-forward HIBP on your router.** LAN mode is for private networks.
For internet access, keep loopback-only and use an SSH tunnel or a VPN.

## What has to move

Move all of these together:

- `hibp.db`
- `hibp.db.meta` — required; the database will not open without it
- the database passphrase
- the controller SSH private keys
- the same HIBP binary version, or newer

The database contains hosts, credentials references, monitoring, schedules,
SMTP secrets, durable job records, audit history, the UI account, TOTP, and
passkeys. Host-key trust is also stored in the database, so moving the database
preserves trusted target keys and the audit chain.

The SSH **private key files** are not stored in the database. Copy them
separately and update each host's `key_path` after migration.

## 1. Prepare the database on the local machine

Stop the local HIBP process before copying the live database.

### Recommended: use HIBP's backup

1. Open the local HIBP UI.
2. Click **Backup database**.
3. Choose a backup directory.
4. Click **Backup**.

This creates a consistent encrypted copy:

```text
hibp-YYYY-MM-DD-HHMMSS.bac
hibp-YYYY-MM-DD-HHMMSS.bac.meta
```

Copy both files:

```bash
scp hibp-YYYY-MM-DD-HHMMSS.bac \
    hibp-YYYY-MM-DD-HHMMSS.bac.meta \
    user@server:/tmp/hibp-migrate/
```

### Alternative: copy the stopped database

Find the database pair. The default is:

```bash
ls -l ~/.local/share/hibp/
```

If you used `--db`, use that path instead. To search for the default or a
nearby custom path:

```bash
find ~ -maxdepth 6 \( -name 'hibp.db' -o -name 'hibp.db.meta' \)
```

Stop HIBP, then copy both files:

```bash
scp ~/.local/share/hibp/hibp.db \
    ~/.local/share/hibp/hibp.db.meta \
    user@server:/tmp/hibp-migrate/
```

If `hibp.db-wal` or `hibp.db-shm` exists after the stop, copy those too, or use
the backup method above instead. A database copied while HIBP is running can be
inconsistent.

### Copy the SSH keys

```bash
scp ~/.ssh/id_ed25519 user@server:/tmp/hibp-migrate/id_ed25519
```

If any host uses `ProxyJump`, copy the jump-host key too.

## 2. Install the service account and binary

On the server:

```bash
sudo useradd --system --user-group \
  --home-dir /var/lib/hibp \
  --shell /usr/sbin/nologin hibp

sudo install -d -o hibp -g hibp -m 0700 /var/lib/hibp
sudo install -d -o root -g hibp -m 0750 /etc/hibp
sudo install -d -o hibp -g hibp -m 0700 /etc/hibp/ssh
```

Install the static Linux release binary:

```bash
sudo install -o root -g root -m 0755 /tmp/hibp /usr/local/bin/hibp
/usr/local/bin/hibp version
```

Use the release archive for the server architecture:

```text
hibp-vX.Y.Z-linux-amd64.tar.gz
```

The locally built `dist/hibp` is dynamically linked against the system
SQLCipher and OpenSSL libraries. It works on a matching development machine but
is not the right artifact for a stock server. The release workflow builds a
static binary.

If you build on the server instead:

```bash
# Requires Docker
make production

# Or install libsqlcipher-dev and build against the system SQLCipher
make build-system
```

The controller and target helper architectures must match the targets you
manage.

## 3. Move the database, passphrase, and SSH keys

The passphrase file must contain the **same passphrase** you used for the
existing database. Do not generate a new passphrase for an existing database.
There is no passphrase-rotation command in this release.

### Install the database

For a UI backup pair:

```bash
sudo install -o hibp -g hibp -m 0600 \
  /tmp/hibp-migrate/hibp-YYYY-MM-DD-HHMMSS.bac \
  /var/lib/hibp/hibp.db

sudo install -o hibp -g hibp -m 0600 \
  /tmp/hibp-migrate/hibp-YYYY-MM-DD-HHMMSS.bac.meta \
  /var/lib/hibp/hibp.db.meta
```

For a live database pair:

```bash
sudo install -o hibp -g hibp -m 0600 \
  /tmp/hibp-migrate/hibp.db /var/lib/hibp/hibp.db

sudo install -o hibp -g hibp -m 0600 \
  /tmp/hibp-migrate/hibp.db.meta /var/lib/hibp/hibp.db.meta
```

The rename from `.bac` to `hibp.db` is intentional. HIBP derives the sidecar
path from the database path, so `hibp.db` must be paired with `hibp.db.meta`.

### Install the passphrase file

Create a protected source file on a trusted machine, then install it:

```bash
sudo install -o hibp -g hibp -m 0400 \
  /secure/db.passphrase /etc/hibp/db.passphrase
```

The file must not be readable by group or others. A trailing newline is fine;
HIBP trims `\r` and `\n`.

If you must create the file on the server, use a protected editor or a password
manager. Do not paste the passphrase into shell history, an environment
variable, or the systemd unit.

### Install the SSH keys

```bash
sudo install -o hibp -g hibp -m 0600 \
  /tmp/hibp-migrate/id_ed25519 /etc/hibp/ssh/id_ed25519

sudo -u hibp touch /etc/hibp/ssh/config
sudo chown hibp:hibp /etc/hibp/ssh/config
sudo chmod 0600 /etc/hibp/ssh/config
```

HIBP requires unencrypted SSH key files at mode `0600`. `ssh-agent`,
hardware-backed keys, passphrase-protected keys, and SSH certificates are not
supported for controller-managed targets.

### Check permissions

```bash
sudo -u hibp stat -c '%a %U:%G %n' \
  /etc/hibp/db.passphrase \
  /var/lib/hibp/hibp.db \
  /var/lib/hibp/hibp.db.meta \
  /etc/hibp/ssh/id_ed25519
```

Expected:

```text
400 hibp:hibp /etc/hibp/db.passphrase
600 hibp:hibp /var/lib/hibp/hibp.db
600 hibp:hibp /var/lib/hibp/hibp.db.meta
600 hibp:hibp /etc/hibp/ssh/id_ed25519
```

Remove the migration copies:

```bash
rm -rf /tmp/hibp-migrate
```

## 4. Test the server manually

Do **not** use `--create` with the moved database. `--create` refuses an
existing database and is only for first-time creation.

```bash
sudo -u hibp /usr/local/bin/hibp server \
  --db /var/lib/hibp/hibp.db \
  --listen 127.0.0.1:8443 \
  --key-dir /etc/hibp/ssh \
  --ssh-config /etc/hibp/ssh/config \
  --passphrase-file /etc/hibp/db.passphrase
```

The startup output should include:

```text
Database: /var/lib/hibp/hibp.db
Open:     http://localhost:8443/
TLS:      disabled (loopback only)
```

From your workstation, open a tunnel:

```bash
ssh -N -o ExitOnForwardFailure=yes \
  -L 8443:127.0.0.1:8443 user@server
```

Open:

```text
http://localhost:8443/
```

Use `localhost`, not `127.0.0.1`, if you want passkeys to work. TOTP works
either way.

Your existing HIBP account, TOTP/passkeys, hosts, audit history, monitoring,
schedules, and settings move with the database. Log in and verify one host
connection. Then stop the manual server with `Ctrl+C`.

If the database is new and has no account, complete first-run setup immediately.
Until that is done, any local user who can reach the loopback port could claim
the administrator account.

## 5. Run HIBP under systemd

Copy the example unit from the repository:

```bash
scp packaging/hibp.service user@server:/tmp/hibp.service
```

On the server:

```bash
sudo install -m 0644 /tmp/hibp.service /etc/systemd/system/hibp.service
sudo systemctl daemon-reload
sudo systemctl enable --now hibp
sudo systemctl status hibp --no-pager
sudo journalctl -u hibp -n 50 --no-pager
```

The shipped unit:

- runs as the unprivileged `hibp` user;
- uses `ProtectSystem=strict`, `ProtectHome=true`, and an empty capability set;
- allows writes only under `/var/lib/hibp`;
- reads the passphrase from `/etc/hibp/db.passphrase`;
- listens on `127.0.0.1:8443`;
- restarts on failure.

Verify the health endpoint locally on the server:

```bash
curl -fsS http://127.0.0.1:8443/healthz
```

`systemctl enable` creates the boot-time symlink. The service starts after
`network-online.target` and restarts after a crash.

## 6. Test a reboot

```bash
sudo systemctl reboot
```

After the server comes back:

```bash
systemctl is-enabled hibp
systemctl status hibp --no-pager
curl -fsS http://127.0.0.1:8443/healthz
```

If the server's disk encryption requires a passphrase at boot, someone must
unlock the disk before systemd can start HIBP. HIBP's passphrase file only
unlocks the database after the operating system is running. For truly
unattended boot, use TPM-backed disk unlock or accept manual disk unlock.

For access from your workstation:

```bash
ssh -N -o ExitOnForwardFailure=yes \
  -L 8443:127.0.0.1:8443 user@server
```

## 7. Optional LAN HTTPS access

Use this only on a trusted private network. Do not expose the port to the
internet or port-forward it on your router.

### Requirements

- A stable DNS name for the server, for example `hibp.lan`. An IP-only URL
  works but disables passkeys; TOTP remains available.
- A TLS certificate whose subject alternative name (SAN) matches the DNS name.
- Client machines that trust the certificate or its issuing CA.
- A firewall rule that allows TCP `8443` only from the LAN subnet.

The `--public-url` value must use the exact scheme, host, and port that users
will open. It must not contain a path, query, fragment, or credentials. In
built-in TLS mode the public port must match `--listen`; in trusted-proxy mode
the external port may differ from the backend listener.

### How LAN mode is protected

- A non-loopback listener is refused unless TLS is configured or the listener
  is explicitly placed behind a trusted proxy.
- TLS 1.2 is the minimum.
- The Host header allowlist contains the `--public-url` hostname plus
  `localhost`, `127.0.0.1`, and `::1`.
- The Origin header must match both the Host and the request scheme.
- Session cookies are `HttpOnly`, `SameSite=Strict`, and `Secure` over TLS.
- `--public-url` also defines the WebAuthn relying-party ID and origin.
- An IP-address public URL disables passkeys; use TOTP or a DNS name.

### Trusted TLS proxy

Use this only when a TLS-terminating proxy is already in front of HIBP and the
proxy cannot be replaced by HIBP's built-in TLS listener.

The controller accepts a plaintext backend listener only when all of these are
true:

- `--trust-proxy` is set explicitly;
- `--public-url` is the exact external `https://` origin;
- `--trusted-proxy-cidrs` lists the proxy source address or private subnet;
- the backend port is reachable only from the proxy, enforced by a firewall or
  container network policy.

Example when HAProxy runs on the same host:

```bash
hibp server \
  --db /var/lib/hibp/hibp.db \
  --listen 127.0.0.1:8017 \
  --public-url https://hibp.example.com \
  --trust-proxy \
  --trusted-proxy-cidrs 127.0.0.1/32 \
  --passphrase-file /etc/hibp/db.passphrase
```

Example when HAProxy is on another host or container network:

```bash
hibp server \
  --db /var/lib/hibp/hibp.db \
  --listen 0.0.0.0:8017 \
  --public-url https://hibp.example.com \
  --trust-proxy \
  --trusted-proxy-cidrs 10.20.0.10/32 \
  --passphrase-file /etc/hibp/db.passphrase
```

The proxy must:

- terminate TLS with a certificate matching `--public-url`;
- preserve the original `Host` header;
- set `X-Forwarded-Proto: https`;
- be the only source allowed to reach the backend listener.

HAProxy example:

```haproxy
backend hibp
    mode http
    server hibp 127.0.0.1:8017 check

frontend hibp_https
    bind *:443 ssl crt /etc/haproxy/certs/hibp.example.com.pem
    http-request set-header X-Forwarded-Proto https
    default_backend hibp
```

Do not use `0.0.0.0/0` as the trusted proxy CIDR. Do not point the proxy at the
controller if the controller port is reachable by arbitrary clients; forwarded
headers can otherwise be spoofed. Use the proxy's exact address or a dedicated
private subnet.

The controller uses `X-Forwarded-Proto` for the Origin check, Secure cookie
decision, and WebAuthn origin. Passkeys work through the proxy only when the
proxy passes the external HTTPS scheme correctly.

### Create a certificate with mkcert

`mkcert` is the easiest option for a private LAN because it creates a local CA
and certificates that browsers trust once the CA is installed.

On the server:

```bash
mkcert -install
mkcert -cert-file /tmp/hibp-tls.crt -key-file /tmp/hibp-tls.key \
  hibp.lan 192.168.1.10

sudo install -o root -g hibp -m 0644 /tmp/hibp-tls.crt /etc/hibp/tls.crt
sudo install -o hibp -g hibp -m 0600 /tmp/hibp-tls.key /etc/hibp/tls.key
rm -f /tmp/hibp-tls.crt /tmp/hibp-tls.key
```

Install the mkcert root CA on every client machine that will use the UI. The CA
is in `mkcert -CAROOT` as `rootCA.pem`.

### Create a self-signed certificate with OpenSSL

```bash
sudo openssl req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes \
  -keyout /etc/hibp/tls.key \
  -out /etc/hibp/tls.crt \
  -subj '/CN=hibp.lan' \
  -addext 'subjectAltName=DNS:hibp.lan,IP:192.168.1.10'

sudo chown hibp:hibp /etc/hibp/tls.key
sudo chmod 0600 /etc/hibp/tls.key
sudo chown root:hibp /etc/hibp/tls.crt
sudo chmod 0644 /etc/hibp/tls.crt
```

Clients must trust this certificate. A browser warning is not sufficient for
passkeys; install the certificate in the client trust store or use an internal
CA.

### Start in LAN mode manually

```bash
sudo -u hibp /usr/local/bin/hibp server \
  --db /var/lib/hibp/hibp.db \
  --listen 192.168.1.10:8443 \
  --public-url https://hibp.lan:8443 \
  --tls-cert /etc/hibp/tls.crt \
  --tls-key /etc/hibp/tls.key \
  --key-dir /etc/hibp/ssh \
  --ssh-config /etc/hibp/ssh/config \
  --passphrase-file /etc/hibp/db.passphrase
```

Startup should show:

```text
Open:     https://hibp.lan:8443/
TLS:      enabled (TLS 1.2 minimum)
```

From a client on the LAN:

```text
https://hibp.lan:8443/
```

Do not use a different hostname or IP unless it is also in the certificate and
the allowlist. The Host header is checked strictly.

### Run LAN mode under systemd

The repository includes `packaging/hibp-lan.service`. Copy it and edit the
listen address, public URL, and certificate paths:

```bash
scp packaging/hibp-lan.service user@server:/tmp/hibp-lan.service
sudo install -m 0644 /tmp/hibp-lan.service /etc/systemd/system/hibp.service
sudo systemctl daemon-reload
sudo systemctl enable --now hibp
```

Do not enable both `hibp.service` and `hibp-lan.service`; they use the same
database. Install one unit as `/etc/systemd/system/hibp.service`.

Bind to the controller's specific LAN address when possible. `0.0.0.0` listens
on every interface, including any public interface, so the firewall becomes the
only boundary. HIBP also prints a warning when it binds all interfaces.

HIBP does not redirect HTTP to HTTPS. Users must open the `https://` URL. If a
client tries `http://hibp.lan:8443`, the request fails rather than silently
sending credentials in clear text.

TLS certificates expire. Before expiry, replace `/etc/hibp/tls.crt` and
`/etc/hibp/tls.key` and restart the service. HIBP does not hot-reload
certificates:

```bash
sudo systemctl restart hibp
```

Plan the restart for a quiet period; it briefly interrupts the UI and any
in-flight operation.

### Firewall

Allow only the LAN subnet:

```bash
# ufw
sudo ufw allow from 192.168.1.0/24 to any port 8443 proto tcp

# firewalld
sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=192.168.1.0/24 port port=8443 protocol=tcp accept'
sudo firewall-cmd --reload
```

Do not add a router port-forward or a public firewall rule. Keep SSH restricted
to the administrator network.

### Verify

From the server:

```bash
curl -fsS --cacert /etc/hibp/tls.crt \
  --resolve hibp.lan:8443:192.168.1.10 \
  https://hibp.lan:8443/healthz
```

An unexpected Host header must be rejected:

```bash
curl -ksS -o /dev/null -w '%{http_code}\n' \
  -H 'Host: evil.example:8443' \
  https://127.0.0.1:8443/healthz
```

Expected: `403`.

### Passkeys on a LAN

- Use the DNS name from `--public-url`, not the IP address.
- The certificate must be trusted by the client.
- Passkeys are scoped to the WebAuthn relying-party ID. A passkey registered on
  `localhost` will not appear on `hibp.lan`, and vice versa. Register a new
  passkey while logged in through the LAN URL if you want passkeys there.
- TOTP works on both origins and is the fallback.

## 8. Post-migration checklist

1. **Update host key paths.** The database still contains old paths such as
   `/home/roger/.ssh/id_ed25519`. Edit each host and change it to
   `/etc/hibp/ssh/id_ed25519`. Update `ProxyJump` key paths too.

2. **Test one host.** Open a host and run a connection test. If the key file is
   not readable by `hibp`, the test fails with a permission error.

3. **Set the backup directory.** The old local path probably does not exist on
   the server.

   ```bash
   sudo install -d -o hibp -g hibp -m 0700 /var/lib/hibp/backups
   ```

   In HIBP: **Settings → backup directory** = `/var/lib/hibp/backups`,
   retention `3`. Run a backup and copy it off-host.

4. **Update helpers if needed.** If a target helper is older than the
   controller, run **Setup / Update helpers**. The `preview` action added in
   v0.10.0 must be installed before package previews work.

5. **Enable NTP.** TOTP and schedules depend on the controller clock.

   ```bash
   sudo timedatectl set-ntp true
   timedatectl status
   ```

6. **Verify SMTP and monitoring.** SMTP settings and monitor definitions move
   with the database. Ensure the server can reach the SMTP relay and the
   monitored endpoints. Standalone web-service probes now originate from the
   server, so it needs outbound HTTP/HTTPS.

7. **Review firewall egress.** The controller needs outbound SSH to targets,
   SMTP to the relay, and optional HTTP/HTTPS to monitored endpoints.

## 9. Backups and upgrades

- Always back up the database **and** the `.meta` sidecar together.
- Keep at least one encrypted backup off the controller.
- Keep the matching HIBP binary with important backups. HIBP refuses a database
  whose schema version is newer than the running binary.
- HIBP creates an automatic verified pre-migration backup before applying a
  schema upgrade. A failed backup aborts the upgrade.
- Test a restore to a new path while the service is stopped.

Upgrade procedure:

```bash
sudo systemctl stop hibp
# Create or copy a backup first.
sudo install -o root -g root -m 0755 /tmp/hibp-new /usr/local/bin/hibp
sudo systemctl start hibp
sudo systemctl status hibp --no-pager
sudo journalctl -u hibp -n 100 --no-pager
```

Then open the UI and verify hosts, audit chain, monitoring, and schedules.

## 10. Troubleshooting

### Service fails to start

```bash
sudo systemctl status hibp --no-pager
sudo journalctl -u hibp -n 100 --no-pager
```

Common causes:

- wrong database path;
- missing `hibp.db.meta`;
- passphrase file readable by group/others;
- wrong passphrase;
- TLS certificate or key not readable by `hibp`;
- public URL port does not match the listen port;
- the database schema is newer than the binary.

### `unexpected Host header`

The browser is using a hostname or IP that is not the `--public-url` hostname.
Open the exact URL configured in `--public-url`. Add a DNS record or `/etc/hosts`
entry if needed. Do not add wildcard hosts.

### Browser certificate warning

The certificate SAN does not match the URL, the client does not trust the
issuing CA, or the certificate is expired. Passkeys require a trusted
certificate. TOTP still works over a certificate warning, but fix the trust
before using the UI routinely.

### Passkeys unavailable

- The URL uses an IP address. Use a DNS name.
- The URL is HTTP. Use HTTPS.
- The certificate is not trusted.
- The request hostname does not match `--public-url`.
- The passkey was registered under a different origin (for example
  `localhost`). Register a new passkey on the LAN origin, or use TOTP.

### Locked out of the UI

Stop the service and reset the local account:

```bash
sudo systemctl stop hibp
sudo -u hibp /usr/local/bin/hibp user reset \
  --username <name> \
  --db /var/lib/hibp/hibp.db \
  --passphrase-file /etc/hibp/db.passphrase
sudo systemctl start hibp
```

This resets the UI password, TOTP, and passkeys. It does not change the
database passphrase.

### Lost database passphrase

There is no recovery path. The encrypted database cannot be opened without the
passphrase. Restore a backup made with a known passphrase, or start a new
database and re-enroll hosts.

### Port already in use

```bash
ss -lntp | grep 8443
```

Stop the other HIBP process or choose a different port. Do not run two HIBP
processes against the same database.

## 11. Security checklist

- Use full-disk encryption on the controller.
- Keep the database passphrase in a `0400` or `0600` file owned by `hibp`.
- Do not put the passphrase in the unit file, environment, shell history, or an
  unencrypted backup.
- Run as the unprivileged `hibp` user.
- Keep SSH keys at `0600`, outside `/home` when using the packaged unit.
- Use TLS for LAN mode. A plain-HTTP backend is allowed only with explicit
  `--trust-proxy` and a proxy source CIDR allowlist, with the backend port
  firewalled to the proxy.
- Restrict the LAN port to the LAN subnet with a firewall.
- Do not port-forward HIBP or expose it to the internet.
- Use NTP on the controller and targets.
- Keep encrypted backups off the controller.
- Treat the controller as root-equivalent: it holds target SSH keys and can run
  privileged helper actions.
