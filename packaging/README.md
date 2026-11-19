# Packaging notes

These files are examples, not a complete distribution package.

## Public demo image

`packaging/Dockerfile.demo` builds the separate `hibp-demo` image. It uses the
same SQLCipher production build path but compiles `cmd/hibp-demo` with the
`demo` Go build tag. The demo binary seeds fake hosts and simulates SSH, helper
actions, package installation, email, network probes, backup/restore, and helper
setup. It is not the production controller.

Build and test locally:

```bash
make demo-test
make demo-image
```

The demo image runs as UID/GID `65532`, listens on `0.0.0.0:8080`, and expects a
TLS-terminating reverse proxy. See [`docs/demo.md`](../docs/demo.md).

## Controller server

1. Install the static binary at `/usr/local/bin/hibp` and create the service
   account:

   ```bash
   sudo useradd --system --home /var/lib/hibp --shell /usr/sbin/nologin hibp
   sudo install -d -o hibp -g hibp -m 0700 /var/lib/hibp
   sudo install -d -o root -g hibp -m 0750 /etc/hibp
   sudo install -d -o hibp -g hibp -m 0700 /etc/hibp/ssh
   ```

2. Put controller SSH keys in `/etc/hibp/ssh` with mode `0600`, owned by
   `hibp`. Do not rely on `~/.ssh`: the example unit sets `ProtectHome=true`.
   Set `--key-dir /etc/hibp/ssh` and `--ssh-config /etc/hibp/ssh/config`.

   ```bash
   sudo install -o hibp -g hibp -m 0600 /secure/id_ed25519 /etc/hibp/ssh/id_ed25519
   ```

3. Choose the unlock policy:

   - **Headless/service:** install a long random database passphrase in
     `/etc/hibp/db.passphrase` with mode `0400` or `0600`, owner `hibp`, and
     full-disk encryption on the controller. The example unit passes
     `--passphrase-file`.

     ```bash
     sudo install -o hibp -g hibp -m 0400 /secure/db.passphrase /etc/hibp/db.passphrase
     ```

   - **Interactive:** omit `--passphrase-file` and run the service with a
     controlling terminal. Systemd services do not have a terminal by default;
     this is not a headless option.

   There is no TPM-sealed unlock or passphrase-rotation command in this release.
   The service account can read the passphrase while the host is running under
   the headless option; treat that as an explicit availability/security
   trade-off. For a scheduled fleet, the headless systemd path is the reliable
   choice; use interactive tmux/screen for first-run setup or recovery.

4. Create/open the database once, then complete first-run setup immediately.
   Headless/service example:

   ```bash
   sudo -u hibp /usr/local/bin/hibp server \
     --db /var/lib/hibp/hibp.db --create \
     --key-dir /etc/hibp/ssh --ssh-config /etc/hibp/ssh/config \
     --passphrase-file /etc/hibp/db.passphrase \
     --listen 127.0.0.1:8443
   ```

   Interactive-unlock example (run in a persistent local console or a
   `tmux`/`screen` session; the scheduler and collector stop if this process
   exits):

   ```bash
   sudo HIBP_CREATE=1 sh scripts/start-interactive.sh
   ```

   The helper prefers `tmux` and falls back to `screen`; it runs the server as
   the `hibp` service user and prompts for the passphrase inside the session.
   Do not use it while a systemd unit is already running against the same
   database.

   Through a tunnel:

   ```bash
   ssh -L 8443:127.0.0.1:8443 user@server
   ```

   Open <http://localhost:8443/>, create the administrator, and enroll TOTP
   and/or a passkey. Until this is complete, any local user who can reach the
   loopback port could claim the account. Stop the manual server after setup.

5. Install the systemd unit for headless/unattended start, or adapt it for your
   interactive policy:

   ```bash
   sudo install -m 0644 packaging/hibp.service /etc/systemd/system/hibp.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now hibp
   ```

   The shipped unit uses `/etc/hibp/ssh`, `/etc/hibp/db.passphrase`, and
   `/var/lib/hibp`. `ProtectSystem=strict` only permits writes under
   `/var/lib/hibp`; choose a backup path there or add your backup directory to
   `ReadWritePaths` after reviewing its ownership.

   If you require interactive unlock, do **not** enable the shipped
   `--passphrase-file` unit unchanged. Start the server manually in a persistent
   terminal, or add a tested TTY configuration to a separate unit. A systemd
   service has no controlling terminal by default.

6. For upgrades, stop the service, take and verify a backup of the database and
   `.meta` sidecar, install the new binary, start the service, and check the
   audit chain and host data. Set the backup directory and retention count in
   **Settings**; HIBP prunes only timestamped backups it created. On open, HIBP
   also creates and verifies an automatic
   `<database>-pre-migration-YYYY-MM-DD-HHMMSS.bac` backup before applying
   pending migrations, and aborts the upgrade if that backup fails.

The included `hibp.service` is a hardening baseline, not a universal unit.
Adjust `SystemCallFilter`, `ProtectSystem`, key paths, and backup paths if your
distribution or SQLCipher build needs different access.

## LAN HTTPS access

The default unit serves the UI on loopback and is reached through an SSH tunnel.
For a trusted private intranet, use the separate `hibp-lan.service` example.
It adds:

```text
--listen 192.168.1.10:8443
--public-url https://hibp.lan:8443
--tls-cert /etc/hibp/tls.crt
--tls-key /etc/hibp/tls.key
```

A non-loopback listener is refused unless TLS and a public URL are configured.
The public URL must use the exact scheme, host, and port that users open. It
defines the Host-header allowlist and the WebAuthn origin. The certificate SAN
must match the hostname.

Create the certificate with an internal CA, `mkcert`, or OpenSSL. For example:

```bash
mkcert -install
mkcert -cert-file /tmp/hibp-tls.crt -key-file /tmp/hibp-tls.key \
  hibp.lan 192.168.1.10

sudo install -o root -g hibp -m 0644 /tmp/hibp-tls.crt /etc/hibp/tls.crt
sudo install -o hibp -g hibp -m 0600 /tmp/hibp-tls.key /etc/hibp/tls.key
```

Then edit the listen address, public URL, and certificate paths in
`hibp-lan.service`, install it as `/etc/systemd/system/hibp.service`, and
enable it. Do not install both units at once; they use the same database.

Restrict TCP `8443` to the LAN subnet with the host firewall and do not create a
router port-forward. Clients must trust the certificate. Passkeys require a
DNS-name origin; an IP-address public URL leaves TOTP as the only second factor.

The full migration and deployment runbook, including moving an existing
database and passphrase, is in
[`docs/server-deployment.md`](../docs/server-deployment.md).

## Target helper

The app can install the helper from the host row's **Setup** button. It uploads
the controller binary, writes the restricted rule for the configured SSH
account, validates it with `visudo`, and verifies passwordless execution. The
controller must be the static release build and the CPU architectures must
match. Use the manual steps below for a different architecture or a custom
path.

Install the same binary on each managed target as:

```text
/usr/local/libexec/hibp/hibp-helper
```

It must be owned by `root:root` and must not be writable by the SSH account.
Install `hibp-helper.sudoers` in `/etc/sudoers.d/` after replacing the `hibp`
account name, then validate with:

```bash
visudo -cf /etc/sudoers.d/hibp-helper
```

The controller invokes only:

```text
sudo -n /usr/local/libexec/hibp/hibp-helper facts
sudo -n /usr/local/libexec/hibp/hibp-helper preview
sudo -n /usr/local/libexec/hibp/hibp-helper check
sudo -n /usr/local/libexec/hibp/hibp-helper apply
sudo -n /usr/local/libexec/hibp/hibp-helper cleanup-check
sudo -n /usr/local/libexec/hibp/hibp-helper cleanup-apply
sudo -n /usr/local/libexec/hibp/hibp-helper reboot
sudo -n /usr/local/libexec/hibp/hibp-helper reboot-check
sudo -n /usr/local/libexec/hibp/hibp-helper system-info
sudo -n /usr/local/libexec/hibp/hibp-helper metrics
sudo -n /usr/local/libexec/hibp/hibp-helper docker-list
sudo -n /usr/local/libexec/hibp/hibp-helper docker-check <project>
sudo -n /usr/local/libexec/hibp/hibp-helper docker-apply <project>
sudo -n /usr/local/libexec/hibp/hibp-helper docker-update-all
sudo -n /usr/local/libexec/hibp/hibp-helper install-package
```

No package names, host names, or shell fragments are accepted as command-line
arguments from the controller. `install-package` reads one validated JSON
request from stdin: a package filename, SHA-256, optional installer environment
variables, and the package bytes. The helper verifies the hash and stages the
file in a root-owned temporary path before invoking the target package manager.

## Security debt

The development build uses the `mutecomm/go-sqlcipher` spike driver. Production
deployments must use the `make production` artifact, which builds current
SQLCipher 4.20 with the patched `third_party/go-sqlite3` driver in an Alpine/musl
build image.
