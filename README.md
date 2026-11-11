# HIBP - Have I Been Patched

> **Status: M1 feature set with a production build path.** The repository
> contains a working Go server, browser UI, SQLCipher storage, host CRUD/import,
> password + TOTP/passkey authentication, SSH host-key approval, remote helper
> installation, fact collection, read-only system information, Docker
> inventory, metric history, reboot control, SSH config import, audit chain,
> backup/restore, helper actions, tests, and CI. `make production`
> builds against current SQLCipher 4.20 in a pinned Alpine/musl image; the
> development build still uses the 2020 spike driver and prints a warning. SSH
> password and sudo fallbacks are manual-run only.
> Scheduler, playbooks, agent mode, and notifications are not implemented yet.
>
> **Name:** HIBP stands for **Have I Been Patched**. It is not affiliated with
> Have I Been Pwned (haveibeenpwned.com).

HIBP is a Linux-first patch management controller. It runs as an always-on
server that owns the encrypted database, scheduler, credentials, and job queue;
the operator uses a laptop client or a browser through an SSH tunnel. It
inventories hosts, checks for pending updates using each distribution's native
package manager, applies updates on demand or on a schedule, and records exactly
what changed. The database is a single encrypted file that the operator chooses
and can back up. A CLI and a background service use the same core.

## Screenshots

> Screenshot of the M1 build running with demo data. The browser UI, encrypted
> database, host list, facts, and audit chain are real. Real patch execution
> requires the root-owned helper and SSH access to targets.

![HIBP fleet overview](docs/screenshots/dashboard.png)

## Contents

- [Screenshots](#screenshots)
- [Install a release](#install-a-release-recommended)
- [Install prerequisites](#install-prerequisites)
- [Quick start (source build)](#quick-start-source-build)
- [Authentication and MFA](#authentication-and-mfa)
- [Docker, system information, and monitoring](#docker-system-information-and-monitoring)
- [Target sudo setup](#target-sudo-setup)
- [What HIBP is](#what-hibp-is)
- [Why it exists](#why-it-exists)
- [Goals](#goals)
- [Non-goals](#non-goals)
- [Product requirements](#product-requirements)
- [Supported distributions](#supported-distributions)
- [Recommended architecture](#recommended-architecture)
- [Security model](#security-model)
- [Data model](#data-model)
- [Scheduling and job semantics](#scheduling-and-job-semantics)
- [Import formats](#import-formats)
- [Backup, restore, and schema upgrades](#backup-restore-and-schema-upgrades)
- [Build system and dependencies](#build-system-and-dependencies)
- [Repository layout](#repository-layout)
- [Roadmap](#roadmap)
- [Relationship to cmdb-lite](#relationship-to-cmdb-lite)
- [Confirmed decisions](#confirmed-decisions)
- [Ideas worth adding](#ideas-worth-adding)
- [Deferred decisions](#deferred-decisions)
- [Validation](#validation)
- [License](#license)

## What HIBP is

HIBP is the answer to three operational questions:

1. Which Linux hosts exist, and which of them need patches?
2. What exactly changed on each host, when, and with what result?
3. Can I patch one host, a group, or the whole fleet now, or on a schedule,
   without logging into every machine by hand?

The product is deliberately narrower than a configuration management system. It
does not try to be Ansible, Puppet, Chef, or Salt. It focuses on package
updates, reboot state, evidence, and the safe execution of those updates across
different Linux distributions.

## Install a release (recommended)

End users should not need Go or a compiler.

1. Download the latest release from
   <https://github.com/RogerBergling/HIBP/releases/latest>.
2. Or run the installer (inspect it first):

   ```bash
   curl -fsSL https://raw.githubusercontent.com/RogerBergling/HIBP/main/scripts/install.sh -o install.sh
   less install.sh
   sh install.sh
   ```

   The installer downloads the release archive, verifies it against the
   published `SHA256SUMS`, and installs `hibp` into `~/.local/bin` by default.

   ```bash
   # Install a specific version
   sh install.sh --version v0.2.0

   # Install system-wide (run as a user with write access to /usr/local/bin)
   sudo HIBP_PREFIX=/usr/local/bin sh install.sh

   # Then
   hibp version
   hibp server --db "$HOME/.local/share/hibp/hibp.db" --create
   ```

   Open <http://localhost:8443/> and create the admin account plus MFA.

   Release artifacts are built with the production SQLCipher driver. The
   release automation currently publishes **linux-amd64**; build from source or
   use Docker for other architectures.

3. Docker option (once a release image is published):

   ```bash
   docker pull ghcr.io/rogerbergling/hibp:latest
   mkdir -p /var/lib/hibp
   chown 65532:65532 /var/lib/hibp
   docker run --rm -it --network host      -v /var/lib/hibp:/var/lib/hibp      ghcr.io/rogerbergling/hibp:latest      server --db /var/lib/hibp/hibp.db --create --listen 127.0.0.1:8443
   ```

> **No release yet?** The installer only works after a GitHub release exists. If
> it reports `no published GitHub release found`, use `make bootstrap` to build
> from source, or create a `v*` tag to run the release workflow.

You do **not** need the prerequisites below unless you are building from source.

## Install prerequisites

These prerequisites are only needed when you build HIBP from source.

HIBP's development build needs **Go 1.27 or newer** and a **C compiler** because
the SQLCipher driver uses CGO. The production build uses **Docker** and builds
Go, SQLCipher, and OpenSSL inside the image.

If you want the repository to install Go locally for you, run:

```bash
sh scripts/setup-dev.sh
# or
make bootstrap
```

The script uses Go from `PATH` when available; otherwise it downloads Go into
`$HOME/.local` and builds. It does not use sudo.

You do **not** need Go or a compiler on managed targets. Targets only need an
SSH server and their native package manager; the controller runs the helper
binary there.

### Ubuntu, Debian, and Kali

```bash
sudo apt update
sudo apt install -y build-essential make pkg-config ca-certificates curl tar

# Install Go 1.27 from upstream. The distribution package may be older.
GO_VERSION=1.27.3
curl -fsSLO "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
rm "go${GO_VERSION}.linux-amd64.tar.gz"

# Add Go to PATH for the current shell and future login shells.
export PATH="$PATH:/usr/local/go/bin"
echo 'export PATH="$PATH:/usr/local/go/bin"' >> "$HOME/.profile"

go version
gcc --version
```

For ARM64, replace `linux-amd64` with `linux-arm64` in the download name.

If you do not have sudo, install Go under your home directory instead:

```bash
mkdir -p "$HOME/.local"
curl -fsSL "https://go.dev/dl/go1.27.3.linux-amd64.tar.gz" \
  | tar -xz -C "$HOME/.local"
export PATH="$HOME/.local/go/bin:$PATH"
```

Then run `make build` normally, or pass the binary path explicitly:

```bash
make build GO="$HOME/.local/go/bin/go"
```

### Fedora, RHEL, Rocky Linux, and AlmaLinux

```bash
sudo dnf install -y gcc make pkgconf-pkg-config curl tar ca-certificates

GO_VERSION=1.27.3
curl -fsSLO "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
rm "go${GO_VERSION}.linux-amd64.tar.gz"
export PATH="$PATH:/usr/local/go/bin"
echo 'export PATH="$PATH:/usr/local/go/bin"' >> "$HOME/.bashrc"
```

### openSUSE and SLES

```bash
sudo zypper install -y gcc make pkg-config curl tar ca-certificates

GO_VERSION=1.27.3
curl -fsSLO "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
rm "go${GO_VERSION}.linux-amd64.tar.gz"
export PATH="$PATH:/usr/local/go/bin"
```

### Arch Linux

```bash
sudo pacman -S --needed go gcc make pkgconf curl tar
go version
```

### Alpine Linux (build environment only)

```bash
sudo apk add go gcc musl-dev make pkgconf curl tar
go version
```

Alpine's packaged Go may lag behind 1.27. If `go version` is older than 1.27,
use the official tarball for musl or build in the Docker image.

### Docker for the production build

The production build does not use your local Go installation. It needs Docker:

```bash
# Ubuntu / Debian
sudo apt install -y docker.io
sudo usermod -aG docker "$USER"
# Log out and back in so the group change applies.
docker version
```

For other distributions, use the official Docker installation instructions:
<https://docs.docker.com/engine/install/>.

### Optional: use the distribution's SQLCipher instead of Docker

If you do not want Docker but want the production driver instead of the legacy
development driver, install the SQLCipher development files and run:

```bash
# Fedora / RHEL family
sudo dnf install -y sqlcipher-devel

# Debian / Ubuntu
sudo apt install -y libsqlcipher-dev

# openSUSE / SLES
sudo zypper install -y sqlcipher-devel

make build-system
```

`make build-system` links against the distribution's SQLCipher and uses the
patched `mattn/go-sqlite3` driver. The resulting binary is dynamically linked;
release artifacts still use the static Docker build.

### Verify the toolchain

```bash
go version       # must report go1.27 or newer
gcc --version    # must be available
make --version
```

### Troubleshooting

**`go: command not found`**

The easiest source-build fix is:

```bash
make bootstrap
```

It downloads Go into `$HOME/.local` if needed and runs the build. Or install Go
from the tarball and add it to `PATH`:

```bash
export PATH="$PATH:/usr/local/go/bin"
command -v go
go version
```

For a permanent shell fix, add that export to `~/.profile` or `~/.bashrc`.
You can also pass the path directly:

```bash
make build GO=/usr/local/go/bin/go
```

**`gcc: command not found`**

Install the C toolchain:

```bash
# Ubuntu / Debian / Kali
sudo apt install -y build-essential
# Fedora / RHEL family
sudo dnf install -y gcc make
# openSUSE / SLES
sudo zypper install -y gcc make
# Arch
sudo pacman -S --needed gcc make
```

**`CGO_ENABLED=0` errors**

HIBP requires CGO for SQLCipher. Do not set `CGO_ENABLED=0`; the Makefile sets
`CGO_ENABLED=1` for the development build.

**`docker: command not found` when running `make production`**

Install Docker or use the development build:

```bash
make build
```

**Permission errors in `/usr/local`**

Do not run `sudo make build`. Install Go and the compiler with sudo, then build
as your normal user. If you cannot install Go system-wide, use the home-directory
method above.

### Optional tools

- `python3` 3.9+ for the README validator and its tests.
- `git` for cloning the repository.
- `sqlite3` is not required by HIBP; the database is SQLCipher.

## Quick start (source build)

For a prebuilt binary, use [Install a release](#install-a-release-recommended) instead.

```bash
# Install the prerequisites above first.
make build

# Create the encrypted database and start the local UI
./dist/hibp server --db ~/.local/share/hibp/hibp.db --create

# Open http://localhost:8443/ (the server prints the exact URL)
```

On first visit, create the administrator account, then enroll TOTP and/or a
passkey. After that, add a host, click **Test** to approve its host key, then
click **Setup** to install the restricted helper on the target.

Use **localhost**, not **127.0.0.1**, if you want passkeys. WebAuthn relying
party IDs must be hostnames; IP addresses are rejected. TOTP works with either.

The server browses `~/.ssh` in the host form by default. Add more key
directories with a comma-separated flag:

```bash
./dist/hibp server --db ~/.local/share/hibp/hibp.db \
  --key-dir "$HOME/.ssh,/etc/hibp/ssh"
```

The **SSH config** button reads the local `~/.ssh/config` and prefills a host
form from a concrete alias. It follows simple `Include` files, skips wildcard
and `Match` blocks, and never returns private key contents. Override the config
path with `--ssh-config /path/to/config`.

Requires Go 1.27+, a C toolchain, and CGO for the development build. The
passphrase must be at least 12 characters. Use `make static` for the development
static ELF, or `make production` for the current-SQLCipher Docker build. The
target helper installation and sudoers example are in
[`packaging/README.md`](packaging/README.md).

## Authentication and MFA

HIBP is single-user in v1. There is no default token and no remote account
provider. On first visit, the browser asks you to create the local administrator
account, then to enroll at least one second factor.

### First run

1. Open `http://localhost:8443/`.
2. Choose a username and a password of at least 12 characters.
3. Scan the TOTP QR code with an authenticator app and verify a code, and/or
   add a platform passkey.
4. Click **Continue to HIBP**.

A password alone never unlocks the fleet. A pending password session is
short-lived and cannot access `/api/v1/hosts` or any other application endpoint.

### Password handling

- Passwords are hashed with Argon2id (64 MiB, 3 iterations, 2 threads) with a
  per-password random salt. Parameters are stored in the PHC string so they can
  be raised later.
- The verifier rejects absurd parameters from a tampered database instead of
  turning login into a memory-exhaustion attempt.
- Login failures are rate-limited by client address and username. Five failed
  attempts per username in 15 minutes return `429 Too Many Requests`.
- Missing usernames still pay the Argon2 cost, so response timing does not
  reveal whether the account exists.

### Sessions

- The browser receives an opaque random session token in an `HttpOnly`,
  `SameSite=Strict` cookie. JavaScript cannot read it.
- Only a SHA-256 hash of the token is stored in SQLCipher.
- A pending MFA session expires after 5 minutes. A completed session has a
  12-hour absolute limit and a 30-minute idle timeout.
- A successful MFA step rotates the session token and deletes the pending one,
  preventing session fixation.
- The UI binds to loopback and only accepts loopback Host headers. There is no
  TLS; use an SSH tunnel. Do not expose it directly to a network. A reverse
  proxy on a custom domain would also need Host and WebAuthn-origin changes.

### TOTP

- Standard 30-second, 6-digit, SHA-1 TOTP compatible with Google Authenticator,
  Aegis, 1Password, and similar apps.
- The QR code is generated from an `otpauth://` URI. The base32 secret is shown
  once for manual entry.
- The server accepts one 30-second step of clock skew.
- The last accepted time step is stored and replayed codes are rejected.
- A pending password session cannot replace TOTP. Replacing TOTP requires an
  already-completed MFA session.

### Passkeys

- Passkeys use WebAuthn. The private key stays on the authenticator; the server
  stores only the public key, credential ID, transports, and sign counter.
- Passkeys require a hostname origin. Use `http://localhost:8443/`.
  `127.0.0.1` is not a valid WebAuthn relying party ID; the UI disables passkeys
  there and leaves TOTP available.
- Registration from a password-only pending session is allowed only while the
  account has no other MFA method. Once TOTP or a passkey exists, adding a new
  passkey requires a completed MFA session. This prevents a password-only
  attacker from silently adding a bypass factor.
- A passkey whose signature counter regresses is rejected as a possible cloned
  authenticator and the event is audited.

### Recovery

There is no email reset, recovery code, or remote recovery path. If the only MFA
device is lost, recover locally with the database passphrase:

```bash
hibp user reset --username admin --db ~/.local/share/hibp/hibp.db
```

This opens the encrypted database, prompts for a new account password, and
clears TOTP, passkeys, and all sessions. It requires local access to the
controller and the database passphrase. That is intentionally a physical-access
recovery boundary.

### Security boundaries

- **Single-user, no RBAC.** The authenticated account is the administrator.
- **The session cookie is the admin credential.** Protect the browser profile,
  the SSH tunnel, and the controller.
- **The database passphrase is separate from the account password.** Neither one
  unlocks the other.
- **The UI is loopback-only.** Do not expose it directly to a network.
- **MFA is mandatory after setup.** A stolen password alone cannot reach hosts.
- **Passkeys need `localhost`; TOTP is the fallback on `127.0.0.1`.**

## Docker, system information, and monitoring

> **Status: Docker inventory and project-level check/apply implemented.**
> Read-only system information, Docker inventory, host details, metric history,
> configurable collection, and explicit Docker check/apply are available. Email
> alerting, monitoring rules, vCenter, HAProxy, OPNsense, and CMDB import are
> the next phases.

### Implemented now

- Fixed helper actions `system-info`, `metrics`, and `docker-list`, plus the
  existing package/reboot actions.
- Host detail view: click a host name in the dashboard or Hosts table.
- Tabs: **Overview**, **System**, and **Containers**.
- System snapshot: CPU, memory, swap, disks, network, DNS, default route,
  kernel, uptime, systemd failed/running services, listening ports, Docker
  versions, and container counts.
- Metric history for CPU, memory, disk, and load with canvas charts.
- Fleet defaults under **Settings** and per-host overrides in the host detail
  view.
- Configurable collection intervals, retention, and Docker scan roots.
- Background collector: full facts/system information twice a day and
  lightweight metrics every five minutes by default.
- Read-only Docker Compose project/container inventory with health, state,
  image, and ports.
- Project-level **Check updates** (pull and compare, no restart) and
  **Apply update** (`docker compose up -d --pull never`, typed confirmation).

Scheduled collection requires a trusted host key and the restricted
`NOPASSWD` helper. Password-auth hosts and sudo-password hosts can still be
collected manually from the host detail view; the scheduler never prompts.

Ten-second polling is allowed as a per-host or fleet setting, but it is not the
default. With 2–500 hosts it creates a self-inflicted SSH/CPU load. The
recommended defaults are 60 seconds for availability checks, 5 minutes for
metrics, and 12 hours for full facts.

### Docker containers

Docker access is root-equivalent. HIBP uses fixed helper actions and never
gives the controller a Docker socket or runs a second privileged daemon.

- `docker-list` — implemented read-only Compose projects, containers, health,
  ports, image tags, and project metadata.
- `docker-check <project>` — implemented: `docker compose pull` and image-ID
  comparison without restarting containers.
- `docker-apply <project>` — implemented: `docker compose up -d --pull never`
  after typing `APPLY` in the UI.

Project names come from Docker/Compose metadata, never arbitrary controller
paths. Compose files, `.env` files, and build contexts must be root-owned and
not group/world-writable. The default scan root is `/opt`; it is configurable in
the GUI. HIBP will not run `down -v`, will not prune volumes, and will not
update containers automatically. Check/apply operations are serialised with a
host-wide lock and audited. The generated sudoers rule uses `docker-check *` and
`docker-apply *`; the helper validates the single project argument, re-reads
project metadata from Docker, and trust-checks every Compose file. The wildcard
is not arbitrary shell access.

Containers are **child workloads of a host**, not new SSH-managed “servers”.
They do not inherit SSH keys or the host’s sudo rule. Standalone containers are
visible read-only in phase 1; project-level Compose updates come next.

### Host and Docker screenshots

These screenshots use demo data; the Docker project and container names are
illustrative.

| Host system information | Docker containers and project actions |
| --- | --- |
| ![Host system information](docs/screenshots/host-details-system.png) | ![Docker containers and project actions](docs/screenshots/host-details-containers.png) |

### Docker check and apply

In **Host detail → Containers**, each Compose project has:

- **Check updates** — pulls images and compares local image IDs with the image
  IDs used by running containers. It never restarts anything.
- **Apply update** — requires typing `APPLY`, then runs
  `docker compose up -d --pull never` for that project only.

The helper validates the project name, looks up its Compose files from
`docker compose ls`, and refuses to proceed unless every Compose file and its
parent directory chain is root-owned and not group/world-writable. The default
scan root is `/opt`; the project does not have to live there, but the files must
meet the trust requirement. No `down -v`, no volume pruning, no automatic
updates.

### System information

The implemented read-only `system-info` helper action collects a bounded
snapshot:

- CPU model, cores, and load average.
- Memory and swap.
- Disk usage per mount.
- Network interfaces, addresses, default route, and DNS.
- Kernel, architecture, boot time, uptime, and virtualisation/container hints.
- systemd version, failed units, and running-service count.
- Listening ports.
- Docker Engine and Compose versions, and container counts.
- Time-sync state and reboot requirement.

Full facts/system information runs twice a day by default. Lightweight
`metrics` samples (CPU, memory, disk, load) feed the history graphs. Defaults
are 5 minutes for metrics, 12 hours for full facts, and 30 days of metric
retention; all three are configurable per fleet or per host. Ten seconds is
allowed but discouraged for large fleets. The host detail **System** tab shows
the current snapshot and the last 10 days of metric history.

### Monitoring and email

The implemented host detail view has **Overview**, **System**, and
**Containers** tabs. A future **Services** tab and monitoring rules will be
defined once and assigned to hosts, groups, or the fleet; assignments are
filtered by capability, so Docker checks only apply to hosts with Docker.

Planned check types:

- Host thresholds: CPU, memory, disk, load.
- systemd service up/down.
- Docker project/container up/down and health.
- HTTP/HTTPS endpoint status, latency, and optional TCP port.
- SSL certificate expiry and chain validation.
- Later: vCenter and child objects, HAProxy, and OPNsense.

Email alerts will use SMTP with TLS and authentication. Credentials will be
stored only in the SQLCipher database, never logged or returned by the API.
Alerts will support recipients, cooldowns/deduplication, recovery notices, and
an audit trail. System information remains read-only in the first release; no
service start/stop/restart.

### CMDB

CMDB-lite remains the offline inventory authority. HIBP will provide a
read-only CMDB CSV/JSON import with a preview and an explicit per-record choice
to **merge** or **overwrite**. It will map `external_id`/`ci_id` to
`cmdb_ci_id`. HIBP will not write back to the CMDB database.

### Delivery phases

1. **Implemented:** read-only system information, Docker inventory, host detail
   view, twice-daily collection, metric history, fleet/per-host settings.
2. **Implemented:** Docker project-level check/apply with trust checks and
   explicit confirmation.
3. **Next:** monitoring definitions, SMTP email, HTTP/TCP/SSL checks, services.
4. vCenter, HAProxy, and OPNsense integrations.
5. CMDB import with preview and merge/overwrite.

### Collection settings

The **Settings** entry in the sidebar stores fleet defaults. Each host can
override them in **Host detail → System → Collection settings**:

- `collector.enabled` — enable/disable scheduled collection.
- `collector.metrics_interval` — default `5m`; minimum `10s`.
- `collector.facts_interval` — default `12h`.
- `metrics.retention_days` — default `30`, validated 1–3650.
- `docker.scan_roots` — default `/opt`, used by the planned Docker update
  phase.

Host overrides take precedence over fleet defaults; **Use fleet defaults**
removes the host overrides. The scheduler reloads settings every minute.

## Target sudo setup

HIBP uses `sudo -n` for unattended actions. It never stores a sudo password, and
it does not send one in a command line or environment variable. The supported
unattended automation model is a **root-owned helper with a restricted NOPASSWD
rule**.

The helper accepts only this fixed set of actions:

```text
facts
check
apply
reboot
reboot-check
system-info
metrics
docker-list
docker-check <project>
docker-apply <project>
```

It does not accept package names, host names, or arbitrary shell fragments. This
is not equivalent to `NOPASSWD: ALL`.

### Install from the app (recommended)

After the host key is trusted, click **Setup** on the host row. HIBP:

1. uploads its own executable to `/usr/local/libexec/hibp/hibp-helper`;
2. writes `/etc/sudoers.d/hibp-helper` for the host's configured SSH username;
3. validates the rule with `visudo` before renaming it into place;
4. verifies it with `sudo -n ... facts` and reports the result.

If the host uses password SSH, enter the SSH password when prompted. If sudo
requires a password, enter the sudo password when prompted. The Setup action is
idempotent and is recorded in the audit log as `bootstrap-helper`.

The controller uploads **its own binary**, so remote installation requires the
static release build and matching CPU architectures. For a different
architecture or a custom helper path, use the manual instructions below.

The first install needs sudo rights to create `/usr/local/libexec/hibp` and
write `/etc/sudoers.d`. If the account only has the four fixed helper rules,
installing a new helper requires a manual root step.

Security notes:

- HIBP validates sudo before uploading the helper binary, so a wrong sudo
  password is rejected before any files are transferred.
- The uploaded binary is run as the unprivileged SSH account before it replaces
  an existing helper. A dynamically linked or incompatible binary is rejected
  without touching the working helper.
- The sudo password is used only for this setup request, sent over SSH stdin,
  and never stored.
- The final verification always uses `sudo -n`. If the restricted rule does not
  work, Setup fails instead of reporting success.
- The temporary sudoers file is dot-named, so sudo ignores it while `visudo`
  validates it. It is renamed into place only after validation.
- The SSH username is validated, and the reserved name `ALL` is rejected.
- The helper is installed root-owned and mode `0755`; the sudoers file is
  root-owned and mode `0440`.

### Update helpers across the fleet

The **Hosts** page has an **Update helpers** action (also linked from the
dashboard host card). It runs the setup flow sequentially for every host in the
inventory and shows a per-host progress and result table.

- It installs the helper version of the **currently running HIBP server**.
  Restart the server after upgrading the controller, otherwise the old running
  process uploads its old binary.
- Hosts with untrusted host keys are skipped with a clear result. Run **Test**
  and trust the key first.
- Password-auth hosts and sudo prompts may ask per host. A working restricted
  `NOPASSWD` rule makes fleet updates unattended.
- The operation is foreground: keep the tab open. **Stop after current host**
  cancels the remaining queue; the host currently being updated finishes.
- Each successful host is recorded as `bootstrap-helper` in the audit log.
- The fleet action never trusts host keys automatically and never stores
  passwords.
- Use the per-host **Setup** action when only one target needs an update.

### Configuration model

Configuration is fleet-first with per-host overrides where it makes sense:

- Fleet-level defaults: collection intervals, alert thresholds, recipients,
  monitoring enablement.
- Group/tag overrides and explicit host overrides.
- Capability-aware assignments: Docker monitoring only applies to hosts with
  Docker; systemd monitoring only to systemd hosts; HTTP/SSL/TCP monitors can
  apply anywhere.
- SMTP is a global integration; recipients can be set per monitor or fleet.
- Helper lifecycle: per-host **Setup** and fleet-wide **Update helpers**.
- Secrets (SMTP, vCenter, API tokens) live only in SQLCipher and are never
  returned by the API.

### Install the helper manually

Copy the same `hibp` binary to the fixed helper path:

```bash
sudo install -d -m 0755 /usr/local/libexec/hibp
sudo install -m 0755 /path/to/hibp /usr/local/libexec/hibp/hibp-helper
```

Then create a sudoers rule. Replace `hibp` with the SSH account the controller
uses to log in:

```bash
sudo tee /etc/sudoers.d/hibp-helper >/dev/null <<'EOF'
# Replace "hibp" with the SSH account used by the controller.
hibp ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper facts
hibp ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper check
hibp ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper apply
hibp ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper reboot
hibp ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper reboot-check
hibp ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper system-info
hibp ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper metrics
hibp ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper docker-list
hibp ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper docker-check *
hibp ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper docker-apply *
EOF
sudo chmod 0440 /etc/sudoers.d/hibp-helper
sudo visudo -cf /etc/sudoers.d/hibp-helper
```

Verify from the controller account:

```bash
ssh user@target 'sudo -n /usr/local/libexec/hibp/hibp-helper facts'
```

You should see the helper JSON, not a password prompt.

### Reboot

The host row has a **Reboot** button. It asks for explicit confirmation and
runs the fixed `reboot` helper action as root. The helper uses
`systemctl reboot --no-block` when systemd is available and falls back to
`shutdown -r now`. HIBP never reboots automatically. Later/scheduled reboots are
part of the scheduler work.

### If the SSH account is not `hibp`

Use the actual account name. For example, if the controller logs in as `roger`:

```bash
sudo sed -i 's/^hibp /roger /' /etc/sudoers.d/hibp-helper
sudo visudo -cf /etc/sudoers.d/hibp-helper
```

A dedicated account such as `hibp` with its own SSH key is preferable: it keeps
the sudo rule narrow and makes the audit trail clear.

### SELinux

On Fedora, RHEL, or SUSE with SELinux enforcing, an execution denial means the
uploaded helper has the wrong file context. Check and repair it:

```bash
ls -lZ /usr/local/libexec/hibp/hibp-helper
sudo restorecon -RF /usr/local/libexec/hibp
```

The Setup action runs the candidate helper before replacing a working install,
so an execution denial is reported instead of silently leaving a broken helper.

### Manual sudo password fallback

If the target cannot use a `NOPASSWD` rule yet, the UI can prompt for the sudo
password for **manual** Setup, Facts, Check, and Apply actions. **Setup** uses
the password to install the restricted helper rule; after it succeeds, the
manual actions use `sudo -n` and no longer need the sudo password.

- The server first tries `sudo -n`.
- If the target answers `sudo_password_required`, the UI prompts.
- The retry uses `sudo -S -p ''`; the password is supplied over SSH stdin.
- It is never written to the database, logs, argv, environment variables, or
  browser `localStorage`.
- It is held in browser/server memory for the tab/session. Close the tab or
  restart the server to clear it.
- A wrong password is rejected and the cached value is discarded.

This fallback is for interactive use only. **Scheduled patching still requires
the restricted `NOPASSWD` helper or agent mode.** An unattended schedule cannot
answer a sudo prompt.

### If you cannot change sudoers

Use the manual password fallback for interactive work, or:

- install the restricted helper rule as above;
- use a dedicated account that is allowed to run only the helper;
- run the helper manually from a root shell;
- wait for agent mode, which will run as root under systemd without an SSH login
  or sudo password.

Scheduled patching through HIBP requires passwordless execution of the helper.

### Troubleshooting `sudo: interactive authentication is required`

This means the `sudo -n` rule is missing, the username is wrong, the helper path
is different, or the command arguments do not match exactly. Check:

```bash
sudo -l -U <ssh-user>
sudo visudo -cf /etc/sudoers.d/hibp-helper
ls -l /usr/local/libexec/hibp/hibp-helper
```

The helper must be owned by `root:root`, must not be writable by the SSH
account, and the sudoers path must match exactly.

Click **Setup** and enter the sudo password when prompted. If Setup reports
that the NOPASSWD rule does not work, check the username, helper path, and
`visudo` output. Manual Facts/Check/Apply work with the password fallback, but
schedules do not.

## Why it exists

Linux fleets are rarely homogeneous. A single environment may contain Ubuntu,
Debian, Kali, Fedora, RHEL or a rebuild, Arch, openSUSE, and Alpine. Each has a
different package manager, different update commands, different reboot
indicators, and different notions of a "security update". The operator usually
ends up with a wiki page, a handful of shell scripts, and no reliable answer to
"when was this host last patched?".

The problem is not only convenience. Patch execution requires privileged access
to every host. That makes the server a high-value target: a compromised server
can run commands as root across the fleet. HIBP must therefore treat
credential handling, host identity, least privilege, auditability, and recovery
as core features rather than afterthoughts.

## Goals

- **G1 - One Linux executable.** A Go binary with `server`, `helper`, and
  `version` commands; future `client` and `agent` modes reuse the same core. The
  browser UI assets are embedded; there is no separate web folder, runtime, or
  web server to install.
- **G2 - Always-on server, laptop client and optional target.** The server owns
  the encrypted database, scheduler, credentials, and job queue. The laptop is a
  thin client and never opens the database directly; it can also be enrolled as
  a managed host. Agentless SSH is the default; an agent is optional later for
  segmented networks or scale.
- **G3 - Cross-distribution by design.** Debian/Ubuntu/Kali, Fedora/RHEL family,
  and openSUSE/SLES are the first implementation targets; Arch/Manjaro and Alpine
  follow. Unknown distributions are read-only until a profile is added.
- **G4 - Frictionless onboarding.** Add a host in the browser UI, import a CSV or
  TXT list, or import configuration items from `cmdb-lite`.
- **G5 - Key-based authentication by default.** SSH private keys, `ssh-agent`,
  hardware-backed keys, and SSH certificates, with mandatory host key
  verification and least-privilege sudo. Password SSH is an explicit opt-in
  fallback, disabled by default.
- **G6 - Encrypted, portable storage.** A user-selected SQLCipher database plus
  a key-derivation sidecar, with encrypted backup and restore.
- **G7 - Facts that matter.** OS and kernel, uptime and last boot, pending
  updates, reboot-required state, disk space, time sync, and last patch result.
- **G8 - Safe on-demand patching.** Select one or more hosts, preview the change,
  apply it, cancel it, and see per-host progress and failures.
- **G9 - Schedules that survive reality.** Maintenance windows, time zones,
  jitter, missed-run policy, concurrency limits, and notifications.
- **G10 - Evidence.** Per-run package diffs (old version to new version),
  exit codes, logs, duration, reboot state, and a drill-down per host.
- **G11 - Tamper-evident audit.** Every privileged action is recorded in a
  hash-chained audit log and can be exported to an external log sink.
- **G12 - Integration without coupling.** `cmdb-lite` remains the inventory
  system of record; HIBP consumes inventory and writes back patch status without
  sharing databases, passphrases, or credentials.

## Non-goals

- Windows or macOS target patching in v1. The server is Linux; targets are
  Linux. Other platforms may follow, but they are not part of the initial data
  model or execution profiles.
- Replacing a full configuration management system. HIBP does not manage
  arbitrary desired state, users, files, or services.
- An unrestricted remote shell as a default feature. Arbitrary remote scripts
  are a remote-code-execution feature by definition and are treated separately
  in the security model.
- Multi-tenant SaaS, SSO, and fine-grained RBAC in v1. The schema and audit
  model should make them possible later.
- A built-in CVE scanner. CVE correlation is better delegated to an existing
  scanner (Trivy, Grype, OSV, or a distro feed) and linked to patch results.
- Automatic reboots. HIBP never reboots automatically; the operator chooses
  **Reboot now** or **Reboot later** after a run.
- A native desktop window with zero shared libraries. A browser-based UI served
  by the binary is the practical route to a truly static executable; a native
  webview requires GTK3/WebKitGTK. See
  [Packaging and "single executable"](#packaging-and-single-executable).
- Password SSH as the default. It is an explicit opt-in fallback, disabled by
  default, and intended primarily for manual runs; it is not the security
  baseline.
- An agent on every target in v1. The always-on server makes agentless
  scheduling viable; an agent is a later option for DMZs, NAT, or very large
  fleets.
- Synchronizing one database between a laptop and a server. The server is
  authoritative; the laptop is a client. Standalone laptop mode uses a separate
  database and does not sync in v1.

## Product requirements

### Server and laptop client

- `hibp server` runs on an always-on Linux host. It owns the encrypted database,
  scheduler, job queue, SSH credentials, and audit log.
- The laptop uses the browser UI through an SSH tunnel. A future `hibp client`
  command can provide a native shell; it would still never open the database
  directly.
- The laptop can also be enrolled as a managed target. It is still a client, not
  the server; patching it follows the same policy and helper rules as any host.
- The server binds to a Unix socket or `127.0.0.1` by default. It must not listen
  on a public interface without TLS and authentication.
- The same binary supports both modes. A standalone `hibp --local` mode may use
  a local database for travel or a lab, but it does not sync with the server in
  v1.
- Single-user v1 means one operator, not unauthenticated access: the server is
  protected by the OS account, SSH key, and database passphrase.

### Host inventory and onboarding

- Add or edit a host manually: name, address, SSH port, authentication method,
  sudo mode, group, tags, schedule, and notes.
- Test the connection before saving. Show the resolved OS, host key fingerprint,
  authentication result, and sudo capability.
- Import hosts from CSV or TXT with a preview and an explicit duplicate policy
  (`error`, `skip`, or `update`). Imports never write until confirmed.
- Import configuration items from `cmdb-lite` using its CSV/JSON export and
  preserve `external_id` as the stable link.
- Group hosts by environment, role, location, or arbitrary tags. Support bulk
  selection and saved filters.
- Mark hosts as enabled, disabled, maintenance, or retired. Disabled hosts are
  never scheduled.

### Authentication and privilege

- SSH private key from a file path, with optional passphrase.
- `ssh-agent` and hardware-backed keys (PKCS#11/PIV) as the preferred method.
- SSH certificate authentication where the environment uses short-lived
  certificates.
- Key-based authentication is the default and the required baseline. Password
  and keyboard-interactive SSH are an explicit opt-in fallback for legacy hosts,
  disabled by default. When enabled: per-host opt-in, prominent warning, store
  the password only in the OS keyring or prompt per run, never in the database or
  logs, and prefer migrating the host to keys.
- In v1, password fallback is for manual runs only. Scheduled password auth
  through an external vault/keyring is a later opt-in; the password must never be
  persisted in the HIBP database.
- The always-on server needs an unattended service key. Protect it with a
  dedicated service account, `0600` permissions, and full-disk encryption; use
  TPM2/`systemd-creds` where available. Prefer short-lived SSH certificates or
  per-host keys over one shared key.
- Per-host credentials, group defaults, and a global default with explicit
  precedence.
- Separate SSH authentication from sudo authentication. Keys do not solve sudo:
  use a restricted root-owned helper with `NOPASSWD` for fixed actions. If sudo
  requires a password, prompt for it per run; never store it.
- Host key verification is mandatory. First use requires explicit fingerprint
  approval; a changed key is a hard failure, not a prompt that can be clicked
  away.
- The host form has a **Browse** button for server-side SSH key directories. It
  lists names, sizes, and permissions only; it never reads or returns private key
  contents. The default directory is `~/.ssh`; use `--key-dir` to add more.

### Patch visibility

- Detect the distribution from `/etc/os-release` and the package manager from the
  available binaries, not from a hard-coded hostname convention.
- Collect pending updates, including security classification where the package
  manager supports it.
- Show current and candidate versions, repository, download size, and whether a
  reboot is required.
- Show uptime, last boot time, kernel, and the last successful patch run. Make
  the collection timestamp visible so stale data is obvious.
- Flag end-of-life distributions and hosts that have not checked in for a
  configurable period.

### Patch execution

- Select one or more hosts and choose **Patch now**.
- Always offer a dry-run/preview that lists the packages and versions that would
  change.
- Support security-only and all-updates policies, package excludes, and held
  packages.
- Run with a fixed, reviewed profile per distribution. Never build a shell
  command by concatenating host names, user names, package names, or script
  fragments.
- Enforce a timeout, capture bounded output, redact secrets, and record the exit
  code.
- Serialize package-manager work per host. Detect `apt`/`dpkg`, `dnf`, `pacman`,
  and `zypper` locks instead of killing another package manager.
- Allow cancellation. Cancellation must terminate the process group, record the
  cancellation, and leave the host in a known state where possible.
- Detect whether a reboot is required after the run. Offer **Reboot now** from
  the host row. Later/scheduled reboots are part of the scheduler work; HIBP
  never reboots automatically.

### Scheduling

- Per-host and per-group schedules using a cron expression or systemd
  `OnCalendar` syntax.
- Time zone per schedule, with UTC stored internally.
- Jitter to avoid a thundering herd, and maintenance windows with a start and
  end time.
- Missed-run policy: skip, run once on next start, or bounded catch-up.
- Global, per-group, and per-host concurrency limits.
- A visible next-run time and a run history with the trigger source (manual,
  schedule, retry, API).
- Notifications on failure, reboot required, stale host, and long-running jobs.
  v1 supports webhook and ntfy; email, Slack, and Teams are later.
- Schedules run on the always-on server, not on the laptop. Closing the laptop
  must not affect a schedule.
- If the server reboots, schedules pause until the operator manually unlocks the
  database. The UI shows the locked/paused state. No database key is persisted in
  v1.

### History and drill-down

- Per host: last check, last successful patch, last failed patch, pending
  updates, reboot state, uptime, and a timeline of runs.
- Per run: trigger, actor, start/end time, duration, package manager, kernel
  before/after, exit code, reboot-required result, and log.
- Per package: old version, new version, action (upgrade, install, remove,
  skipped, failed), security flag, and repository.
- Per host drill-down: what was upgraded, what is still pending, what is held
  back, and why.
- Export a run or a host history as CSV/JSON for evidence and reporting.

### Database and operations

- Create or open an encrypted database at a path chosen by the operator.
- Keep the database outside the application installation directory so upgrades
  never replace or delete it.
- Back up and restore from the browser UI. Backups are consistent, encrypted,
  and include the key-derivation sidecar.
- Apply schema migrations automatically on open, after creating a pre-migration
  backup.
- Refuse to open a database created by a newer schema version.
- Lock the database without exiting the application.
- Remember recent database paths without remembering the passphrase.

### Integration and automation

- A CLI for headless use: add hosts, collect facts, run checks, start a patch
  job, export results.
- A local API (Unix socket by default) for the browser UI and future
  integrations. If a TCP listener is added, it must be TLS-protected,
  authenticated, and disabled by default.
- Notifications via webhook and ntfy in v1; email, Slack, and Teams later.
- Import from `cmdb-lite`; write back patch status as attributes or through a
  documented integration API.
- Optional Prometheus metrics for fleet-level monitoring.

## Supported distributions

The profile layer must be data-driven and testable. First implementation
priority: **Debian, Ubuntu, Kali, Fedora, and SUSE**. Arch and Alpine are
supported by the profile model but are scheduled after the first five.

The always-on server baseline is **Ubuntu LTS 24.04/26.04; 22.04 best-effort**. The static binary
may run on other distributions, but Ubuntu is the supported and tested server
platform.

The table below describes the intended default behavior; exact flags must be
verified against each distribution release before implementation.

| Family | Examples | Check for updates | Apply updates | Reboot indicator | Notes |
|---|---|---|---|---|---|
| Debian | Debian, Ubuntu, Kali, Linux Mint | `apt-get update` then `apt list --upgradable` or a simulated upgrade | `apt-get -y upgrade`; use `full-upgrade` only when the policy allows it | `/var/run/reboot-required`; `needrestart -b` for services | Kali is rolling and closer to Debian testing; use a canary ring. Ubuntu phased updates may delay packages. |
| Fedora / RHEL | Fedora, RHEL, AlmaLinux, Rocky Linux, CentOS Stream | `dnf check-update` (exit code 100 means updates) | `dnf -y upgrade --refresh`; security-only where the release supports it | `needs-restarting -r` (exit code 1 means reboot) | RHEL-family security filters depend on release and plugins. Subscription/repo state must be checked. |
| SUSE | openSUSE Leap, Tumbleweed, SLES | `zypper refresh` then `zypper list-updates` | `zypper --non-interactive update`; `zypper patch --category security` for security-only | `zypper needs-reboot` | Tumbleweed is rolling. SLES may require registration and modules. |
| Arch | Arch Linux, Manjaro, EndeavourOS | `checkupdates` (pacman-contrib) or `pacman -Qu` | `pacman -Syu --noconfirm` | Compare running kernel with the installed kernel; use a distro-specific helper where available | Never do a partial upgrade. Arch is rolling; canary and snapshot support matter. |
| Alpine | Alpine Linux | `apk update` then `apk version -l '<'` or an equivalent query | `apk upgrade` | Kernel/package heuristics; reboot when the kernel or critical base packages change | musl-based; package and service behavior differs from glibc distributions. |
| Unknown | Anything else | Read-only fact collection | Refused until a profile is installed | Unknown | Fail closed. A custom profile interface is preferable to guessing. |

Additional distribution rules:

- Detect the family from `/etc/os-release` (`ID`, `ID_LIKE`, `VERSION_ID`) and
  verify the package manager binary exists.
- Never disable repository GPG verification. Do not use
  `--allow-unauthenticated`, `--nogpgcheck`, `--force`, or equivalent defaults.
- Check repository reachability, expired keys, and disk space before applying
  updates. A full `/boot` or `/var` is a common cause of failed upgrades.
- Check time synchronization. Large clock skew breaks TLS, repository metadata,
  and certificate validation.
- Flag end-of-life distributions. An EOL host can appear "up to date" while
  receiving no security fixes.
- Treat distribution upgrades (for example Ubuntu 24.04 to 26.04) as a separate,
  explicitly approved workflow, not as a routine patch run.

## Recommended architecture

### Deployment model

The primary deployment is server-authoritative:

1. **Always-on Linux server (`hibp server`).** It owns the encrypted SQLCipher
   database, scheduler, job queue, SSH credentials, and audit log. It runs under
   systemd and binds its local UI/API to a Unix socket or `127.0.0.1`.
2. **Laptop client (`hibp client` or a browser).** The operator connects to the
   server through an SSH tunnel (`ssh -L`) or, if explicitly enabled, TLS. The
   laptop never opens the database and never holds the SSH credentials used for
   patching. The laptop can also be enrolled as a managed target; it is still a
   client, not the server.
3. **Optional standalone mode (`hibp --local`).** A local database for travel, a
   lab, or a demo. It does not sync with the server in v1. Treat it as a separate
   installation.

This supports both an always-on server and laptop use without creating two
writers to one database. The server is the source of truth; the laptop is a view
and control surface. The same binary provides both modes.

The server starts **locked** after a reboot. The operator unlocks the database
through the browser UI over the SSH tunnel, and schedules resume. While the
database is locked, the UI shows a paused state and no patch jobs run. This is a
deliberate v1 trade-off: no database key is persisted, so a stolen disk or a
compromised server at rest does not expose the fleet credentials.

If the server is unavailable, the laptop can still open its own standalone
database, but it cannot see or change the server's data. Database synchronization
is deliberately out of scope for v1 because conflict resolution, credential
distribution, and audit ordering would add significant complexity and risk.

**Recommendation:** make the server the primary target. It solves the
laptop-sleep problem and keeps the database key, SSH credentials, and audit trail
on one hardened host. Schedules pause after a server reboot until manual unlock.
Add a native desktop client later only if the browser UI is insufficient.

### Why not only agentless?

With an always-on server, agentless SSH is sufficient for reliable schedules:
the server is awake, online, and can hold the database key. The earlier objection
to agentless scheduling was a laptop controller that sleeps; that no longer
applies.

Agentless still has limits:

- It requires inbound SSH and sudo on every target.
- It centralizes root-equivalent credentials on the server.
- It struggles with hosts behind NAT, strict DMZs, or networks that forbid
  inbound SSH.
- A very large fleet needs connection pooling, concurrency limits, and careful
  key management.

An agent is therefore an optional later addition for segmented networks, NAT,
scale, or environments that prefer outbound-only management. It is not required
for v1. If you add one, use mTLS, signed policy, per-agent certificates, and the
same narrow helper.

### Component diagram

```text
┌──────────────────────────────┐
│ Laptop                       │
│ browser or hibp client       │
│ no local database            │
│ optional managed target      │
└──────────────┬───────────────┘
               │ SSH tunnel (recommended) or TLS
┌──────────────▼───────────────────────────────────────────────┐
│ Always-on Linux server: hibp server (one ELF)                │
│  ├─ encrypted SQLCipher database + .meta sidecar             │
│  ├─ scheduler, job queue, approvals, audit                   │
│  ├─ SSH transport + host-key verification                    │
│  ├─ distribution profiles (apt, dnf, pacman, zypper, apk)    │
│  ├─ notifications and exports                                │
│  └─ local web UI/API (Unix socket or 127.0.0.1)              │
└──────────────┬───────────────────────────────────────────────┘
               │ SSH, verified host keys
     ┌─────────┼─────────┐
     ▼         ▼         ▼
  Debian    Fedora    Arch/openSUSE/Alpine
  apt       dnf       pacman / zypper / apk
```

Optional later:

```text
hibp agent (systemd timer) ── outbound mTLS ──► hibp server
        │
        ├─ local policy + signed profile
        ├─ native package manager as root
        └─ structured result + audit event
```

### Execution flow

1. **Preflight.** Resolve the host, connect, verify the host key, authenticate,
   detect the OS and package manager, check `sudo -n`, check disk space, check
   time sync, and detect package-manager locks.
2. **Collect.** Read facts and pending updates. Store them with a collection
   timestamp. Never present stale data as current.
3. **Plan.** Apply the patch policy (security-only or all, excludes, held
   packages, reboot handling) and produce a dry-run package diff.
4. **Approve.** For production or high-risk policies, require an explicit
   approval. The approval records the actor, the plan hash, and the host list.
5. **Execute.** Send the reviewed profile over SSH using a fixed argv or a
   root-owned helper. Run with a timeout, capture bounded output, and serialize
   per host.
6. **Verify.** Re-read package versions, service state, reboot-required state,
   and uptime. If a reboot was performed, reconnect and verify after boot.
7. **Record.** Write the run, package diff, log digest, exit code, and audit
   event. Notify on failure or reboot-required.
8. **Retain.** Prune old logs according to policy while keeping the audit trail
   and run summaries.

### Concurrency and failure handling

- Design target is 2–500 hosts. The default worker pool should stay modest
  (around 10–20 concurrent hosts), be configurable, and respect repository
  capacity. Paginate large host lists and index the queries that drive them.
- One active package-manager operation per host. A second job for the same host
  waits or is rejected.
- Global and per-group worker pools, with a default concurrency low enough to
  avoid saturating repositories or the server.
- Idempotent job targets. A retry must not create duplicate package operations
  or duplicate audit entries.
- Resume after a server restart. Jobs that were running when the process
  stopped are marked `interrupted`, not silently `succeeded`.
- Failure isolation: one host failing must not cancel the rest of the job unless
  the policy explicitly says so.
- Retry with backoff only for transient failures (network, lock contention,
  mirror timeout). Do not retry authentication failures or policy violations
  blindly.

## Security model

HIBP is a privileged remote administration tool. See [`SECURITY.md`](SECURITY.md)
for vulnerability reporting and scope. The security model below is the design
baseline; the M1 implementation status is called out explicitly.

### Assets

- SSH private keys, key passphrases, SSH certificates, and sudo passwords.
- The encrypted database and its backups.
- The database passphrase and any derived keys.
- The authority to execute package-manager commands as root on every managed
  host.
- Host identity records and known host keys.
- Patch evidence and audit logs.
- The integrity of the HIBP binary, its profiles, and its updates.

### Threat model

**Protected against, with the stated assumptions:**

- Theft or unauthorized copying of the database or a backup, assuming a strong
  passphrase and a non-compromised machine.
- Casual inspection of the database by another local user.
- SSH man-in-the-middle attacks, provided host keys are verified and not
  blindly trusted on first use.
- Command injection through imported host names, package names, or script
  arguments, provided execution uses fixed argv/helpers and strict validation.
- Unauthorized patch runs by someone without the database passphrase and OS
  access to the server.
- Silent modification of the audit log by accident, detected by the hash chain.
- Credential leakage into logs, provided redaction is implemented and tested.

**Not protected against:**

- A compromised server while the database is unlocked. At that point the
  attacker can use the stored credentials and execute commands on managed
  hosts. This is the dominant risk of the product.
- A malicious or compromised distribution repository, mirror, or package
  supply chain. HIBP uses the distro's trust model; it does not re-verify every
  package.
- A malicious administrator who has the database key and host access. The audit
  chain is tamper-evident, not tamper-proof, for a key holder.
- Theft of the server's unattended SSH key. Protect it with a dedicated service
  account, strict permissions, full-disk encryption, and rotation.
- A weak, reused, or phished passphrase.
- A compromised target, including a compromised agent running as root.
- Screen capture, keyboard loggers, or a compromised webview.
- Trust-on-first-use mistakes. The first fingerprint must be verified through an
  independent channel.
- Outages caused by a bad update. Rollback depends on snapshots, backups, or
  distribution support and is not guaranteed.
- Loss of scheduled patching after a server reboot until an operator manually
  unlocks the database. This is an intentional v1 availability trade-off.
- Legal or authorization issues. Patching hosts you do not own or administer is
  the operator's responsibility.

### Encryption at rest

- **Database:** SQLCipher 4, AES-256-CBC with per-page HMAC-SHA512
  authentication. This protects the whole database, including indexes, package
  history, host records, and audit data.
- **Key derivation:** Argon2id13 with a memory-hard configuration (at least the
  moderate libsodium profile: 3 passes, 256 MiB) and a random salt.
- **Sidecar:** a `<database>.meta` file contains the KDF algorithm, parameters,
  salt, format version, and a BLAKE2b-256 checksum. It contains no secret
  material, but the database cannot be opened without it. Back up the pair
  together.
- **File permissions:** database, sidecar, backups, logs, and temporary files
  are created with mode `0600` where possible. The containing directory must
  not be world-writable.
- **SQLite settings:** `cipher_memory_security=ON`, `secure_delete=ON`,
  `foreign_keys=ON`, `temp_store=MEMORY`, `trusted_schema=OFF`, WAL with
  appropriate synchronous settings.
- **Memory:** zeroize passphrases and derived keys after use. Document the
  limitation that a webview or runtime may retain copies.
- **No plaintext exports by default.** CSV/JSON exports and logs must be
  explicitly requested and clearly marked as potentially sensitive.
- **No secrets in argv or environment variables.** Passwords and passphrases go
  through stdin, a file descriptor, or an OS keyring, never through a command
  line that other local users can read from `/proc`.

For credentials, use **envelope encryption** even though the whole database is
already encrypted:

- Generate a random data encryption key (DEK) for the credential vault.
- Derive a key-encryption key (KEK) from the database passphrase with Argon2id,
  or obtain it from the OS keyring/TPM.
- Wrap the DEK with the KEK and store only the wrapped DEK in the database.
- Encrypt individual secrets with the DEK using an authenticated cipher such as
  XChaCha20-Poly1305.
- Rotating the passphrase rewraps the DEK; it does not require re-encrypting
  every secret.

This is defense in depth and makes future key rotation and multi-user support
practical. If v1 keeps credentials only in the OS keyring, the envelope design
can be added later without changing the host schema.

### Credential handling

Preferred order, from safest to riskiest:

1. `ssh-agent` or a hardware-backed key. The private key never enters HIBP.
2. SSH certificate authentication with short-lived certificates.
3. A passphrase-protected private key file referenced by path.
4. An unencrypted private key file with strict `0600` permissions and a clear
   warning.

Password and keyboard-interactive SSH authentication are an **explicit opt-in
fallback**, disabled by default. They are not part of the security baseline.
When enabled:

- Require a per-host opt-in and show a prominent warning in the UI.
- Store the password only in the OS keyring or an external vault, or prompt for
  it per run. Never store it in the HIBP database or logs.
- In v1, use it for manual runs only. Scheduled password auth through an external
  vault/keyring is a later opt-in; otherwise the schedule is refused.
- Rate-limit attempts, avoid retry storms, and record failures in the audit log.
- Prefer migrating the host to keys and flag it as a technical-debt item.

Rules:

- Never log private keys, passphrases, passwords, tokens, or full command lines
  that contain them.
- Reference private keys by path; do not copy them into the database by default.
  If a key must be imported, encrypt it with the credential vault and require an
  explicit confirmation.
- Treat the server's unattended SSH key as a crown jewel. Prefer a dedicated key
  or short-lived SSH certificate; protect it with TPM2/`systemd-creds` where
  available; restrict it to the HIBP service account; rotate it; audit its use.
- Separate SSH credentials from sudo credentials. Keys do not solve sudo: use a
  restricted helper or prompt per run.
- Scope credentials globally, per group, or per host, with explicit precedence.
- Record credential creation, rotation, and deletion in the audit log, but never
  record the secret itself.
- Provide a rotation workflow and a "revoke and re-enter" path after a suspected
  compromise.

### Single-user access

- v1 has one operator and no RBAC. "Single user" does not mean unauthenticated.
- The server binds to a Unix socket or `127.0.0.1`. The laptop connects through
  an SSH tunnel, so the server's remote surface is SSH, not an exposed web port.
- The UI requires a local password plus TOTP and/or a passkey. The database
  passphrase is a separate startup secret and is not reused for the web login.
- The browser receives an HttpOnly, SameSite=Strict session cookie. Only a
  SHA-256 hash of the session token is stored. Pending MFA sessions are
  short-lived and cannot reach application endpoints.
- The database is unlocked manually after a server reboot. The server does not
  persist the database key in v1. While locked, the UI shows a paused state and
  schedules do not run.
- If a TCP listener is enabled for the UI/API, require TLS and an explicit
  opt-in. The current implementation only accepts loopback Host headers. Do not
  expose it to the internet.
- The audit actor is the authenticated username in v1. The schema keeps an actor
  column so RBAC can be added later.
- Do not share the database file or passphrase between users. Do not run two
  server instances against the same database.

### Host key verification

- Maintain a per-host known-host-key record with key type, fingerprint, first
  seen, last seen, and trusted/revoked state.
- On first connection, show the fingerprint and require explicit approval. Do
  not silently trust `ssh-keyscan` output.
- On a changed key, fail the connection, show both fingerprints, and require an
  explicit rotation action with an audit entry.
- Support multiple host keys per host during a rotation window.
- Never set `StrictHostKeyChecking=no` or `UserKnownHostsFile=/dev/null` as a
  convenience default.
- For jump hosts, verify every hop, not only the final target.

### Least privilege and sudo

The server needs root-equivalent privileges on targets to install packages.
That authority must be narrow and auditable.

- Use a dedicated account for HIBP where possible, not a personal admin account.
- Prefer a root-owned helper installed on the target, invoked through a
  restricted sudoers rule. The helper accepts a small allowlist of actions
  (`facts`, `check`, `apply`, `reboot`, `reboot-check`, `system-info`,
  `metrics`, `docker-list`, `docker-check <project>`, `docker-apply <project>`,
  `custom:<approved-id>`) and validates its arguments.
- Example sudoers shape (illustrative, not a complete hardening guide):

  ```sudoers
  hibp ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper facts
  hibp ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper check
  hibp ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper apply
  hibp ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper reboot
  hibp ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper reboot-check
  hibp ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper system-info
  hibp ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper metrics
  hibp ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper docker-list
  hibp ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper docker-check *
  hibp ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper docker-apply *
  ```

- Do not recommend `ALL=(ALL) NOPASSWD: ALL`. If an operator insists, warn
  explicitly and record it as a finding.
- If sudo requires a password, supply it over stdin to `sudo -S`, never on the
  command line. Consider an askpass helper for GUI-driven runs.
- The helper and its configuration must be owned by root and not writable by
  the account HIBP uses.
- The agent, if used, should run the same narrow helper rather than exposing a
  general root shell.
- Apply systemd hardening to server and agent units where compatible with the
  package manager: `NoNewPrivileges` where possible, `PrivateTmp`,
  `ProtectSystem`, `ProtectHome`, `RestrictAddressFamilies`,
  `MemoryDenyWriteExecute`, and a minimal `CapabilityBoundingSet`. Package
  managers need broad filesystem access, so test each restriction rather than
  copying a generic unit file.

### Remote scripts and playbooks

The requirement to "add a script or system function" is a request for remote
code execution as root. It must be designed as a first-class, audited feature.

**Decision: versioned, approved playbooks only. Arbitrary shell is not supported
in v1.**

- Built-in actions cover normal patching: facts, check, apply, reboot, and reboot-check.
- A playbook is a named, versioned, reviewed script or profile with a SHA-256
  hash and optional signature.
- The browser UI shows the content, hash, author, approver, and approval time
  before it can be used.
- A playbook cannot be edited after approval without creating a new version and
  a new approval.
- Execution goes through the root-owned helper, with a fixed wrapper, a timeout,
  bounded output, and an audit entry containing the playbook ID, version, hash,
  host, actor, and result.
- Playbooks are stored encrypted in the database and are never accepted from a
  CSV import, an unauthenticated API call, or a remote URL without signature
  verification.
- Custom scripts are an advanced mode with an explicit warning and a typed
  confirmation. They should be rare, expiring, and reviewed.

If you later need unrestricted shell, add it as a separate advanced permission,
isolate it from routine patching, and treat the server as a root-equivalent
administration plane. Do not pretend it is a low-risk feature.

### Agent and transport security

Agent mode is optional and later; v1 uses SSH from the always-on server.

- Agent-to-server communication uses outbound mTLS only. No inbound port on the
  target.
- Each agent has its own certificate or token, with rotation and revocation.
  Do not share one fleet-wide secret.
- Policy and playbooks are signed and versioned. The agent rejects unsigned,
  expired, or rolled-back policy.
- The agent exposes a minimal local interface: collect facts, check, apply,
  reboot-check, and run an approved playbook. It does not expose a general
  shell.
- The agent binary is memory-safe where possible (Go or Rust), statically
  linked, and updated only through signed packages or a signed self-update.
- Log agent starts, policy changes, executions, failures, and certificate
  errors. Ship logs to the server and optionally to syslog/SIEM.
- SSH transport uses modern algorithms and key types (Ed25519,
  `rsa-sha2-512`), connection timeouts, keepalives, and rate limits. Password
  fallback, when explicitly enabled, uses SSH password/keyboard-interactive
  authentication over the encrypted channel and never plaintext.
- The local API binds to a Unix socket by default. If a TCP listener is enabled,
  require TLS, authentication, CSRF protection where relevant, and an explicit
  opt-in. Do not expose the GUI or API to the network by default.

### Audit and logging

- Append-only `audit_log` table with a hash chain: previous hash, timestamp,
  actor, action, entity type/ID, detail, and current hash.
- Audit privileged events: host create/update/delete, credential create/rotate/
  delete, connection test, fact collection, dry-run, patch start, patch result,
  cancellation, reboot, playbook approval, policy change, backup, restore, and
  migration.
- Store the command or playbook hash, not secrets. Store a log digest and a
  bounded, redacted log.
- Use UTC timestamps and record the server's time source. Warn on clock skew.
- The hash chain is tamper-evident for accidental changes, not tamper-proof
  against someone who holds the key and can rewrite the database. For high
  assurance, export signed audit batches to an append-only external sink.
- Provide an audit verification action in the GUI and CLI.
- Redact known secret patterns from logs and test the redaction with fixtures.

### Backup security

- Backups remain encrypted and require the same passphrase, or a separately
  managed backup key.
- Always back up the database and the `.meta` sidecar together.
- Use SQLite's online backup API for a consistent copy while the database is
  open. Do not copy a live WAL database by hand.
- Verify the backup by opening it and checking the schema version and audit
  chain.
- Keep at least one backup off the server and test restore procedures.
- Backups contain credentials and host keys. Treat them as crown jewels. Offer a
  "backup without secrets" mode for operators who prefer to re-enter credentials
  after a restore.
- Apply retention and access controls. Encrypt the backup destination as well
  where possible.

### Supply chain

- Pin dependencies and commit lockfiles. Generate an SBOM for releases.
- Publish SHA-256 checksums and, where possible, sign release artifacts.
- Run `govulncheck`, `gosec`, and dependency review in CI.
- Do not disable distribution repository signature checks. Do not add
  `--nogpgcheck`, `--allow-unauthenticated`, or `--force` as defaults.
- Warn on expired repository keys, unreachable mirrors, and EOL distributions.
- Auto-update HIBP only from signed artifacts. An unsigned self-update path is a
  remote-code-execution feature.
- Consider reproducible builds for the server and agent binaries.

### Implemented in M1

- SQLCipher database with Argon2id-derived keys and a validated `.meta` sidecar.
- `0600` database, sidecar, key, and backup files; wrong-passphrase test.
- Argon2id password login, TOTP, passkeys, HttpOnly sessions, recovery CLI, Host/Origin checks, CSP, and security headers.
- SSH host-key TOFU with explicit fingerprint approval and changed-key failure.
- Manual SSH and sudo password fallbacks with per-run prompts; no password storage.
- SSH key browser limited to configured directories; it never returns key contents.
- Fixed helper actions (`facts`, `check`, `apply`, `reboot`, `reboot-check`, `system-info`, `metrics`, `docker-list`, `docker-check`, `docker-apply`) with absolute
  binary paths, a sanitized environment, no shell, and output limits.
- Explicit-confirmation reboot action through the fixed helper.
- Per-host and fleet-wide helper installation/update with per-host results.
- Read-only system information, Docker inventory, metric history, host detail view, and configurable fleet/per-host collection settings.
- Local SSH config reader for prefilling hosts, with simple `Include` support,
  wildcard/`Match` filtering, and no private-key reads.
- Remote helper installation from the UI with `visudo` validation, a restricted
  per-host sudoers rule, and passwordless verification.
- Hash-chained audit log with verification.
- CSV import limits, preview/commit, duplicate policy, and CSV-injection
  neutralization on export.
- Online encrypted backup with sidecar copy and verification.
- Production build path: patched `mattn/go-sqlite3` + current SQLCipher 4.20,
  statically linked in a pinned Alpine/musl image.
- Unit, integration, race, README, and Python validator tests.

### Known security gaps in M1

- The **development** build uses the 2020 `mutecomm` spike driver. Do not deploy
  it; use the `make production` artifact.
- Password SSH fallback is manual-run only; it is never stored in the database.
  Scheduled password authentication requires an external vault and is deferred.
- No RBAC, external audit anchor, TPM-sealed key, agent mode, or signed
  playbooks yet.
- The browser session cookie is an admin credential; protect the SSH tunnel, browser profile, and controller.
- Passkeys require a `localhost` origin; `127.0.0.1` is TOTP-only.
- Recovery is local-only via `hibp user reset`; there is no self-service reset.
- Systemd hardening has not been validated against every distribution.
- Real target testing is limited to local unit/integration tests so far.

## Data model

The M1 schema is implemented in `internal/store/migrations/001_init.sql` and `002_auth.sql`. The
remaining tables below are the planned design for later milestones. Domain
objects use UUIDs, timestamps are UTC ISO 8601, and durations are stored in
seconds.

> **M1 implementation:** `schema_migrations`, `app_meta`, `hosts`,
> `host_facts`, `host_keys`, `runs` (table only), `users`, `user_passkeys`,
> `sessions`, and `audit_log` exist. The remaining tables are planned.

| Table | Purpose | Key fields |
|---|---|---|
| `schema_migrations` | Applied migrations and checksums. | `version`, `name`, `checksum`, `applied_at` |
| `app_meta` | Application metadata. | `key`, `value` |
| `users` | Local administrator account and MFA state. | `id`, `username`, `password_hash`, `totp_secret`, `totp_pending_secret`, `totp_enabled`, `totp_last_step`, `created_at`, `updated_at` |
| `user_passkeys` | WebAuthn credential records. | `id`, `user_id`, `credential_id`, `credential_json`, `sign_count`, `name`, `created_at`, `last_used_at` |
| `sessions` | Hashed browser sessions. | `id`, `user_id`, `token_hash`, `created_at`, `expires_at`, `last_seen_at`, `mfa_verified` |
| `hosts` | Managed hosts. | `id`, `name`, `address`, `port`, `os_family`, `os_version`, `enabled`, `group_id`, `cmdb_ci_id`, `created_at`, `updated_at`, `deleted_at` |
| `host_facts` | Latest collected facts. | `host_id`, `collected_at`, `uptime_seconds`, `boot_time`, `kernel`, `os_pretty_name`, `package_manager`, `reboot_required`, `disk_free_bytes`, `time_sync_ok` |
| `credentials` | Encrypted credential metadata and secrets. | `id`, `name`, `auth_type`, `username`, `key_path`, `secret_ref`, `wrapped_dek`, `encrypted_secret`, `sudo_mode`, `created_at`, `rotated_at` |
| `host_credentials` | Credential assignment and precedence. | `host_id`, `credential_id`, `priority` |
| `host_keys` | Known host keys. | `host_id`, `key_type`, `fingerprint`, `first_seen`, `last_seen`, `trusted`, `revoked_at` |
| `groups`, `tags`, `host_tags` | Grouping and filtering. | `id`, `name`; `host_id`, `tag_id` |
| `patch_policies` | Reusable patch rules. | `id`, `name`, `security_only`, `include_patterns`, `exclude_patterns`, `reboot_mode`, `max_concurrency`, `timeout_seconds` |
| `schedules` | Per-host or per-group schedules. | `id`, `name`, `target_type`, `target_id`, `cron`, `timezone`, `jitter_seconds`, `window_start`, `window_end`, `missed_run_policy`, `policy_id`, `enabled`, `next_run_at` |
| `jobs` | A requested patch operation. | `id`, `trigger`, `requested_by`, `policy_snapshot`, `created_at`, `started_at`, `finished_at`, `status`, `cancel_requested` |
| `job_targets` | Per-host state within a job. | `job_id`, `host_id`, `status`, `started_at`, `finished_at`, `exit_code`, `error`, `run_id` |
| `runs` | Per-host execution history. | `id`, `host_id`, `job_id`, `trigger`, `started_at`, `finished_at`, `status`, `reboot_required_before`, `reboot_required_after`, `kernel_before`, `kernel_after`, `log_digest`, `log_blob` |
| `run_packages` | Package-level diff for a run. | `run_id`, `package`, `old_version`, `new_version`, `action`, `status`, `security`, `repository` |
| `pending_updates` | Latest known pending updates. | `host_id`, `package`, `current_version`, `candidate_version`, `security`, `repository`, `first_seen`, `last_seen` |
| `playbooks` | Approved custom actions. | `id`, `name`, `version`, `sha256`, `signature`, `content`, `approved_by`, `approved_at`, `enabled` |
| `approvals` | Four-eyes or policy approvals. | `id`, `job_id`, `requested_by`, `approved_by`, `approved_at`, `reason`, `plan_hash` |
| `audit_log` | Hash-chained audit trail. | `id`, `ts`, `actor`, `action`, `entity_type`, `entity_id`, `detail`, `prev_hash`, `hash` |
| `notifications` | Notification channels. | `id`, `name`, `type`, `encrypted_config`, `enabled` |
| `settings` | Non-secret preferences. | `key`, `value` |

Schema rules:

- Use `PRAGMA application_id` and `PRAGMA user_version` in addition to the
  `schema_migrations` table so a wrong file is rejected early.
- Use UUIDs for domain objects and stable external IDs for imports.
- Store secrets only in encrypted columns or external vault references, never
  in logs, audit details, or plaintext settings.
- Keep runs and audit entries append-only. Hosts may be soft-deleted; history
  must survive deletion.
- Store flexible metadata as JSON only where the shape is genuinely variable
  (for example a policy snapshot or a notification configuration). Core query
  fields must be typed columns.
- Index host name/address, host tags, job status, run timestamps, and pending
  update lookups.
- Define retention separately for run logs, package diffs, audit entries, and
  notifications. Do not let log retention delete audit evidence.
- Every migration must be forward-only, transactional where the database allows
  it, checksummed, and tested against a fixture from the previous version.

## Scheduling and job semantics

- Schedule syntax: five-field cron for simple cases, systemd `OnCalendar` for
  operators who prefer it. Validate and show the next five run times in the GUI.
- Time zone: store UTC, display local time, and make the schedule's time zone
  explicit. Test daylight-saving transitions.
- Jitter: randomize start times within a configurable window to avoid all hosts
  hitting mirrors at once.
- Maintenance window: a job may start only inside the window. If it cannot
  finish before the window closes, the policy decides whether to continue,
  pause, or abort.
- Missed runs: `skip`, `run_once_on_next_start`, or `catch_up` with a maximum
  number of attempts. Never silently run a week of missed patches at once.
- Concurrency: global, per-group, and per-host limits. One active package
  operation per host. Queue the rest fairly.
- Idempotency: a job target has a stable identity. Retries update the existing
  attempt instead of creating duplicate package operations.
- Cancellation: request, signal the process group, wait for a grace period, then
  force-terminate if necessary. Record the final state and verify the host.
- Reboot behavior: never automatic. After a run that requires a reboot, the
  operator chooses **Reboot now** or **Reboot later**. Scheduled runs record the
  requirement and notify; they do not reboot. A reboot must be visible in the
  plan and in the result.
- Post-reboot verification: reconnect, check uptime and boot ID, confirm the
  kernel, and re-check pending updates and service health.
- Notifications: failure, reboot required, long-running job, host stale, EOL
  detected, and a daily/weekly summary. v1 supports webhook and ntfy; email,
  Slack, Teams, and a generic JSON endpoint are later.
- UI: dashboard cards for hosts needing patches, reboot required, failed runs,
  stale hosts, and EOL hosts. A host table with filters, a run timeline, a
  package diff, a log viewer, and a next-run column.

## Import formats

### CSV

Required headers: `name,address`. Optional headers:

```text
port,username,auth_type,key_path,group,tags,cmdb_ci_id,schedule,policy,notes
```

Example:

```csv
name,address,port,username,auth_type,key_path,group,tags,cmdb_ci_id
web01.example.com,10.0.0.10,22,ubuntu,key,/home/ops/.ssh/id_ed25519,prod,"web,eu-west",CI-123
db01.example.com,10.0.0.20,22,root,agent,,prod,db,CI-456
```

Rules:

- UTF-8, RFC 4180 quoting, header row required, maximum file size and row count.
- `name` and `address` are required. Validate IPv4, IPv6, and DNS names.
- `port` defaults to 22 and must be in the valid range.
- `auth_type` is one of `key`, `agent`, `certificate`, `password`.
- `key_path` is a reference, not key material. The file must exist and should be
  `0600`. Never import a private key through CSV.
- `tags` is a quoted, comma-separated list.
- `cmdb_ci_id` is the stable link to a `cmdb-lite` CI.
- Duplicate policy is explicit: `error`, `skip`, or `update`. Match by
  `cmdb_ci_id` first, then by name and address.
- Preview before commit. Show validation errors per row. Commit transactionally.
- Host keys are never trusted automatically during import. The first connection
  still requires fingerprint approval.

### TXT

One host per line. Comments start with `#`. Supported forms:

```text
# simple host names or IPs
web01.example.com
10.0.0.10

# user and port
ubuntu@10.0.0.10:2222
root@db01.example.com
```

TXT import is intentionally limited to identity and connection metadata. It does
not accept passwords, private keys, or scripts.

### cmdb-lite import

- Use the `cmdb-lite` CSV/JSON export.
- Map `external_id` to `cmdb_ci_id`; this is the idempotent key.
- Import name, IP/hostname attributes, OS version, environment, owner, and tags
  where present.
- Do not import secrets from the CMDB. `cmdb-lite` explicitly does not store
  them, and HIBP should not add them to the CMDB.
- Optionally write back `last_patched_at`, `last_patch_status`,
  `reboot_required`, and `uptime_seconds` as CI attributes or through a
  documented integration API.
- Never open the `cmdb-lite` database directly. It has its own passphrase,
  schema, and lifecycle. Integration happens through files or a narrow API.

## Backup, restore, and schema upgrades

### Create and open

1. Choose **Create database**.
2. Select a path outside the application installation directory. A database
   file such as `inventory.hibp` and a matching `inventory.hibp.meta` sidecar are
   created.
3. Enter a master passphrase of at least 12 characters. A long random phrase is
   better.
4. The application derives the key with Argon2id and opens SQLCipher.
5. The database and sidecar are set to `0600` where possible.

### Backup

- Use SQLite's online backup API for a consistent copy while the database is
  open.
- Write the matching `.meta` sidecar next to the backup.
- Refuse to overwrite an existing backup unless the operator explicitly chooses
  a new path.
- Verify the backup by opening it, checking the schema version, and running an
  audit-chain check.
- Keep at least one backup off the server.
- Offer a "backup without secrets" mode that omits credential material and
  requires re-entry after restore.
- Record backup creation, destination, and result in the audit log, but not the
  passphrase.

### Restore

- Restore to a **new** path. Never overwrite a live database in place.
- Require the passphrase that was active when the backup was created.
- Verify the restored database and audit chain before switching to it.
- Keep the old database until the restored one is validated.
- Test the restore procedure, not just the backup procedure.

### Schema migrations

- On open, compare the database schema version with the application's supported
  version.
- If the database is older, create an automatic pre-migration backup, then run
  forward-only migrations in a transaction.
- If the database is newer, refuse to open it. Do not attempt a downgrade.
- Store a checksum for every applied migration. A mismatch is a hard failure.
- Test migrations against fixtures from every supported previous version.
- Use expand/contract changes for columns that are renamed or removed. Do not
  drop data in the same release that stops using it.
- Keep the database encrypted throughout migration. Do not create a plaintext
  temporary copy.
- Document rollback as "restore the pre-migration backup", not as an automatic
  down-migration.

### Upgrade the application

- Package upgrades replace the executable, not the database.
- Read the release notes before upgrading. If the schema changes, the notes must
  say so.
- Verify release checksums or signatures.
- Open the database and confirm the schema version, host count, and audit chain.
- If the new version fails, restore the pre-upgrade backup and reinstall the
  previous version.

### If "external database" means PostgreSQL

The chosen design is SQLite/SQLCipher: simple, embedded, and easy to back up.
This section is retained only to document the alternative if requirements
change. If the requirement later becomes a central PostgreSQL server, the design
changes:

- The application becomes a controller/server with a database connection, not a
  single-user file.
- Use TLS, strong authentication, least-privilege database roles, and
  encryption at rest (LUKS, storage encryption, or a PostgreSQL encryption
  extension).
- Backups use `pg_dump` or physical backup plus point-in-time recovery.
- Multi-user RBAC becomes practical, but so does the need for migrations,
  connection pooling, and operational ownership.
- Do not support both SQLite and PostgreSQL in v1 unless the repository layer is
  deliberately abstracted and tested against both. Two storage engines double
  the migration and backup surface.

## Build system and dependencies

### Current state

M1 is implemented in Go:

- `cmd/hibp` server, helper, and local recovery commands
- `internal/crypto` Argon2id key derivation and `.meta` sidecar
- `internal/auth` password hashing, session tokens, TOTP, and username validation
- `internal/store` SQLCipher database, migrations, hosts, facts, host keys,
  observability snapshots, settings, backup, and hash-chained audit
- `internal/remote` SSH transport and host-key policy
- `internal/helper` fixed target actions, system information, and Docker inventory
- `internal/sshconfig` local OpenSSH client config reader
- `internal/server` browser UI/API, session/password/MFA auth, collector,
  Host/Origin checks, and security headers
- `internal/webui` embedded HTML/CSS/JS
- tests, `Makefile`, and GitHub Actions CI

The development build uses the 2020 `mutecomm/go-sqlcipher` spike driver. The
production build uses the local `third_party/go-sqlite3` patch, which calls
`sqlite3_key` immediately after `sqlite3_open_v2`, linked against current
SQLCipher 4.20.0 built statically in `packaging/Dockerfile`.

### The "single executable, no dependencies" constraint

Define the constraint precisely:

- **No runtime dependency:** one statically linked ELF; no Python, Node, JVM,
  database server, web server, or OpenSSL shared library.
- **Browser UI:** the UI is embedded HTML/CSS/JS served by the binary on
  `127.0.0.1` or a Unix socket. The laptop uses its browser through an SSH
  tunnel. No GTK/WebKit.
- **No separate assets:** the UI is compiled into the binary with `embed`.
- **Not "no target requirements":** managed hosts still need SSH and their
  native package manager. That is the point of the tool.

The hard part is SQLCipher. Go can produce a static binary, but SQLCipher is a C
library and requires CGO. The build plan is:

- Use a maintained SQLCipher-enabled Go driver, or a small CGO wrapper around
  `libsqlcipher`. Verify the driver's maintenance status before committing to it.
- Build with `CGO_ENABLED=1` in an Alpine/musl container or with a musl
  cross-compiler.
- Link with `-linkmode external -extldflags "-static"`.
- Add `netgo` and `osusergo` to the build tags so a static binary uses Go's
  resolver instead of glibc NSS.
- Verify with `ldd` that the release binary is "not a dynamic executable".

**Development build:** Go 1.27.3 with `mutecomm/go-sqlcipher` v4.4.2 produced a
statically linked ELF on Ubuntu/glibc using
`-tags "sqlite_omit_load_extension netgo osusergo"` and
`-ldflags '-linkmode external -extldflags "-static"'`. This is for development
only and prints a warning.

**Production build:** `packaging/Dockerfile` builds SQLCipher 4.20.0 from source
with the OpenSSL backend, links it statically with musl, and uses the local
`third_party/go-sqlite3` patch that calls `sqlite3_key` before any schema read.
The driver path was tested against current system `libsqlcipher` with the full
store/server test suite, including backup/restore. CI runs the Docker production
build and verifies the ELF.

### Why Go

Go is the chosen stack:

- Memory-safe, fast to develop, and easy to review.
- Excellent SSH support in `golang.org/x/crypto/ssh`.
- Strong concurrency for a 2–500 host worker pool.
- `embed` makes the browser UI a single binary.
- `net/http` is enough for the local UI/API; no external web server.
- Cross-compilation is straightforward; CGO is the only complication, and it is
  confined to SQLCipher.

### Dependencies

- Development: `github.com/mutecomm/go-sqlcipher/v4` v4.4.2 — spike driver only.
- Production: local `third_party/go-sqlite3` (patched `mattn/go-sqlite3` with a
  `sqlite3_key` call) linked against SQLCipher 4.20.0.
- `golang.org/x/crypto` — SSH, Argon2id, and BLAKE2b.
- `golang.org/x/term` — terminal passphrase prompt.
- `github.com/google/uuid` — host and run IDs.
- Standard library: `embed`, `net/http`, `database/sql`, `encoding/csv`,
  `crypto/rand`, `log/slog`.

All dependencies are compiled into the binary. The only runtime requirement on
the server is the Linux kernel and the target hosts' SSH/package managers.

### Packaging and "single executable"

- One static ELF named `hibp`, with `server`, `helper`, and `version` commands.
  A future `client`/`agent` command can reuse the same core.
- Embedded browser UI; no `web/` directory, Node/Python runtime, or external web
  server.
- `make static` builds the development ELF; `make production` builds the
  current-SQLCipher production image via `packaging/Dockerfile`.
- systemd unit example in `packaging/hibp.service`; target helper and sudoers
  example in `packaging/`.
- Primary artifact: the production image or the binary extracted from it.
  `.deb`/`.rpm` are future convenience wrappers around the same binary.
- No Flatpak in v1. The sandbox complicates SSH agent/key access, and the
  browser UI already avoids GUI toolkit dependencies.
- Publish SHA-256 checksums and an SBOM. Sign releases if possible.

### Cross-distro validation

Use containers or disposable VMs to test the server and the profiles. First
priority: Debian, Ubuntu, Kali, Fedora, and SUSE. Add Arch and Alpine after the
first five.

- Server baseline: Ubuntu 24.04 and 26.04; 22.04 best-effort.
- Targets: Ubuntu 24.04/26.04, Debian 12, Kali rolling, Fedora current and
  previous, and openSUSE Leap/Tumbleweed or SLES if available.
- Arch Linux and Alpine Linux in the second wave.
- Test SSH into the container/VM, host key approval, sudo helper installation,
  fact collection, dry-run, a real patch of a small package, reboot detection,
  and cancellation.
- Test the server binary on the distributions you intend to support. A static
  binary should run broadly.

### Build and validation commands

See [Install prerequisites](#install-prerequisites) before running these
commands.

```bash
make help           # list targets and the Go-path override
make bootstrap      # install Go locally if needed, then make build
make build          # development build, CGO + dynamic libc
make build-system   # production driver against system SQLCipher (no Docker)
make test           # Go tests (development driver)
make vet            # go vet
make static         # development static ELF + ldd check
make production     # production Docker build: current SQLCipher 4.20
make validate       # tests, vet, README validator, Python tests, git diff check

# Run
./dist/hibp server --db ~/.local/share/hibp/hibp.db --create
```

CI runs development tests, race tests, vet, README/Python validation, the
development static build, `govulncheck`, and the production Docker build.

## Repository layout

Implemented layout:

```text
go.mod / go.sum           Go module and pinned dependencies
Makefile                  build, test, static, validate, package
cmd/hibp/main.go          server, helper, and version commands
internal/crypto/          Argon2id, sidecar, tokens, zeroization
internal/store/           SQLCipher, migrations, hosts, facts, keys, backup, audit
internal/store/migrations SQL schema
internal/remote/          SSH transport and host-key policy
internal/helper/          fixed target actions
internal/server/          browser UI/API, auth, security headers, import/export
internal/webui/           embedded HTML/CSS/JS
third_party/go-sqlite3/   patched mattn driver with sqlite3_key before open
packaging/Dockerfile          production SQLCipher 4.20 + musl static build
packaging/                systemd unit, sudoers example, install notes
scripts/                  README validator, release installer, developer bootstrap
tests/                    Python validator tests
docs/screenshots/         real M1 screenshot
.github/workflows/        CI
```

## Roadmap

### M0 - Production build (implemented)

- Production SQLCipher build implemented in `packaging/Dockerfile`: SQLCipher 4.20,
  patched `third_party/go-sqlite3`, static musl ELF.
- The production driver passes the store/server suite, including backup and
  restore, against current system `libsqlcipher`.
- Remaining M0 documentation: threat model, data model, and distribution
  profile interface as versioned documents.
- Do not deploy the development `mutecomm` spike build.

### M1 - Implemented prototype

Implemented:

- Go module, Makefile, tests, CI, and static build.
- Server mode with a browser UI/API bound to `127.0.0.1`.
- Encrypted SQLCipher database with Argon2id sidecar.
- Host add/edit/delete plus CSV/TXT import with preview and duplicate policy.
- Server-side SSH key browser scoped to configured key directories.
- SSH key authentication, host-key approval, and connection test.
- Manual SSH and sudo password fallbacks with per-run prompts; no password storage.
- Fact collection through the fixed helper.
- Dashboard, host list, audit viewer, backup, and restore to a new path.
- Audit chain verification and CSV-injection-neutralized export.
- Production SQLCipher build path in `packaging/Dockerfile`.

Not yet:

- Real target matrix and sudo helper install test.
- Scheduler, playbooks, notifications, and agent.

### M2 - Patch execution (partial)

Implemented:

- Fixed helper `check` and `apply` actions.
- UI patch modal with dry-run and apply confirmation.
- Audit entries for patch attempts.

Still missing:

- Per-host job queue and concurrency control.
- Run history and per-package drill-down.
- Cancellation, retries, and post-reboot verification.
- Package diff/security classification and evidence export.

### M3 - Scheduling and unattended execution

- Scheduler with maintenance windows, jitter, missed-run policy, and concurrency.
- Run the scheduler on the always-on server; no agent is required.
- Manual database unlock after a server reboot; show the locked/paused state and
  do not run jobs until unlocked.
- Notifications via email, webhook, and ntfy for failures, reboot required, stale
  hosts, Docker/service availability, HTTP/TLS checks, and threshold alarms.
- Next-run and run-history UI.
- Acceptance: a daily schedule runs with the laptop closed, survives a server
  restart after manual unlock, and reports the result.

### M4 - Security hardening

- Key-based authentication baseline.
- Manual password fallback implemented with per-run prompts; no password is
  persisted. Vault-backed scheduled password authentication remains deferred.
- Service SSH key protection with a dedicated account, `0600` permissions,
  full-disk encryption, and optional TPM2/`systemd-creds`.
- Host key rotation workflow.
- Root-owned sudo helper and least-privilege packaging.
- Log redaction tests and audit export.
- Independent threat-model review and dependency audit.
- Acceptance: no plaintext secret in the database, logs, argv, or environment;
  changed host keys fail closed.

### M5 - Packaging and integration

- Static single ELF, systemd units, tarball, and release checksums; optional
  `.deb`/`.rpm` wrappers.
- Cross-distro CI matrix: Debian, Ubuntu, Kali, Fedora, and SUSE first; Arch and
  Alpine in the second wave.
- read-only `cmdb-lite` import with explicit merge/overwrite preview; no write-back.
- Documentation for operators, backup, upgrade, and troubleshooting.

### M6 - Agent hardening and scale

- mTLS, per-agent certificates, rotation, revocation, and signed policy at fleet
  scale.
- Result collection and reconciliation for large fleets.
- Scale testing with a representative fleet.

### M7 - Reporting and advanced workflows

- CVE correlation through an existing scanner.
- Patch SLA and compliance reports.
- Canary rings, approval gates, and snapshot/rollback integration.
- Prometheus metrics and SIEM export.

## Relationship to cmdb-lite

**Decision: keep HIBP as a separate application and integrate at the edges.**
Do not merge the patch engine into the CMDB database.

Reasons:

- **Different risk profile.** A CMDB is mostly read-only inventory. HIBP stores
  SSH credentials and executes package-manager commands as root. Merging them
  puts root-equivalent execution inside the CMDB's threat model and blast
  radius.
- **Different data sensitivity.** `cmdb-lite` explicitly says not to store
  passwords, API keys, or private keys in the CMDB. HIBP needs credential
  handling. Keeping the secret vault separate is safer.
- **Different lifecycle.** HIBP needs a scheduler, worker pool, agent lifecycle,
  network transports, and long-running jobs. The CMDB should remain usable if
  the patch engine is down or compromised.
- **Different scaling model.** A single-user encrypted SQLite file is excellent
  for a CMDB. A patch controller may need a daemon or agent and, eventually, a
  server database. Coupling the two would force one model on both.
- **Different failure domains.** A failed patch run should not risk inventory
  data, and a CMDB migration should not block emergency patching.

Integration points:

- Import CIs from `cmdb-lite` CSV/JSON and preserve `external_id` as
  `cmdb_ci_id`.
- Write back patch facts as CI attributes or through a documented API.
- Deep link from a CI to the corresponding HIBP host.
- Share UI conventions, theme, and documentation style, not a database.
- If a single pane of glass is mandatory, embed HIBP as a separate privileged
  service with its own encrypted database, called by `cmdb-lite` over a local
  authenticated socket. Keep the process and privilege boundary even if the UI
  looks unified.

If you decide to merge anyway, do it deliberately:

- Extract a shared library for crypto, database open, backup, and migrations.
- Keep remote execution in a separate process with its own credentials and
  audit trail.
- Document the expanded threat model and get an independent review.
- Make sure the CMDB remains fully usable when HIBP is disabled or uninstalled.

## Confirmed decisions

These are settled unless you explicitly change them:

- **Deployment:** an always-on Linux server is the primary host. The laptop is a
  client and can also be enrolled as a managed target. The same binary supports
  server, client, and optional standalone modes. The server owns the database,
  scheduler, credentials, and audit log.
- **Server OS:** Ubuntu LTS (24.04/26.04; 22.04 best-effort) is the supported server baseline. The
  static binary may run on other distributions, but Ubuntu is what we test and
  support first.
- **UI:** browser-based. The server embeds the HTML/CSS/JS and serves it on
  `127.0.0.1` or a Unix socket; the laptop uses a browser through an SSH tunnel.
  No GTK/WebKit dependency.
- **Stack:** Go. The development build uses the 2020 `mutecomm/go-sqlcipher`
  driver and prints a warning. The production SQLCipher driver is a locally
  patched, maintained `mattn/go-sqlite3` linked against current SQLCipher built
  in a pinned Alpine/musl image.
- **Database:** SQLite with SQLCipher, stored as a user-chosen file with a
  `.meta` sidecar. No PostgreSQL in v1.
- **Unattended unlock:** manual. The server starts locked after a reboot and
  schedules are paused until the operator unlocks the database. No TPM2 or
  persisted database key in v1.
- **Authentication:** SSH keys, `ssh-agent`, hardware-backed keys, and SSH
  certificates by default. Password SSH is an explicit opt-in fallback, disabled
  by default, never stored in plaintext, and **manual-runs only in v1**.
  Vault-backed scheduled password auth is deferred.
- **Remote actions:** built-in patch actions plus approved, signed, versioned
  playbooks. No arbitrary shell in v1.
- **Users:** single-user v1. No RBAC; the server is protected by the OS account,
  SSH key, and database passphrase.
- **Fleet size:** design target is 2–500 hosts.
- **Target priority:** Debian, Ubuntu, Kali, Fedora, and SUSE first; Arch and
  Alpine follow.
- **Reboot behavior:** never automatic. After a run that requires a reboot, the
  operator chooses **Reboot now** or **Reboot later**. Scheduled runs record the
  requirement and notify; they do not reboot.
- **Notifications:** webhook and ntfy in v1; email, Slack, and Teams later.
- **CMDB integration:** separate application, integrated through CSV/JSON import
  and patch-status write-back. No shared database or passphrase.
- **Name:** Have I Been Patched (HIBP).
- **License:** MIT.

No architecture-blocking decisions remain. Deferred work is listed below.

## Ideas worth adding

Prioritized, with an eye on value versus complexity:

**High value, low-to-moderate complexity**

- Dry-run and package diff before every patch.
- Preflight checks: disk space, time sync, repository reachability, package
  manager lock, EOL detection.
- Reboot-required detection and a visible **Reboot now / Reboot later** choice.
- Maintenance windows, jitter, and missed-run policy.
- Notifications for failure and reboot-required.
- Host key verification UI with fingerprint approval and rotation.
- CSV/JSON evidence export for audits.
- Saved filters and smart groups (for example "Ubuntu hosts with reboot
  required").
- A "last seen" and "data stale" indicator.
- Per-host package hold/exclude list.

**High value, higher complexity**

- CVE correlation through Trivy, Grype, OSV, or distro security feeds. Do not
  build a vulnerability scanner from scratch.
- Patch SLA and compliance reporting (for example "critical patches within 7
  days").
- Canary rings: test hosts first, then production, with approval gates.
- Snapshot/rollback integration for btrfs, ZFS, LVM, or VM snapshots.
- Post-patch service health checks and automatic rollback triggers.
- Agent mode with mTLS and signed policy.
- Prometheus metrics and SIEM/webhook export.
- Ansible/Salt execution backend for organizations that already have one.
- Import from Ansible inventory, SSH config, or network discovery.
- A CLI/API that is good enough for CI/CD and change management.

**Later, only if the product needs it**

- Multi-user RBAC, SSO, and per-user audit actors.
- Agent auto-update with signature verification.
- Air-gapped repository mirrors and bandwidth throttling.
- Kernel livepatch awareness.
- Windows/macOS targets.
- A plugin SDK for custom distributions and notification channels.

**Avoid**

- Building a CVE scanner instead of integrating one.
- Arbitrary remote shell as the default workflow.
- Automatic reboots without an explicit policy.
- Storing plaintext passwords or private keys.
- Disabling host key verification for convenience.
- `--force`, `--nogpgcheck`, or `--allow-unauthenticated` defaults.
- Sharing one encrypted database over a network share.
- Treating a hash-chained local audit log as tamper-proof.

## Deferred decisions

No architecture-blocking decisions remain. These are intentionally deferred:

- **Agent mode** for DMZs, NAT, or scale.
- **Scheduled password authentication** through an external vault.
- **CVE correlation** through Trivy, Grype, OSV, or distro security feeds.
- **RBAC/SSO** and per-user audit actors.
- **Email, Slack, and Teams** notifications.
- **Arch and Alpine** profiles in the second wave.
- **Native desktop client** — not planned; the browser UI is the chosen path.
- **Windows/macOS targets** — not planned for v1.

## Validation

```bash
# Go tests, vet, README validator, Python validator tests, whitespace checks
make validate

# Development static ELF build and ldd check
make static

# Production build: current SQLCipher 4.20 + musl static binary
make production

# Race detector
CGO_ENABLED=1 go test -race ./...

# Repository verification without network access (when git-create is installed)
git-create check --offline

# Reachable-history secret scan (when git-create is installed)
git-create secrets .
```

M1 validation status:

- `go test ./...` passes.
- `go vet ./...` passes.
- `go test -race ./...` passes.
- `make static` produces a development ELF with no dynamic dependencies.
- The current-SQLCipher production Docker build is defined in CI and must pass
  before release.
- The store/server suite passes against the production driver with current
  system `libsqlcipher`, including backup and restore.
- README validator and Python validator tests pass.
- A release must still pass the cross-distro matrix and real target tests.

## License

MIT. See [LICENSE](LICENSE). Third-party components are listed in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

HIBP performs privileged operations and can break systems. It is provided "as
is", without warranty of any kind. Test patch policies in a canary ring, keep
backups, and use it only on hosts you are authorized to administer.
